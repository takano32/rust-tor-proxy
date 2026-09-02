//! Circuits: onion-encrypted relay cells, circuit construction, flow control
//! and stream multiplexing.
//!
//! One thread per circuit ("the pump") owns the receive side. It takes cells
//! from the channel, peels one AES-CTR layer per hop until the running digest
//! recognises the cell, and hands the result to the right stream. Every piece
//! of per-hop crypto lives behind a single mutex, so the pump and any number
//! of writer threads take turns rather than racing.
//!
//! A rendezvous circuit carries one hop more than it has relays: the onion
//! service at the far end is a "virtual" hop, reached through the rendezvous
//! point, whose layer uses AES-256 and SHA3-256 instead of AES-128 and SHA-1.
//! Nothing else about relay cells changes, which is why the hop list simply
//! holds a cipher and a digest rather than assuming either.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use super::cell::{self, Cell, CELL_BODY_LEN};
use super::channel::Channel;
use super::hs::ntor::HsCircuitKeys;
use super::ntor::{self, CreateFastClient, NtorClient};
use super::RelayInfo;
use crate::ffi::aes::{Aes128Ctr, Aes256Ctr};
use crate::ffi::hash::Digest;
use crate::ffi::rand;
use crate::util::invalid_data;

pub const RELAY_BEGIN: u8 = 1;
pub const RELAY_DATA: u8 = 2;
pub const RELAY_END: u8 = 3;
pub const RELAY_CONNECTED: u8 = 4;
pub const RELAY_SENDME: u8 = 5;
pub const RELAY_TRUNCATED: u8 = 9;
pub const RELAY_DROP: u8 = 10;
pub const RELAY_BEGIN_DIR: u8 = 13;
pub const RELAY_EXTEND2: u8 = 14;
pub const RELAY_EXTENDED2: u8 = 15;
pub const RELAY_ESTABLISH_RENDEZVOUS: u8 = 33;
pub const RELAY_INTRODUCE1: u8 = 34;
pub const RELAY_RENDEZVOUS2: u8 = 37;
pub const RELAY_RENDEZVOUS_ESTABLISHED: u8 = 39;
pub const RELAY_INTRODUCE_ACK: u8 = 40;

/// Relay header: command, recognized, stream ID, digest, length.
const RELAY_HEADER_LEN: usize = 11;
/// Most application bytes one RELAY_DATA cell can carry.
pub const RELAY_DATA_MAX: usize = CELL_BODY_LEN - RELAY_HEADER_LEN;

const CIRCUIT_WINDOW_START: i32 = 1000;
const CIRCUIT_WINDOW_INCREMENT: i32 = 100;
const STREAM_WINDOW_START: i32 = 500;
const STREAM_WINDOW_INCREMENT: i32 = 50;

/// A circuit may carry at most this many RELAY_EARLY cells, which is what
/// bounds how far it can be extended.
const MAX_RELAY_EARLY: u8 = 8;

/// How long to wait for a CREATED2 / EXTENDED2 or a stream reply.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a blocked writer waits for a SENDME before giving up.
const SENDME_TIMEOUT: Duration = Duration::from_secs(120);

/// Cap on queued control replies, so a relay that floods us with them cannot
/// grow the queue without bound.
const MAX_QUEUED_CONTROL: usize = 16;

/// END reason codes (tor-spec/closing-streams.md).
pub const END_REASON_MISC: u8 = 1;
pub const END_REASON_RESOLVEFAILED: u8 = 2;
pub const END_REASON_CONNECTREFUSED: u8 = 3;
pub const END_REASON_EXITPOLICY: u8 = 4;
pub const END_REASON_DONE: u8 = 6;
pub const END_REASON_TIMEOUT: u8 = 7;
pub const END_REASON_NOROUTE: u8 = 8;

pub fn end_reason_name(reason: u8) -> &'static str {
    match reason {
        1 => "MISC",
        2 => "RESOLVEFAILED",
        3 => "CONNECTREFUSED",
        4 => "EXITPOLICY",
        5 => "DESTROY",
        6 => "DONE",
        7 => "TIMEOUT",
        8 => "NOROUTE",
        9 => "HIBERNATING",
        10 => "INTERNAL",
        11 => "RESOURCELIMIT",
        12 => "CONNRESET",
        13 => "TORPROTOCOL",
        14 => "NOTDIRECTORY",
        _ => "UNKNOWN",
    }
}

/// A hop's stream cipher. Which one it is depends on the handshake that set
/// the hop up, and on nothing else.
enum HopCipher {
    Aes128(Aes128Ctr),
    Aes256(Aes256Ctr),
}

impl HopCipher {
    fn apply(&mut self, buf: &mut [u8]) {
        match self {
            Self::Aes128(cipher) => cipher.apply(buf),
            Self::Aes256(cipher) => cipher.apply(buf),
        }
    }
}

/// One hop's cryptographic state.
struct Hop {
    forward_cipher: HopCipher,
    backward_cipher: HopCipher,
    forward_digest: Digest,
    backward_digest: Digest,
}

impl Hop {
    /// An ordinary relay hop: AES-128-CTR and SHA-1.
    fn new(keys: &ntor::CircuitKeys) -> Self {
        Self::build(
            HopCipher::Aes128(Aes128Ctr::new(&keys.kf)),
            HopCipher::Aes128(Aes128Ctr::new(&keys.kb)),
            Digest::sha1(),
            &keys.df,
            &keys.db,
        )
    }

    /// The onion service beyond a rendezvous point: AES-256-CTR and SHA3-256.
    fn virtual_hop(keys: &HsCircuitKeys) -> Self {
        Self::build(
            HopCipher::Aes256(Aes256Ctr::new(&keys.kf)),
            HopCipher::Aes256(Aes256Ctr::new(&keys.kb)),
            Digest::sha3_256(),
            &keys.df,
            &keys.db,
        )
    }

    fn build(
        forward_cipher: HopCipher,
        backward_cipher: HopCipher,
        digest: Digest,
        df: &[u8],
        db: &[u8],
    ) -> Self {
        let mut forward_digest = digest.clone();
        forward_digest.update(df);
        let mut backward_digest = digest;
        backward_digest.update(db);
        Self {
            forward_cipher,
            backward_cipher,
            forward_digest,
            backward_digest,
        }
    }
}

struct State {
    hops: Vec<Hop>,
    relay_early_left: u8,
    /// How many more RELAY_DATA cells we may send before a SENDME.
    package_window: i32,
    /// How many more RELAY_DATA cells we will accept before sending a SENDME.
    deliver_window: i32,
    next_stream_id: u16,
    /// Filled in by the pump when a CREATED2 or EXTENDED2 arrives.
    handshake: Option<Result<Vec<u8>, String>>,
    /// Control-cell replies the pump has taken off the circuit, waiting for
    /// whoever asked for them. A queue rather than a slot because a
    /// RENDEZVOUS2 can arrive before the thread that wants it starts waiting.
    control: VecDeque<(u8, Vec<u8>)>,
    /// Rolling digest of the last recognised inbound cell, which is what an
    /// authenticated (version 1) SENDME has to quote.
    last_recv_digest: [u8; 20],
}

impl State {
    /// Queue a control reply for whoever is waiting on it. A peer that sends
    /// more of these than anyone asked for loses the oldest rather than
    /// growing the queue.
    fn push_control(&mut self, relay_command: u8, data: Vec<u8>) {
        if self.control.len() >= MAX_QUEUED_CONTROL {
            self.control.pop_front();
        }
        self.control.push_back((relay_command, data));
    }

    /// Take the first queued reply with this command, leaving the others.
    fn take_control(&mut self, relay_command: u8) -> Option<Vec<u8>> {
        let index = self
            .control
            .iter()
            .position(|(command, _)| *command == relay_command)?;
        self.control.remove(index).map(|(_, data)| data)
    }
}

struct Inner {
    chan: Channel,
    circ_id: u32,
    state: Mutex<State>,
    event: Condvar,
    streams: Mutex<HashMap<u16, Arc<StreamShared>>>,
    closed: AtomicBool,
}

pub struct Circuit {
    inner: Arc<Inner>,
}

impl Clone for Circuit {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Circuit {
    /// Build a one-hop circuit to `first` over `chan`.
    pub fn create(chan: &Channel, first: &RelayInfo) -> io::Result<Self> {
        let circuit = Self::new_on(chan)?;
        if let Err(e) = circuit.do_create(first) {
            circuit.close();
            return Err(e);
        }
        Ok(circuit)
    }

    /// Register a circuit ID and start its pump thread, with no hops yet.
    fn new_on(chan: &Channel) -> io::Result<Self> {
        let (circ_id, rx) = chan.register_circuit()?;
        let inner = Arc::new(Inner {
            chan: chan.clone(),
            circ_id,
            state: Mutex::new(State {
                hops: Vec::new(),
                relay_early_left: MAX_RELAY_EARLY,
                package_window: CIRCUIT_WINDOW_START,
                deliver_window: CIRCUIT_WINDOW_START,
                next_stream_id: 1,
                handshake: None,
                control: VecDeque::new(),
                last_recv_digest: [0u8; 20],
            }),
            event: Condvar::new(),
            streams: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
        });

        let pump_inner = Arc::clone(&inner);
        std::thread::Builder::new()
            .name(format!("circ-{circ_id}"))
            .spawn(move || pump(pump_inner, rx))?;

        Ok(Self { inner })
    }

    /// Build a one-hop circuit with CREATE_FAST, for fetching directory
    /// documents before any onion key is known.
    pub fn create_fast(chan: &Channel) -> io::Result<Self> {
        let circuit = Self::new_on(chan)?;
        if let Err(e) = circuit.do_create_fast() {
            circuit.close();
            return Err(e);
        }
        Ok(circuit)
    }

    fn do_create_fast(&self) -> io::Result<()> {
        let (client, x) = CreateFastClient::new()?;
        self.inner
            .chan
            .send_cell(&Cell::new(self.inner.circ_id, cell::CMD_CREATE_FAST, x)?)?;
        let reply = self.wait_for_handshake()?;
        let keys = client.finish(&reply)?;
        self.inner.state.lock().unwrap().hops.push(Hop::new(&keys));
        debug!(
            "circuit {}: one-hop CREATE_FAST to {}",
            self.inner.circ_id,
            self.inner.chan.peer()
        );
        Ok(())
    }

    fn do_create(&self, first: &RelayInfo) -> io::Result<()> {
        let (client, skin) = NtorClient::new(&first.rsa_identity, &first.ntor_onion_key)?;
        let mut body = Vec::with_capacity(4 + skin.len());
        body.extend_from_slice(&ntor::HANDSHAKE_TYPE_NTOR.to_be_bytes());
        body.extend_from_slice(&(skin.len() as u16).to_be_bytes());
        body.extend_from_slice(&skin);
        self.inner
            .chan
            .send_cell(&Cell::new(self.inner.circ_id, cell::CMD_CREATE2, body)?)?;

        let reply = self.wait_for_handshake()?;
        let keys = client.finish(&reply)?;
        self.inner.state.lock().unwrap().hops.push(Hop::new(&keys));
        debug!(
            "circuit {}: hop 1 established via {}",
            self.inner.circ_id, first.addr
        );
        Ok(())
    }

    /// Extend the circuit by one hop with EXTEND2, which must travel in a
    /// RELAY_EARLY cell.
    pub fn extend(&self, next: &RelayInfo) -> io::Result<()> {
        let (client, skin) = NtorClient::new(&next.rsa_identity, &next.ntor_onion_key)?;
        let payload = build_extend2(next, &skin);

        let last_hop = self.last_hop()?;
        self.send_relay(last_hop, RELAY_EXTEND2, 0, &payload, true)?;

        let reply = self.wait_for_handshake()?;
        let keys = client.finish(&reply)?;
        self.inner.state.lock().unwrap().hops.push(Hop::new(&keys));
        debug!(
            "circuit {}: hop {} established via {}",
            self.inner.circ_id,
            last_hop + 2,
            next.addr
        );
        Ok(())
    }

    fn wait_for_handshake(&self) -> io::Result<Vec<u8>> {
        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        let mut state = self.inner.state.lock().unwrap();
        loop {
            if let Some(result) = state.handshake.take() {
                return result.map_err(io::Error::other);
            }
            if self.is_closed() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "circuit closed during handshake",
                ));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for CREATED2/EXTENDED2",
                ));
            }
            let (guard, _) = self
                .inner
                .event
                .wait_timeout(state, deadline - now)
                .unwrap();
            state = guard;
        }
    }

    /// Wait for one of the control-cell replies the pump queues.
    ///
    /// Unlike a handshake reply these are not tied to a request-response turn:
    /// a RENDEZVOUS2 arrives when the service gets round to it, possibly
    /// before this is even called, so the pump queues them and this takes the
    /// first matching one.
    pub fn wait_for_control(&self, relay_command: u8, timeout: Duration) -> io::Result<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        let mut state = self.inner.state.lock().unwrap();
        loop {
            if let Some(data) = state.take_control(relay_command) {
                return Ok(data);
            }
            if self.is_closed() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "circuit closed while waiting for a reply",
                ));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("timed out waiting for relay command {relay_command}"),
                ));
            }
            let (guard, _) = self
                .inner
                .event
                .wait_timeout(state, deadline - now)
                .unwrap();
            state = guard;
        }
    }

    /// Send a control message to the far end of the circuit: stream ID zero,
    /// last hop, never RELAY_EARLY.
    pub fn send_control(&self, relay_command: u8, payload: &[u8]) -> io::Result<()> {
        let hop = self.last_hop()?;
        self.send_relay(hop, relay_command, 0, payload, false)
    }

    /// Add the onion service at the far end of a rendezvous circuit as a
    /// further hop.
    ///
    /// It is not a relay we ever connected to -- the rendezvous point splices
    /// the two circuits together -- but from here on its layer is applied and
    /// stripped exactly like any other, so it belongs in the hop list.
    pub fn add_virtual_hop(&self, keys: &HsCircuitKeys) {
        let mut state = self.inner.state.lock().unwrap();
        state.hops.push(Hop::virtual_hop(keys));
        debug!(
            "circuit {}: virtual hop added, {} hops",
            self.inner.circ_id,
            state.hops.len()
        );
    }

    fn last_hop(&self) -> io::Result<usize> {
        self.inner
            .state
            .lock()
            .unwrap()
            .hops
            .len()
            .checked_sub(1)
            .ok_or_else(|| invalid_data("this circuit has no hops"))
    }

    pub fn hop_count(&self) -> usize {
        self.inner.state.lock().unwrap().hops.len()
    }

    /// How many streams are open on this circuit. The pool spreads new
    /// streams across circuits by this figure: with window-based flow control
    /// each circuit is capped at 1000 cells per round trip, so several
    /// circuits carry more in total than one ever can.
    pub fn open_streams(&self) -> usize {
        self.inner.streams.lock().unwrap().len()
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire) || self.inner.chan.is_closed()
    }

    pub fn circ_id(&self) -> u32 {
        self.inner.circ_id
    }

    pub fn peer(&self) -> SocketAddrV4 {
        self.inner.chan.peer()
    }

    /// Encrypt and send one relay cell addressed to `hop`.
    fn send_relay(
        &self,
        hop: usize,
        relay_command: u8,
        stream_id: u16,
        data: &[u8],
        early: bool,
    ) -> io::Result<()> {
        let mut state = self.inner.state.lock().unwrap();
        let cell = build_relay_cell(
            &mut state,
            self.inner.circ_id,
            hop,
            relay_command,
            stream_id,
            data,
            early,
        )?;
        drop(state);
        self.inner.chan.send_cell(&cell)
    }

    /// Open a stream and wait for the exit to confirm it.
    pub fn begin_stream(&self, target: &str, port: u16) -> io::Result<TorStream> {
        let addrport = format!("{}:{}\0", target.to_lowercase(), port);
        self.open_stream(RELAY_BEGIN, addrport.as_bytes())
    }

    /// Open a stream on a rendezvous circuit.
    ///
    /// The address is left empty: the service is the only thing at the far end
    /// of this circuit, so there is nothing to name, and C Tor sends `:port`
    /// alone here too.
    pub fn begin_stream_onion(&self, port: u16) -> io::Result<TorStream> {
        self.open_stream(RELAY_BEGIN, format!(":{port}\0").as_bytes())
    }

    /// Open a stream to the relay's own directory cache.
    pub fn begin_dir_stream(&self) -> io::Result<TorStream> {
        self.open_stream(RELAY_BEGIN_DIR, &[])
    }

    /// Send a BEGIN and hand back the stream at once, without waiting for the
    /// far end to confirm it. See [`TorStream`] for why.
    fn open_stream(&self, relay_command: u8, payload: &[u8]) -> io::Result<TorStream> {
        let hop = self.last_hop()?;
        let stream_id = self.alloc_stream_id()?;
        let shared = Arc::new(StreamShared {
            id: stream_id,
            hop,
            buf: Mutex::new(StreamBuf {
                data: VecDeque::new(),
                connected: false,
                ended: None,
                error: None,
                deliver_window: STREAM_WINDOW_START,
                package_window: STREAM_WINDOW_START,
                unacked: 0,
            }),
            cond: Condvar::new(),
        });
        self.inner
            .streams
            .lock()
            .unwrap()
            .insert(stream_id, Arc::clone(&shared));

        if let Err(e) = self.send_relay(hop, relay_command, stream_id, payload, false) {
            self.inner.streams.lock().unwrap().remove(&stream_id);
            return Err(e);
        }
        Ok(TorStream::new(self.clone(), shared))
    }

    fn alloc_stream_id(&self) -> io::Result<u16> {
        let streams = self.inner.streams.lock().unwrap();
        let mut state = self.inner.state.lock().unwrap();
        for _ in 0..u16::MAX as u32 {
            let id = state.next_stream_id;
            state.next_stream_id = state.next_stream_id.wrapping_add(1);
            if id == 0 || streams.contains_key(&id) {
                continue;
            }
            return Ok(id);
        }
        Err(io::Error::other("no free stream ID on this circuit"))
    }

    /// Send one RELAY_DATA cell, waiting for a SENDME if the circuit's package
    /// window is exhausted.
    fn send_data(&self, hop: usize, stream_id: u16, data: &[u8]) -> io::Result<()> {
        let deadline = Instant::now() + SENDME_TIMEOUT;
        let mut state = self.inner.state.lock().unwrap();
        while state.package_window <= 0 {
            if self.is_closed() {
                return Err(circuit_closed());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "circuit send window stayed empty",
                ));
            }
            let (guard, _) = self
                .inner
                .event
                .wait_timeout(state, deadline - now)
                .unwrap();
            state = guard;
        }
        state.package_window -= 1;
        let cell = build_relay_cell(
            &mut state,
            self.inner.circ_id,
            hop,
            RELAY_DATA,
            stream_id,
            data,
            false,
        )?;
        drop(state);
        self.inner.chan.send_cell(&cell)
    }

    pub fn close(&self) {
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        // Best effort: tell the first hop the circuit is going away.
        if let Ok(cell) = Cell::new(self.inner.circ_id, cell::CMD_DESTROY, vec![END_REASON_MISC]) {
            let _ = self.inner.chan.send_cell(&cell);
        }
        self.inner.chan.unregister_circuit(self.inner.circ_id);
        fail_all(&self.inner, "circuit closed");
        self.inner.event.notify_all();
    }
}

fn circuit_closed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "circuit is closed")
}

/// A RELAY_END reason, so callers (notably SOCKS5) can map it to their own
/// status codes.
#[derive(Debug, Clone, Copy)]
pub struct StreamEnd(pub u8);

impl std::fmt::Display for StreamEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "stream closed by exit: {}", end_reason_name(self.0))
    }
}

impl std::error::Error for StreamEnd {}

/// True when this error carries a RELAY_END reason -- that is, when the far
/// end answered the request rather than the circuit failing under it.
pub fn is_stream_end(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<StreamEnd>())
        .is_some()
}

impl From<StreamEnd> for io::Error {
    fn from(end: StreamEnd) -> io::Error {
        let kind = match end.0 {
            END_REASON_CONNECTREFUSED => io::ErrorKind::ConnectionRefused,
            END_REASON_TIMEOUT => io::ErrorKind::TimedOut,
            END_REASON_RESOLVEFAILED | END_REASON_NOROUTE => io::ErrorKind::NotFound,
            END_REASON_EXITPOLICY => io::ErrorKind::PermissionDenied,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, end)
    }
}

/// Build the EXTEND2 payload: link specifiers in the order the spec asks for
/// (IPv4, legacy identity, Ed25519 identity) then the ntor onion skin.
fn build_extend2(next: &RelayInfo, skin: &[u8]) -> Vec<u8> {
    let mut out = next.link_specifiers();
    out.reserve(4 + skin.len());
    out.extend_from_slice(&ntor::HANDSHAKE_TYPE_NTOR.to_be_bytes());
    out.extend_from_slice(&(skin.len() as u16).to_be_bytes());
    out.extend_from_slice(skin);
    out
}

/// Assemble one relay cell: digest first (over the body with the digest field
/// zeroed), then one AES layer per hop from the far end back to the near end.
fn build_relay_cell(
    state: &mut State,
    circ_id: u32,
    hop: usize,
    relay_command: u8,
    stream_id: u16,
    data: &[u8],
    early: bool,
) -> io::Result<Cell> {
    if data.len() > RELAY_DATA_MAX {
        return Err(invalid_data("relay message body too long"));
    }
    if hop >= state.hops.len() {
        return Err(invalid_data("relay cell addressed to a nonexistent hop"));
    }
    if early {
        if state.relay_early_left == 0 {
            return Err(invalid_data("circuit has no RELAY_EARLY cells left"));
        }
        state.relay_early_left -= 1;
    }

    let mut body = vec![0u8; CELL_BODY_LEN];
    body[0] = relay_command;
    // body[1..3] is 'recognized', which the sender always leaves at zero.
    body[3..5].copy_from_slice(&stream_id.to_be_bytes());
    // body[5..9] is the digest, zero while the digest is being computed.
    body[9..11].copy_from_slice(&(data.len() as u16).to_be_bytes());
    body[RELAY_HEADER_LEN..RELAY_HEADER_LEN + data.len()].copy_from_slice(data);
    // Padding: four zero bytes then random, so cell contents stay
    // unpredictable (tor-spec/relay-cells.md, proposal 289).
    let pad_start = RELAY_HEADER_LEN + data.len();
    if CELL_BODY_LEN > pad_start + 4 {
        rand::fill(&mut body[pad_start + 4..])?;
    }

    let target = &mut state.hops[hop];
    target.forward_digest.update(&body);
    let digest = target.forward_digest.peek_prefix::<4>();
    body[5..9].copy_from_slice(&digest);

    // XOR is commutative, but apply the layers outward from the target hop the
    // way the spec describes, so the code reads like the protocol.
    for h in (0..=hop).rev() {
        state.hops[h].forward_cipher.apply(&mut body);
    }

    let command = if early {
        cell::CMD_RELAY_EARLY
    } else {
        cell::CMD_RELAY
    };
    Cell::new(circ_id, command, body)
}

/// Peel layers until a hop recognises the cell. Returns the hop index and the
/// decrypted body; leaves every hop's state untouched if nobody recognises it.
fn decrypt_inbound(state: &mut State, body: &mut [u8]) -> Option<usize> {
    for index in 0..state.hops.len() {
        state.hops[index].backward_cipher.apply(body);
        // 'recognized' is a cheap filter; the digest is the real check.
        if body[1] != 0 || body[2] != 0 {
            continue;
        }
        let mut claimed = [0u8; 4];
        claimed.copy_from_slice(&body[5..9]);
        body[5..9].fill(0);

        // Try on a copy: an unrecognised cell must not advance the digest.
        let mut trial = state.hops[index].backward_digest.clone();
        trial.update(body);
        let full = trial.peek_prefix::<20>();
        if full[..4] == claimed {
            state.hops[index].backward_digest = trial;
            state.last_recv_digest = full;
            return Some(index);
        }
        body[5..9].copy_from_slice(&claimed);
    }
    None
}

fn pump(inner: Arc<Inner>, rx: Receiver<Cell>) {
    while let Ok(cell) = rx.recv() {
        if inner.closed.load(Ordering::Acquire) {
            break;
        }
        if let Err(e) = handle_cell(&inner, cell) {
            debug!("circuit {}: {e}", inner.circ_id);
            break;
        }
    }
    inner.closed.store(true, Ordering::Release);
    inner.chan.unregister_circuit(inner.circ_id);
    fail_all(&inner, "circuit closed");
    inner.event.notify_all();
}

fn handle_cell(inner: &Arc<Inner>, cell: Cell) -> io::Result<()> {
    match cell.command {
        cell::CMD_CREATED_FAST => {
            if cell.body.len() < ntor::CREATED_FAST_LEN {
                return Err(invalid_data("CREATED_FAST cell is too short"));
            }
            let mut state = inner.state.lock().unwrap();
            state.handshake = Some(Ok(cell.body[..ntor::CREATED_FAST_LEN].to_vec()));
            drop(state);
            inner.event.notify_all();
            Ok(())
        }
        cell::CMD_CREATED2 => {
            let len = super::cell::be_u16(&cell.body, 0)? as usize;
            if 2 + len > cell.body.len() {
                return Err(invalid_data("CREATED2 length runs past the cell"));
            }
            let mut state = inner.state.lock().unwrap();
            state.handshake = Some(Ok(cell.body[2..2 + len].to_vec()));
            drop(state);
            inner.event.notify_all();
            Ok(())
        }
        cell::CMD_DESTROY => {
            let reason = cell.body.first().copied().unwrap_or(0);
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("DESTROY received, reason {reason}"),
            ))
        }
        cell::CMD_RELAY | cell::CMD_RELAY_EARLY => handle_relay(inner, cell),
        other => {
            trace!(
                "circuit {}: ignoring {} cell",
                inner.circ_id,
                cell::command_name(other)
            );
            Ok(())
        }
    }
}

fn handle_relay(inner: &Arc<Inner>, cell: Cell) -> io::Result<()> {
    let mut body = cell.body;
    if body.len() != CELL_BODY_LEN {
        return Err(invalid_data("relay cell has the wrong body length"));
    }

    let mut state = inner.state.lock().unwrap();
    let hop = match decrypt_inbound(&mut state, &mut body) {
        Some(hop) => hop,
        None => {
            // Not for us and not forwardable: a client is always the far end.
            warn!("circuit {}: unrecognised relay cell", inner.circ_id);
            return Ok(());
        }
    };

    let relay_command = body[0];
    let stream_id = u16::from_be_bytes([body[3], body[4]]);
    let length = u16::from_be_bytes([body[9], body[10]]) as usize;
    if length > RELAY_DATA_MAX {
        return Err(invalid_data("relay message length exceeds the cell"));
    }
    let data = &body[RELAY_HEADER_LEN..RELAY_HEADER_LEN + length];

    match relay_command {
        RELAY_EXTENDED2 => {
            let len = super::cell::be_u16(data, 0)? as usize;
            if 2 + len > data.len() {
                return Err(invalid_data("EXTENDED2 length runs past the message"));
            }
            state.handshake = Some(Ok(data[2..2 + len].to_vec()));
            drop(state);
            inner.event.notify_all();
        }
        RELAY_SENDME => {
            if stream_id == 0 {
                state.package_window += CIRCUIT_WINDOW_INCREMENT;
                drop(state);
                inner.event.notify_all();
            } else {
                drop(state);
                if let Some(stream) = lookup(inner, stream_id) {
                    let mut buf = stream.buf.lock().unwrap();
                    buf.package_window += STREAM_WINDOW_INCREMENT;
                    drop(buf);
                    stream.cond.notify_all();
                }
            }
        }
        RELAY_DATA => {
            state.deliver_window -= 1;
            if state.deliver_window < 0 {
                return Err(invalid_data("peer overran the circuit deliver window"));
            }
            // Acknowledge a whole increment as soon as one is outstanding; the
            // digest we quote is the one from this triggering cell.
            let sendme = if state.deliver_window <= CIRCUIT_WINDOW_START - CIRCUIT_WINDOW_INCREMENT
            {
                state.deliver_window += CIRCUIT_WINDOW_INCREMENT;
                let mut payload = Vec::with_capacity(23);
                payload.push(1); // authenticated SENDME
                payload.extend_from_slice(&20u16.to_be_bytes());
                payload.extend_from_slice(&state.last_recv_digest);
                Some(build_relay_cell(
                    &mut state,
                    inner.circ_id,
                    hop,
                    RELAY_SENDME,
                    0,
                    &payload,
                    false,
                )?)
            } else {
                None
            };
            let payload = data.to_vec();
            drop(state);
            if let Some(cell) = sendme {
                inner.chan.send_cell(&cell)?;
            }
            match lookup(inner, stream_id) {
                Some(stream) => {
                    let mut buf = stream.buf.lock().unwrap();
                    buf.deliver_window -= 1;
                    buf.unacked += 1;
                    buf.data.extend(payload.iter().copied());
                    drop(buf);
                    stream.cond.notify_all();
                }
                None => trace!(
                    "circuit {}: data for unknown stream {stream_id}",
                    inner.circ_id
                ),
            }
        }
        RELAY_CONNECTED => {
            drop(state);
            if let Some(stream) = lookup(inner, stream_id) {
                let mut buf = stream.buf.lock().unwrap();
                buf.connected = true;
                drop(buf);
                stream.cond.notify_all();
            }
        }
        RELAY_END => {
            let reason = data.first().copied().unwrap_or(END_REASON_MISC);
            drop(state);
            if let Some(stream) = lookup(inner, stream_id) {
                let mut buf = stream.buf.lock().unwrap();
                buf.ended = Some(reason);
                drop(buf);
                stream.cond.notify_all();
            }
            inner.streams.lock().unwrap().remove(&stream_id);
        }
        RELAY_TRUNCATED => {
            let reason = data.first().copied().unwrap_or(0);
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("circuit truncated, reason {reason}"),
            ));
        }
        RELAY_RENDEZVOUS_ESTABLISHED | RELAY_INTRODUCE_ACK | RELAY_RENDEZVOUS2 => {
            state.push_control(relay_command, data.to_vec());
            drop(state);
            inner.event.notify_all();
        }
        RELAY_DROP => {}
        other => {
            trace!("circuit {}: ignoring relay command {other}", inner.circ_id);
        }
    }
    Ok(())
}

fn lookup(inner: &Arc<Inner>, stream_id: u16) -> Option<Arc<StreamShared>> {
    inner.streams.lock().unwrap().get(&stream_id).cloned()
}

fn fail_all(inner: &Arc<Inner>, reason: &str) {
    let streams: Vec<Arc<StreamShared>> = inner
        .streams
        .lock()
        .unwrap()
        .drain()
        .map(|(_, s)| s)
        .collect();
    for stream in streams {
        let mut buf = stream.buf.lock().unwrap();
        if buf.error.is_none() && buf.ended.is_none() {
            buf.error = Some(reason.to_string());
        }
        drop(buf);
        stream.cond.notify_all();
    }
}

struct StreamShared {
    id: u16,
    hop: usize,
    buf: Mutex<StreamBuf>,
    cond: Condvar,
}

struct StreamBuf {
    data: VecDeque<u8>,
    connected: bool,
    /// Set when the far end sent RELAY_END; the value is its reason code.
    ended: Option<u8>,
    error: Option<String>,
    deliver_window: i32,
    package_window: i32,
    /// Received cells not yet acknowledged with a stream SENDME.
    unacked: i32,
}

/// How many bytes written before the far end confirms the stream are kept, in
/// case the attempt has to be made again on another circuit. C Tor keeps a
/// comparable amount for the same reason; past this the request is too big to
/// be worth replaying and the connection simply fails.
const MAX_REPLAY_BYTES: usize = 16 * 1024;

/// How many times one connection may be started again elsewhere.
const MAX_REATTACHES: usize = 2;

/// How the client opens this connection again on a different circuit.
/// Given the circuit that let the connection down, open it again elsewhere.
pub type Reattach = Box<dyn Fn(&Circuit) -> io::Result<TorStream> + Send + Sync>;

/// A TCP-like stream carried by a circuit.
///
/// The stream is *optimistic*: `begin_stream` returns as soon as the BEGIN has
/// been sent, without waiting for the exit's CONNECTED. The consensus sets
/// `UseOptimisticData=1` and tor-spec/opening-streams.md allows it, and it
/// takes a whole round trip off every connection -- the client's first bytes
/// (a TLS ClientHello, say) travel in the same direction as the BEGIN instead
/// of after the reply to it.
///
/// The cost is that a refusal now arrives after the caller has been told the
/// connection succeeded. For the one refusal that is about the exit rather
/// than the destination -- EXITPOLICY -- and for a circuit that dies under
/// the stream, the bytes written so far are replayed on a fresh circuit and
/// the caller sees nothing. A refusal that is about the destination
/// (CONNECTREFUSED, RESOLVEFAILED) would get the same answer anywhere, so it
/// is passed straight through.
pub struct TorStream {
    inner: Arc<StreamState>,
}

struct StreamState {
    /// The circuit and stream currently carrying this connection, replaced
    /// wholesale by a reattach. Both halves of a `try_clone` share it, so a
    /// reader and a writer move together.
    live: Mutex<Live>,
    replay: Mutex<Replay>,
    /// Absent for streams that cannot be moved, such as a directory fetch.
    reattach: std::sync::OnceLock<Reattach>,
}

#[derive(Clone)]
struct Live {
    circuit: Circuit,
    shared: Arc<StreamShared>,
}

struct Replay {
    buffered: Vec<u8>,
    /// False once the far end has answered, once more has been written than
    /// is worth keeping, or once the attempts are used up.
    allowed: bool,
    attempts: usize,
}

impl TorStream {
    fn new(circuit: Circuit, shared: Arc<StreamShared>) -> Self {
        Self {
            inner: Arc::new(StreamState {
                live: Mutex::new(Live { circuit, shared }),
                replay: Mutex::new(Replay {
                    buffered: Vec::new(),
                    allowed: true,
                    attempts: 0,
                }),
                reattach: std::sync::OnceLock::new(),
            }),
        }
    }

    /// A second handle on the same stream, so the relay loop can read on one
    /// thread and write on another.
    pub fn try_clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Say how to open this connection again elsewhere, which is what makes
    /// an optimistic failure recoverable. Without it a failure is final.
    pub fn set_reattach(&self, reattach: Reattach) {
        let _ = self.inner.reattach.set(reattach);
    }

    fn live(&self) -> Live {
        self.inner.live.lock().unwrap().clone()
    }

    /// Whether this failure is worth trying again on another circuit, and
    /// whether we are still in a position to.
    fn may_retry(&self, error: &io::Error) -> bool {
        let worth_it = match error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<StreamEnd>())
        {
            // The exit will not carry this destination. Another one may.
            Some(end) => end.0 == END_REASON_EXITPOLICY,
            // The circuit went away under us, which says nothing about the
            // destination.
            None => matches!(
                error.kind(),
                io::ErrorKind::ConnectionAborted | io::ErrorKind::NotConnected
            ),
        };
        if !worth_it || self.inner.reattach.get().is_none() {
            return false;
        }
        let replay = self.inner.replay.lock().unwrap();
        replay.allowed && replay.attempts < MAX_REATTACHES
    }

    /// Open the connection again on a fresh circuit and re-send whatever was
    /// written before the first attempt failed.
    fn reattach(&self) -> io::Result<()> {
        let Some(open) = self.inner.reattach.get() else {
            return Err(io::Error::other("this stream cannot be moved"));
        };
        let buffered = {
            let mut replay = self.inner.replay.lock().unwrap();
            replay.attempts += 1;
            replay.buffered.clone()
        };

        let failed = self.live().circuit;
        let fresh = open(&failed)?;
        let live = fresh.live();
        crate::debug!(
            "connection moved to circuit {}, replaying {} buffered bytes",
            live.circuit.circ_id(),
            buffered.len()
        );
        *self.inner.live.lock().unwrap() = live.clone();

        for chunk in buffered.chunks(RELAY_DATA_MAX) {
            send_stream_data(&live, chunk)?;
        }
        Ok(())
    }

    /// Note what was sent, in case it has to be sent again.
    fn record_written(&self, data: &[u8]) {
        let mut replay = self.inner.replay.lock().unwrap();
        if !replay.allowed {
            return;
        }
        if replay.buffered.len() + data.len() > MAX_REPLAY_BYTES {
            // Too much to be worth holding: from here the connection lives or
            // dies on the circuit it is on.
            replay.allowed = false;
            replay.buffered = Vec::new();
            return;
        }
        replay.buffered.extend_from_slice(data);
    }

    /// The far end has answered, so nothing needs replaying any more.
    fn note_established(&self) {
        let mut replay = self.inner.replay.lock().unwrap();
        if replay.allowed {
            replay.allowed = false;
            replay.buffered = Vec::new();
        }
    }

    /// Ask the far end for another increment once the application has drained
    /// enough of the buffer; this is what stops a slow reader from being sent
    /// more than it can hold.
    fn maybe_send_sendme(&self, live: &Live) -> io::Result<()> {
        loop {
            let mut buf = live.shared.buf.lock().unwrap();
            let backlog_low = buf.data.len() <= STREAM_WINDOW_INCREMENT as usize * RELAY_DATA_MAX;
            if buf.unacked < STREAM_WINDOW_INCREMENT || !backlog_low {
                return Ok(());
            }
            buf.unacked -= STREAM_WINDOW_INCREMENT;
            buf.deliver_window += STREAM_WINDOW_INCREMENT;
            drop(buf);
            live.circuit
                .send_relay(live.shared.hop, RELAY_SENDME, live.shared.id, &[], false)?;
        }
    }

    /// Tell the exit we are done with this stream.
    pub fn close(&self) {
        let live = self.live();
        let _ = live.circuit.send_relay(
            live.shared.hop,
            RELAY_END,
            live.shared.id,
            &[END_REASON_DONE],
            false,
        );
        live.circuit
            .inner
            .streams
            .lock()
            .unwrap()
            .remove(&live.shared.id);
        let mut buf = live.shared.buf.lock().unwrap();
        if buf.ended.is_none() {
            buf.ended = Some(END_REASON_DONE);
        }
        drop(buf);
        live.shared.cond.notify_all();
    }
}

/// Wait for the far end to say something on this stream: data, a refusal, or
/// the circuit failing under it.
fn read_stream(live: &Live, out: &mut [u8]) -> io::Result<usize> {
    let mut buf = live.shared.buf.lock().unwrap();
    loop {
        if !buf.data.is_empty() {
            let n = buf.data.len().min(out.len());
            for (slot, byte) in out.iter_mut().zip(buf.data.drain(..n)) {
                *slot = byte;
            }
            return Ok(n);
        }
        if let Some(err) = buf.error.clone() {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, err));
        }
        if let Some(reason) = buf.ended {
            // A clean close reads as EOF; anything else is an error.
            return match reason {
                END_REASON_DONE | END_REASON_MISC => Ok(0),
                other => Err(StreamEnd(other).into()),
            };
        }
        let (guard, _) = live
            .shared
            .cond
            .wait_timeout(buf, Duration::from_secs(1))
            .unwrap();
        buf = guard;
        if live.circuit.is_closed() && buf.data.is_empty() {
            return Err(circuit_closed());
        }
    }
}

/// Send one chunk on a stream, waiting for a SENDME if its window is spent.
///
/// The stream may not be connected yet; that is the point of optimistic data,
/// and the exit queues what arrives before it has answered.
fn send_stream_data(live: &Live, chunk: &[u8]) -> io::Result<()> {
    let deadline = Instant::now() + SENDME_TIMEOUT;
    let mut buf = live.shared.buf.lock().unwrap();
    while buf.package_window <= 0 {
        if let Some(reason) = buf.ended {
            return Err(StreamEnd(reason).into());
        }
        if let Some(err) = buf.error.clone() {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, err));
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "stream send window stayed empty",
            ));
        }
        let (guard, _) = live
            .shared
            .cond
            .wait_timeout(buf, (deadline - now).min(Duration::from_secs(1)))
            .unwrap();
        buf = guard;
        if live.circuit.is_closed() {
            return Err(circuit_closed());
        }
    }
    if let Some(reason) = buf.ended {
        return Err(StreamEnd(reason).into());
    }
    buf.package_window -= 1;
    drop(buf);

    live.circuit
        .send_data(live.shared.hop, live.shared.id, chunk)
}

impl io::Read for TorStream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            let live = self.live();
            match read_stream(&live, out) {
                Ok(n) => {
                    // Anything at all coming back means the far end answered,
                    // so there is no longer anything to replay.
                    self.note_established();
                    self.maybe_send_sendme(&live)?;
                    return Ok(n);
                }
                Err(e) if self.may_retry(&e) => {
                    crate::info!("stream failed before it was established ({e}); trying again");
                    self.reattach()?;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl io::Write for TorStream {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let chunk = &data[..data.len().min(RELAY_DATA_MAX)];
        loop {
            let live = self.live();
            if live.shared.buf.lock().unwrap().connected {
                self.note_established();
            }
            match send_stream_data(&live, chunk) {
                Ok(()) => {
                    self.record_written(chunk);
                    return Ok(chunk.len());
                }
                Err(e) if self.may_retry(&e) => {
                    crate::info!("stream failed before it was established ({e}); trying again");
                    self.reattach()?;
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::hash::Digest;
    use crate::tor::ntor::CircuitKeys;

    fn keys(seed: u8) -> CircuitKeys {
        CircuitKeys {
            df: [seed; 20],
            db: [seed ^ 0xff; 20],
            kf: [seed.wrapping_add(1); 16],
            kb: [seed.wrapping_add(2); 16],
        }
    }

    fn hs_keys(seed: u8) -> HsCircuitKeys {
        HsCircuitKeys {
            df: [seed; 32],
            db: [seed ^ 0xff; 32],
            kf: [seed.wrapping_add(1); 32],
            kb: [seed.wrapping_add(2); 32],
        }
    }

    /// The far end's view of one hop: the mirror image of ours.
    struct PeerHop {
        cipher_from_client: HopCipher,
        digest_from_client: Digest,
    }

    impl PeerHop {
        fn new(k: &CircuitKeys) -> Self {
            let mut digest = Digest::sha1();
            digest.update(&k.df);
            Self {
                cipher_from_client: HopCipher::Aes128(Aes128Ctr::new(&k.kf)),
                digest_from_client: digest,
            }
        }

        fn virtual_hop(k: &HsCircuitKeys) -> Self {
            let mut digest = Digest::sha3_256();
            digest.update(&k.df);
            Self {
                cipher_from_client: HopCipher::Aes256(Aes256Ctr::new(&k.kf)),
                digest_from_client: digest,
            }
        }
    }

    fn state_with_hops(all: &[CircuitKeys]) -> State {
        State {
            hops: all.iter().map(Hop::new).collect(),
            relay_early_left: MAX_RELAY_EARLY,
            package_window: CIRCUIT_WINDOW_START,
            deliver_window: CIRCUIT_WINDOW_START,
            next_stream_id: 1,
            handshake: None,
            control: VecDeque::new(),
            last_recv_digest: [0u8; 20],
        }
    }

    /// A cell built for hop N must decrypt correctly after every hop in front
    /// of it has removed its layer, and its digest must check out.
    #[test]
    fn onion_layers_unwrap_at_the_target_hop() {
        let all = [keys(1), keys(40), keys(90)];
        let mut state = state_with_hops(&all);
        let mut peers: Vec<PeerHop> = all.iter().map(PeerHop::new).collect();

        for target in 0..3usize {
            let payload = vec![target as u8 + 0x10; 100];
            let cell = build_relay_cell(
                &mut state,
                0x8000_0001,
                target,
                RELAY_DATA,
                7,
                &payload,
                false,
            )
            .unwrap();
            let mut body = cell.body.clone();
            // Every hop up to the target strips its own layer.
            for peer in peers.iter_mut().take(target + 1) {
                peer.cipher_from_client.apply(&mut body);
            }
            assert_eq!(body[0], RELAY_DATA);
            assert_eq!(
                &body[1..3],
                &[0, 0],
                "recognized must be zero at the target"
            );
            assert_eq!(u16::from_be_bytes([body[3], body[4]]), 7);
            assert_eq!(
                u16::from_be_bytes([body[9], body[10]]) as usize,
                payload.len()
            );
            assert_eq!(
                &body[RELAY_HEADER_LEN..RELAY_HEADER_LEN + payload.len()],
                &payload[..]
            );

            let mut claimed = [0u8; 4];
            claimed.copy_from_slice(&body[5..9]);
            body[5..9].fill(0);
            peers[target].digest_from_client.update(&body);
            assert_eq!(peers[target].digest_from_client.peek_prefix::<4>(), claimed);
        }
    }

    /// The receive path must accept a cell from any hop and, crucially, leave
    /// every hop's running digest untouched when nothing recognises the cell.
    #[test]
    fn inbound_recognition_and_rollback() {
        let all = [keys(3), keys(50)];
        let mut client = state_with_hops(&all);
        // A second copy standing in for the relays' backward state.
        let mut relays = state_with_hops(&all);

        for target in 0..2usize {
            // Build the cell using the relay-side hop's *backward* keys by
            // reusing the forward machinery on a mirrored state.
            let mut body = vec![0u8; CELL_BODY_LEN];
            body[0] = RELAY_DATA;
            body[3..5].copy_from_slice(&9u16.to_be_bytes());
            body[9..11].copy_from_slice(&4u16.to_be_bytes());
            body[RELAY_HEADER_LEN..RELAY_HEADER_LEN + 4].copy_from_slice(b"ping");
            relays.hops[target].backward_digest.update(&body);
            let digest = relays.hops[target].backward_digest.peek_prefix::<4>();
            body[5..9].copy_from_slice(&digest);
            for h in target..=target {
                relays.hops[h].backward_cipher.apply(&mut body);
            }
            for h in (0..target).rev() {
                relays.hops[h].backward_cipher.apply(&mut body);
            }

            let hop = decrypt_inbound(&mut client, &mut body).expect("cell should be recognised");
            assert_eq!(hop, target);
            assert_eq!(&body[RELAY_HEADER_LEN..RELAY_HEADER_LEN + 4], b"ping");
        }

        // Garbage must be rejected without disturbing the digests.
        let before: Vec<[u8; 20]> = client
            .hops
            .iter()
            .map(|h| h.backward_digest.peek_prefix::<20>())
            .collect();
        let mut junk = vec![0u8; CELL_BODY_LEN];
        junk[1] = 0;
        junk[2] = 0;
        assert!(decrypt_inbound(&mut client, &mut junk).is_none());
        let after: Vec<[u8; 20]> = client
            .hops
            .iter()
            .map(|h| h.backward_digest.peek_prefix::<20>())
            .collect();
        assert_eq!(before, after);
    }

    /// A rendezvous circuit's fourth hop is the service itself, with SHA3-256
    /// and AES-256. Cells addressed to it must unwrap there, and only there,
    /// exactly as for an ordinary hop.
    #[test]
    fn onion_layers_unwrap_at_a_virtual_hop() {
        let relays = [keys(2), keys(60), keys(120)];
        let service = hs_keys(7);
        let mut state = state_with_hops(&relays);
        state.hops.push(Hop::virtual_hop(&service));

        let mut peers: Vec<PeerHop> = relays.iter().map(PeerHop::new).collect();
        peers.push(PeerHop::virtual_hop(&service));

        let target = 3usize;
        let payload = b"onion service payload".to_vec();
        let cell = build_relay_cell(
            &mut state,
            0x8000_0002,
            target,
            RELAY_DATA,
            5,
            &payload,
            false,
        )
        .unwrap();

        let mut body = cell.body.clone();
        for peer in peers.iter_mut() {
            peer.cipher_from_client.apply(&mut body);
        }
        assert_eq!(body[0], RELAY_DATA);
        assert_eq!(&body[1..3], &[0, 0]);
        assert_eq!(
            &body[RELAY_HEADER_LEN..RELAY_HEADER_LEN + payload.len()],
            &payload[..]
        );

        // The digest the service checks is the first four bytes of a
        // SHA3-256, not of a SHA-1.
        let mut claimed = [0u8; 4];
        claimed.copy_from_slice(&body[5..9]);
        body[5..9].fill(0);
        peers[target].digest_from_client.update(&body);
        assert_eq!(peers[target].digest_from_client.peek_prefix::<4>(), claimed);
        // A 32-byte peek would panic on a SHA-1 hop: this one really is SHA3.
        let _ = peers[target].digest_from_client.peek_prefix::<32>();
    }

    /// The inbound path must recognise a cell from the virtual hop, and an
    /// authenticated SENDME still quotes twenty bytes even though the digest
    /// is longer.
    #[test]
    fn inbound_recognition_at_a_virtual_hop() {
        let relays = [keys(4)];
        let service = hs_keys(9);
        let mut client = state_with_hops(&relays);
        client.hops.push(Hop::virtual_hop(&service));
        let mut peers = state_with_hops(&relays);
        peers.hops.push(Hop::virtual_hop(&service));

        let mut body = vec![0u8; CELL_BODY_LEN];
        body[0] = RELAY_DATA;
        body[3..5].copy_from_slice(&11u16.to_be_bytes());
        body[9..11].copy_from_slice(&4u16.to_be_bytes());
        body[RELAY_HEADER_LEN..RELAY_HEADER_LEN + 4].copy_from_slice(b"pong");
        peers.hops[1].backward_digest.update(&body);
        let digest = peers.hops[1].backward_digest.peek_prefix::<4>();
        body[5..9].copy_from_slice(&digest);
        peers.hops[1].backward_cipher.apply(&mut body);
        peers.hops[0].backward_cipher.apply(&mut body);

        let hop = decrypt_inbound(&mut client, &mut body).expect("recognised");
        assert_eq!(hop, 1, "the cell came from the service");
        assert_eq!(&body[RELAY_HEADER_LEN..RELAY_HEADER_LEN + 4], b"pong");
        assert_eq!(
            client.last_recv_digest,
            client.hops[1].backward_digest.peek_prefix::<20>()
        );
    }

    /// Control replies are taken by command rather than in arrival order,
    /// because a RENDEZVOUS2 can turn up while an INTRODUCE_ACK is still
    /// being waited for.
    #[test]
    fn control_replies_are_queued_and_taken_by_command() {
        let mut state = state_with_hops(&[keys(1)]);
        state.push_control(RELAY_RENDEZVOUS_ESTABLISHED, Vec::new());
        state.push_control(RELAY_INTRODUCE_ACK, vec![0, 0]);
        assert_eq!(state.take_control(RELAY_INTRODUCE_ACK), Some(vec![0, 0]));
        assert_eq!(state.take_control(RELAY_INTRODUCE_ACK), None);
        assert_eq!(
            state.take_control(RELAY_RENDEZVOUS_ESTABLISHED),
            Some(Vec::new())
        );

        // A flood must not grow the queue; the newest replies are the ones
        // worth keeping.
        for i in 0..MAX_QUEUED_CONTROL as u8 * 2 {
            state.push_control(RELAY_RENDEZVOUS2, vec![i]);
        }
        assert_eq!(state.control.len(), MAX_QUEUED_CONTROL);
        assert_eq!(
            state.take_control(RELAY_RENDEZVOUS2),
            Some(vec![MAX_QUEUED_CONTROL as u8])
        );
    }

    #[test]
    fn relay_early_budget_is_enforced() {
        let all = [keys(11)];
        let mut state = state_with_hops(&all);
        for _ in 0..MAX_RELAY_EARLY {
            build_relay_cell(&mut state, 1, 0, RELAY_EXTEND2, 0, &[1, 2, 3], true).unwrap();
        }
        assert!(build_relay_cell(&mut state, 1, 0, RELAY_EXTEND2, 0, &[1, 2, 3], true).is_err());
        // Ordinary relay cells are still fine.
        assert!(build_relay_cell(&mut state, 1, 0, RELAY_DATA, 1, &[1], false).is_ok());
    }

    #[test]
    fn rejects_oversized_and_misaddressed_messages() {
        let all = [keys(21)];
        let mut state = state_with_hops(&all);
        assert!(build_relay_cell(
            &mut state,
            1,
            0,
            RELAY_DATA,
            1,
            &[0; RELAY_DATA_MAX + 1],
            false
        )
        .is_err());
        assert!(build_relay_cell(&mut state, 1, 5, RELAY_DATA, 1, &[0], false).is_err());
    }

    /// The distinction the onion path leans on: a RELAY_END is the far end
    /// answering, while anything else means the circuit let us down.
    #[test]
    fn stream_end_errors_are_recognisable() {
        let answered: io::Error = StreamEnd(END_REASON_DONE).into();
        assert!(is_stream_end(&answered));
        assert!(is_stream_end(&StreamEnd(END_REASON_CONNECTREFUSED).into()));
        assert!(!is_stream_end(&circuit_closed()));
        assert!(!is_stream_end(&io::Error::other("something else")));
        assert!(!is_stream_end(&invalid_data("malformed")));
    }

    #[test]
    fn extend2_payload_layout() {
        let relay = RelayInfo {
            addr: "10.1.2.3:9001".parse().unwrap(),
            rsa_identity: [0xaa; 20],
            ed_identity: Some([0xbb; 32]),
            ntor_onion_key: [0xcc; 32],
        };
        let payload = build_extend2(&relay, &[0x11; 84]);
        assert_eq!(payload[0], 3, "three link specifiers");
        assert_eq!(payload[1], 0x00, "IPv4 comes first");
        assert_eq!(payload[2], 6);
        assert_eq!(&payload[3..7], &[10, 1, 2, 3]);
        assert_eq!(u16::from_be_bytes([payload[7], payload[8]]), 9001);
        assert_eq!(payload[9], 0x02, "then the legacy identity");
        assert_eq!(payload[10], 20);
        assert_eq!(payload[31], 0x03, "then the Ed25519 identity");
        assert_eq!(payload[32], 32);
        let tail = &payload[65..];
        assert_eq!(u16::from_be_bytes([tail[0], tail[1]]), 2, "HTYPE ntor");
        assert_eq!(u16::from_be_bytes([tail[2], tail[3]]), 84, "HLEN");
        assert_eq!(tail.len(), 4 + 84);
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::tor::channel::Channel;
    use crate::tor::dir::fallback::FALLBACK_DIRS;
    use std::net::Ipv4Addr;

    /// Live check: build a one-hop CREATE_FAST circuit to a fallback mirror,
    /// open a BEGIN_DIR stream and fetch a small document over it.
    ///
    /// Run with `cargo test -- --ignored --nocapture`.
    #[test]
    #[ignore = "requires network access to the Tor network"]
    fn one_hop_circuit_fetches_from_a_directory_cache() {
        crate::log::init();
        let mut last = String::new();
        for _ in 0..8 {
            let index = rand::below(FALLBACK_DIRS.len() as u64).unwrap() as usize;
            let fb = &FALLBACK_DIRS[index];
            let addr = SocketAddrV4::new(Ipv4Addr::from(fb.ipv4), fb.or_port);
            let chan = match Channel::connect(addr, None) {
                Ok(c) => c,
                Err(e) => {
                    last = format!("{addr}: channel: {e}");
                    continue;
                }
            };
            let circuit = match Circuit::create_fast(&chan) {
                Ok(c) => c,
                Err(e) => {
                    last = format!("{addr}: create_fast: {e}");
                    chan.close();
                    continue;
                }
            };
            assert_eq!(circuit.hop_count(), 1);
            match crate::tor::dir::fetch::get(&circuit, "/tor/server/authority") {
                Ok(body) => {
                    println!("{addr}: BEGIN_DIR fetched {} bytes", body.len());
                    assert!(
                        body.starts_with(b"router "),
                        "expected a router descriptor, got {:?}",
                        String::from_utf8_lossy(&body[..body.len().min(60)])
                    );
                    circuit.close();
                    chan.close();
                    return;
                }
                Err(e) => {
                    // Not every mirror serves that path; CONNECTED still proves
                    // the circuit and the stream work.
                    last = format!("{addr}: fetch: {e}");
                    println!("{last}");
                    circuit.close();
                    chan.close();
                }
            }
        }
        panic!("no fallback mirror answered: {last}");
    }
}
