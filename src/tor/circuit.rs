//! Circuits: onion-encrypted relay cells, circuit construction, flow control
//! and stream multiplexing.
//!
//! One thread per circuit ("the pump") owns the receive side. It takes cells
//! from the channel, peels one AES-CTR layer per hop until the running SHA-1
//! digest recognises the cell, and hands the result to the right stream. Every
//! piece of per-hop crypto lives behind a single mutex, so the pump and any
//! number of writer threads take turns rather than racing.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use super::cell::{self, Cell, CELL_BODY_LEN};
use super::channel::Channel;
use super::ntor::{self, CreateFastClient, NtorClient};
use super::RelayInfo;
use crate::ffi::aes::Aes128Ctr;
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

/// One hop's cryptographic state.
struct Hop {
    forward_cipher: Aes128Ctr,
    backward_cipher: Aes128Ctr,
    forward_digest: Digest,
    backward_digest: Digest,
}

impl Hop {
    fn new(keys: &ntor::CircuitKeys) -> Self {
        let mut forward_digest = Digest::sha1();
        forward_digest.update(&keys.df);
        let mut backward_digest = Digest::sha1();
        backward_digest.update(&keys.db);
        Self {
            forward_cipher: Aes128Ctr::new(&keys.kf),
            backward_cipher: Aes128Ctr::new(&keys.kb),
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
    /// Rolling digest of the last recognised inbound cell, which is what an
    /// authenticated (version 1) SENDME has to quote.
    last_recv_digest: [u8; 20],
}

struct Inner {
    chan: Channel,
    circ_id: u32,
    state: Mutex<State>,
    event: Condvar,
    streams: Mutex<HashMap<u16, Arc<StreamShared>>>,
    closed: AtomicBool,
    created: Instant,
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
                last_recv_digest: [0u8; 20],
            }),
            event: Condvar::new(),
            streams: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
            created: Instant::now(),
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

        let last_hop = {
            let state = self.inner.state.lock().unwrap();
            state
                .hops
                .len()
                .checked_sub(1)
                .ok_or_else(|| invalid_data("cannot extend a circuit with no hops"))?
        };
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

    pub fn hop_count(&self) -> usize {
        self.inner.state.lock().unwrap().hops.len()
    }

    pub fn age(&self) -> Duration {
        self.inner.created.elapsed()
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

    /// Open a stream to the relay's own directory cache.
    pub fn begin_dir_stream(&self) -> io::Result<TorStream> {
        self.open_stream(RELAY_BEGIN_DIR, &[])
    }

    fn open_stream(&self, relay_command: u8, payload: &[u8]) -> io::Result<TorStream> {
        let hop = {
            let state = self.inner.state.lock().unwrap();
            state
                .hops
                .len()
                .checked_sub(1)
                .ok_or_else(|| invalid_data("cannot open a stream on a circuit with no hops"))?
        };
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

        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        let mut buf = shared.buf.lock().unwrap();
        loop {
            if buf.connected {
                break;
            }
            if let Some(reason) = buf.ended {
                drop(buf);
                self.inner.streams.lock().unwrap().remove(&stream_id);
                return Err(StreamEnd(reason).into());
            }
            if let Some(err) = buf.error.clone() {
                drop(buf);
                self.inner.streams.lock().unwrap().remove(&stream_id);
                return Err(io::Error::other(err));
            }
            let now = Instant::now();
            if now >= deadline {
                drop(buf);
                self.inner.streams.lock().unwrap().remove(&stream_id);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for RELAY_CONNECTED",
                ));
            }
            let (guard, _) = shared.cond.wait_timeout(buf, deadline - now).unwrap();
            buf = guard;
        }
        drop(buf);

        Ok(TorStream {
            circuit: self.clone(),
            shared,
        })
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
    let mut specs: Vec<(u8, Vec<u8>)> = Vec::with_capacity(3);
    let mut ipv4 = Vec::with_capacity(6);
    ipv4.extend_from_slice(&next.addr.ip().octets());
    ipv4.extend_from_slice(&next.addr.port().to_be_bytes());
    specs.push((0x00, ipv4));
    specs.push((0x02, next.rsa_identity.to_vec()));
    if let Some(ed) = next.ed_identity {
        specs.push((0x03, ed.to_vec()));
    }

    let mut out = Vec::with_capacity(64 + skin.len());
    out.push(specs.len() as u8);
    for (kind, value) in specs {
        out.push(kind);
        out.push(value.len() as u8);
        out.extend_from_slice(&value);
    }
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
        let full = trial.peek();
        if full[..4] == claimed {
            state.hops[index].backward_digest = trial;
            state.last_recv_digest.copy_from_slice(&full[..20]);
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
    let streams: Vec<Arc<StreamShared>> = inner.streams.lock().unwrap().drain().map(|(_, s)| s).collect();
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

/// A TCP-like stream carried by a circuit.
pub struct TorStream {
    circuit: Circuit,
    shared: Arc<StreamShared>,
}

impl TorStream {
    /// A second handle on the same stream, so the relay loop can read on one
    /// thread and write on another.
    pub fn try_clone(&self) -> Self {
        Self {
            circuit: self.circuit.clone(),
            shared: Arc::clone(&self.shared),
        }
    }

    pub fn stream_id(&self) -> u16 {
        self.shared.id
    }

    /// Ask the far end for another increment once the application has drained
    /// enough of the buffer; this is what stops a slow reader from being sent
    /// more than it can hold.
    fn maybe_send_sendme(&self) -> io::Result<()> {
        loop {
            let mut buf = self.shared.buf.lock().unwrap();
            let backlog_low = buf.data.len() <= STREAM_WINDOW_INCREMENT as usize * RELAY_DATA_MAX;
            if buf.unacked < STREAM_WINDOW_INCREMENT || !backlog_low {
                return Ok(());
            }
            buf.unacked -= STREAM_WINDOW_INCREMENT;
            buf.deliver_window += STREAM_WINDOW_INCREMENT;
            drop(buf);
            self.circuit
                .send_relay(self.shared.hop, RELAY_SENDME, self.shared.id, &[], false)?;
        }
    }

    /// Tell the exit we are done with this stream.
    pub fn close(&self) {
        let _ = self.circuit.send_relay(
            self.shared.hop,
            RELAY_END,
            self.shared.id,
            &[END_REASON_DONE],
            false,
        );
        self.circuit.inner.streams.lock().unwrap().remove(&self.shared.id);
        let mut buf = self.shared.buf.lock().unwrap();
        if buf.ended.is_none() {
            buf.ended = Some(END_REASON_DONE);
        }
        drop(buf);
        self.shared.cond.notify_all();
    }
}

impl io::Read for TorStream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let n = {
            let mut buf = self.shared.buf.lock().unwrap();
            loop {
                if !buf.data.is_empty() {
                    let n = buf.data.len().min(out.len());
                    for (slot, byte) in out.iter_mut().zip(buf.data.drain(..n)) {
                        *slot = byte;
                    }
                    break n;
                }
                if let Some(err) = buf.error.clone() {
                    return Err(io::Error::other(err));
                }
                if let Some(reason) = buf.ended {
                    // A clean close reads as EOF; anything else is an error.
                    return match reason {
                        END_REASON_DONE | END_REASON_MISC => Ok(0),
                        other => Err(StreamEnd(other).into()),
                    };
                }
                let (guard, _) = self
                    .shared
                    .cond
                    .wait_timeout(buf, Duration::from_secs(1))
                    .unwrap();
                buf = guard;
                if self.circuit.is_closed() && buf.data.is_empty() {
                    return Err(circuit_closed());
                }
            }
        };
        self.maybe_send_sendme()?;
        Ok(n)
    }
}

impl io::Write for TorStream {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let chunk = &data[..data.len().min(RELAY_DATA_MAX)];

        let deadline = Instant::now() + SENDME_TIMEOUT;
        let mut buf = self.shared.buf.lock().unwrap();
        while buf.package_window <= 0 {
            if let Some(reason) = buf.ended {
                return Err(StreamEnd(reason).into());
            }
            if let Some(err) = buf.error.clone() {
                return Err(io::Error::other(err));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "stream send window stayed empty",
                ));
            }
            let (guard, _) = self
                .shared
                .cond
                .wait_timeout(buf, (deadline - now).min(Duration::from_secs(1)))
                .unwrap();
            buf = guard;
            if self.circuit.is_closed() {
                return Err(circuit_closed());
            }
        }
        if let Some(reason) = buf.ended {
            return Err(StreamEnd(reason).into());
        }
        buf.package_window -= 1;
        drop(buf);

        self.circuit
            .send_data(self.shared.hop, self.shared.id, chunk)?;
        Ok(chunk.len())
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

    /// The relay's view of one hop: the mirror image of ours.
    struct PeerHop {
        cipher_from_client: Aes128Ctr,
        digest_from_client: Digest,
    }

    impl PeerHop {
        fn new(k: &CircuitKeys) -> Self {
            let mut digest = Digest::sha1();
            digest.update(&k.df);
            Self {
                cipher_from_client: Aes128Ctr::new(&k.kf),
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
            assert_eq!(&body[1..3], &[0, 0], "recognized must be zero at the target");
            assert_eq!(u16::from_be_bytes([body[3], body[4]]), 7);
            assert_eq!(u16::from_be_bytes([body[9], body[10]]) as usize, payload.len());
            assert_eq!(&body[RELAY_HEADER_LEN..RELAY_HEADER_LEN + payload.len()], &payload[..]);

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
        let before: Vec<Vec<u8>> = client.hops.iter().map(|h| h.backward_digest.peek()).collect();
        let mut junk = vec![0u8; CELL_BODY_LEN];
        junk[1] = 0;
        junk[2] = 0;
        assert!(decrypt_inbound(&mut client, &mut junk).is_none());
        let after: Vec<Vec<u8>> = client.hops.iter().map(|h| h.backward_digest.peek()).collect();
        assert_eq!(before, after);
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
        assert!(build_relay_cell(&mut state, 1, 0, RELAY_DATA, 1, &[0; RELAY_DATA_MAX + 1], false).is_err());
        assert!(build_relay_cell(&mut state, 1, 5, RELAY_DATA, 1, &[0], false).is_err());
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
