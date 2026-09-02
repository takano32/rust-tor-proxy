//! A channel: one TLS connection to one relay, plus the link handshake and a
//! single I/O thread that multiplexes cells for every circuit on it.
//!
//! The link handshake (tor-spec/negotiating-channels.md) runs synchronously on
//! the still-blocking socket: VERSIONS both ways, then the responder's CERTS,
//! AUTH_CHALLENGE and NETINFO, then our NETINFO. We never authenticate
//! ourselves -- clients must not -- so AUTH_CHALLENGE is read and dropped.
//!
//! Afterwards the socket goes non-blocking and one thread owns the `SslStream`
//! for good, driven by `poll(2)` on the TLS socket and on a wake-up pipe that
//! senders poke after queueing a cell. That keeps the OpenSSL `SSL` object
//! confined to a single thread without forcing writers to wait on a read.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use super::cell::{self, Cell};
use super::certs::{self, CertsCell};
use crate::ffi::rand;
use crate::ffi::tls::SslStream;
use crate::ffi::{poll, PollFd, POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT};
use crate::util::invalid_data;

/// Link protocol versions we are willing to speak. v5 is left out on purpose:
/// it turns on padding negotiation, which we do not implement.
const SUPPORTED_VERSIONS: [u16; 2] = [3, 4];

/// How long a TCP connect plus TLS plus link handshake may take. Kept short
/// so that an unreachable relay is abandoned quickly and another can be tried.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Cap on bytes queued for the I/O thread before senders block. Circuit-level
/// flow control keeps the real figure far below this.
const MAX_OUTBOUND_BYTES: usize = 1 << 20;

/// Upper bound on how long the I/O thread sleeps without any event, so that a
/// `close()` is noticed promptly.
const POLL_INTERVAL_MS: i32 = 1000;

pub struct Channel {
    shared: Arc<Shared>,
}

struct Shared {
    peer: SocketAddrV4,
    /// `KP_relayid_ed`, proven by the CERTS cell.
    ed_identity: [u8; 32],
    link_version: u16,
    circ_id_len: usize,
    out: Mutex<Outbound>,
    out_space: Condvar,
    wake_tx: Mutex<UnixStream>,
    circuits: Mutex<HashMap<u32, Sender<Cell>>>,
    closed: AtomicBool,
}

struct Outbound {
    queue: VecDeque<u8>,
}

impl Channel {
    /// Open a channel to `peer` and prove it holds `expected_ed_identity`.
    pub fn connect(
        peer: SocketAddrV4,
        expected_ed_identity: Option<&[u8; 32]>,
    ) -> io::Result<Self> {
        let sock = TcpStream::connect_timeout(&SocketAddr::V4(peer), HANDSHAKE_TIMEOUT)?;
        let mut tls = SslStream::connect(sock, HANDSHAKE_TIMEOUT)?;
        let tls_cert_sha256 = *tls.peer_cert_sha256();

        let link_version = negotiate_versions(&mut tls)?;
        let circ_id_len = if link_version >= 4 {
            cell::CIRC_ID_LEN_V4
        } else {
            cell::CIRC_ID_LEN_V2
        };
        debug!("{peer}: link protocol v{link_version}");

        let ed_identity = read_responder_handshake(&mut tls, circ_id_len, &tls_cert_sha256)?;
        if let Some(expected) = expected_ed_identity {
            if !crate::ffi::constant_time_eq(&ed_identity, expected) {
                return Err(invalid_data(format!(
                    "{peer}: relay identity is {}, expected {}",
                    crate::util::hex_encode(&ed_identity),
                    crate::util::hex_encode(expected)
                )));
            }
        }
        send_netinfo(&mut tls, circ_id_len, peer.ip())?;

        tls.set_nonblocking()?;
        let (wake_tx, wake_rx) = UnixStream::pair()?;
        wake_tx.set_nonblocking(true)?;
        wake_rx.set_nonblocking(true)?;

        let shared = Arc::new(Shared {
            peer,
            ed_identity,
            link_version,
            circ_id_len,
            out: Mutex::new(Outbound {
                queue: VecDeque::new(),
            }),
            out_space: Condvar::new(),
            wake_tx: Mutex::new(wake_tx),
            circuits: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
        });

        let io_shared = Arc::clone(&shared);
        std::thread::Builder::new()
            .name(format!("chan-{peer}"))
            .spawn(move || io_loop(tls, wake_rx, io_shared))?;

        Ok(Self { shared })
    }

    pub fn peer(&self) -> SocketAddrV4 {
        self.shared.peer
    }

    pub fn ed_identity(&self) -> &[u8; 32] {
        &self.shared.ed_identity
    }

    pub fn link_version(&self) -> u16 {
        self.shared.link_version
    }

    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::Acquire)
    }

    /// Claim an unused circuit ID and a queue for cells addressed to it.
    ///
    /// The side that opened the connection must pick IDs with the high bit
    /// set (tor-spec/create-created-cells.md), and zero is never valid.
    pub fn register_circuit(&self) -> io::Result<(u32, Receiver<Cell>)> {
        let (msb, mask) = if self.shared.circ_id_len == cell::CIRC_ID_LEN_V4 {
            (0x8000_0000u32, 0xffff_ffffu32)
        } else {
            (0x8000u32, 0xffffu32)
        };
        let (tx, rx) = mpsc::channel();
        let mut circuits = self.shared.circuits.lock().unwrap();
        for _ in 0..64 {
            let id = (rand::u32_value()? & mask) | msb;
            if id == 0 || circuits.contains_key(&id) {
                continue;
            }
            circuits.insert(id, tx);
            return Ok((id, rx));
        }
        Err(io::Error::other("could not find a free circuit ID"))
    }

    pub fn unregister_circuit(&self, circ_id: u32) {
        self.shared.circuits.lock().unwrap().remove(&circ_id);
    }

    pub fn send_cell(&self, cell: &Cell) -> io::Result<()> {
        let bytes = cell.encode(self.shared.circ_id_len);
        let mut out = self.shared.out.lock().unwrap();
        while out.queue.len() + bytes.len() > MAX_OUTBOUND_BYTES {
            if self.is_closed() {
                return Err(closed_error(self.shared.peer));
            }
            let (guard, timeout) = self
                .shared
                .out_space
                .wait_timeout(out, Duration::from_millis(200))
                .unwrap();
            out = guard;
            let _ = timeout;
        }
        if self.is_closed() {
            return Err(closed_error(self.shared.peer));
        }
        out.queue.extend(bytes);
        drop(out);
        self.wake();
        Ok(())
    }

    pub fn close(&self) {
        self.shared.closed.store(true, Ordering::Release);
        self.shared.out_space.notify_all();
        self.wake();
    }

    fn wake(&self) {
        let mut tx = self.shared.wake_tx.lock().unwrap();
        // A full pipe already means "there is work to do".
        let _ = tx.write(&[1u8]);
    }
}

impl Clone for Channel {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

fn closed_error(peer: SocketAddrV4) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        format!("channel to {peer} is closed"),
    )
}

/// Exchange VERSIONS cells and return the highest version both sides offer.
fn negotiate_versions(tls: &mut SslStream) -> io::Result<u16> {
    let mut body = Vec::with_capacity(SUPPORTED_VERSIONS.len() * 2);
    for v in SUPPORTED_VERSIONS {
        body.extend_from_slice(&v.to_be_bytes());
    }
    // VERSIONS is always sent with a two-byte CircID: no version is agreed yet.
    let versions = Cell::new(0, cell::CMD_VERSIONS, body)?;
    tls.write_all(&versions.encode(cell::CIRC_ID_LEN_V2))?;
    tls.flush()?;

    let reply = Cell::read_from(tls, cell::CIRC_ID_LEN_V2)?;
    if reply.command != cell::CMD_VERSIONS {
        return Err(invalid_data(format!(
            "expected VERSIONS, got {}",
            cell::command_name(reply.command)
        )));
    }
    if reply.body.len() % 2 != 0 {
        return Err(invalid_data("VERSIONS cell has an odd body length"));
    }
    let best = reply
        .body
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|v| SUPPORTED_VERSIONS.contains(v))
        .max()
        .ok_or_else(|| invalid_data("no link protocol version in common"))?;
    Ok(best)
}

/// Read CERTS / AUTH_CHALLENGE / NETINFO and authenticate the relay.
fn read_responder_handshake(
    tls: &mut SslStream,
    circ_id_len: usize,
    tls_cert_sha256: &[u8; 32],
) -> io::Result<[u8; 32]> {
    let mut identity: Option<[u8; 32]> = None;
    // The responder ends its side of the handshake with NETINFO.
    for _ in 0..16 {
        let cell = Cell::read_from(tls, circ_id_len)?;
        match cell.command {
            cell::CMD_CERTS => {
                let certs = CertsCell::parse(&cell.body)?;
                identity = Some(certs::validate_responder(
                    &certs,
                    tls_cert_sha256,
                    certs::now_unix(),
                )?);
            }
            // Clients never authenticate, so the challenge is of no use to us.
            cell::CMD_AUTH_CHALLENGE => {}
            cell::CMD_VPADDING | cell::CMD_PADDING => {}
            cell::CMD_NETINFO => {
                return identity.ok_or_else(|| {
                    invalid_data("responder sent NETINFO without a valid CERTS cell")
                });
            }
            other => {
                return Err(invalid_data(format!(
                    "unexpected {} cell during link handshake",
                    cell::command_name(other)
                )));
            }
        }
    }
    Err(invalid_data("link handshake did not finish"))
}

/// Our NETINFO: timestamp zero and no addresses of our own, as the spec asks
/// of clients, with the relay's own address echoed back.
fn send_netinfo(tls: &mut SslStream, circ_id_len: usize, peer_ip: &Ipv4Addr) -> io::Result<()> {
    let mut body = Vec::with_capacity(11);
    body.extend_from_slice(&0u32.to_be_bytes());
    body.push(0x04);
    body.push(4);
    body.extend_from_slice(&peer_ip.octets());
    body.push(0);
    let netinfo = Cell::new(0, cell::CMD_NETINFO, body)?;
    tls.write_all(&netinfo.encode(circ_id_len))?;
    tls.flush()
}

fn io_loop(mut tls: SslStream, mut wake_rx: UnixStream, shared: Arc<Shared>) {
    let result = run_io(&mut tls, &mut wake_rx, &shared);
    match result {
        Ok(()) => debug!("{}: channel closed", shared.peer),
        Err(e) => debug!("{}: channel ended: {e}", shared.peer),
    }
    shared.closed.store(true, Ordering::Release);
    // Dropping every circuit's sender makes each circuit's receive loop stop.
    shared.circuits.lock().unwrap().clear();
    shared.out_space.notify_all();
    tls.shutdown();
}

fn run_io(tls: &mut SslStream, wake_rx: &mut UnixStream, shared: &Arc<Shared>) -> io::Result<()> {
    let tls_fd = tls.as_raw_fd();
    let wake_fd = wake_rx.as_raw_fd();
    let mut inbound: Vec<u8> = Vec::with_capacity(8192);
    let mut pending: VecDeque<u8> = VecDeque::new();
    let mut read_buf = [0u8; 8192];
    let mut drain_buf = [0u8; 256];

    loop {
        if shared.closed.load(Ordering::Acquire) {
            return Ok(());
        }

        if pending.is_empty() {
            let mut out = shared.out.lock().unwrap();
            if !out.queue.is_empty() {
                std::mem::swap(&mut pending, &mut out.queue);
                shared.out_space.notify_all();
            }
        }

        while !pending.is_empty() {
            // `pending` is a VecDeque, so write whichever contiguous run comes
            // first and let the next iteration pick up the wrapped remainder.
            let (front, _) = pending.as_slices();
            match tls.write(front) {
                Ok(0) => return Err(io::Error::other("TLS write made no progress")),
                Ok(n) => {
                    pending.drain(..n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        loop {
            match tls.read(&mut read_buf) {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    inbound.extend_from_slice(&read_buf[..n]);
                    dispatch_cells(&mut inbound, shared)?;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        // A read can also ask to wait for writability, during a TLS key
        // update; asking for POLLOUT then keeps that from stalling.
        let want_write = !pending.is_empty() || tls.wants_write();
        let mut fds = [
            PollFd {
                fd: tls_fd,
                events: POLLIN | if want_write { POLLOUT } else { 0 },
                revents: 0,
            },
            PollFd {
                fd: wake_fd,
                events: POLLIN,
                revents: 0,
            },
        ];
        let rc = unsafe { poll(fds.as_mut_ptr(), fds.len() as _, POLL_INTERVAL_MS) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
        if fds[0].revents & (POLLERR | POLLHUP | POLLNVAL) != 0 && fds[0].revents & POLLIN == 0 {
            return Ok(());
        }
        if fds[1].revents & POLLIN != 0 {
            // Drain the wake-up bytes; their number carries no meaning.
            while let Ok(n) = wake_rx.read(&mut drain_buf) {
                if n < drain_buf.len() {
                    break;
                }
            }
        }
    }
}

fn dispatch_cells(inbound: &mut Vec<u8>, shared: &Arc<Shared>) -> io::Result<()> {
    let mut consumed = 0usize;
    while let Some((cell, used)) = Cell::try_parse(&inbound[consumed..], shared.circ_id_len)? {
        consumed += used;
        deliver(cell, shared);
    }
    if consumed > 0 {
        inbound.drain(..consumed);
    }
    Ok(())
}

fn deliver(cell: Cell, shared: &Arc<Shared>) {
    if cell.circ_id == 0 {
        // Link padding and anything else not tied to a circuit.
        trace!(
            "{}: dropping {} cell with CircID 0",
            shared.peer,
            cell::command_name(cell.command)
        );
        return;
    }
    let mut circuits = shared.circuits.lock().unwrap();
    match circuits.get(&cell.circ_id) {
        Some(tx) => {
            if tx.send(cell.clone()).is_err() {
                circuits.remove(&cell.circ_id);
            }
        }
        None => {
            warn!(
                "{}: {} cell for unknown circuit {}",
                shared.peer,
                cell::command_name(cell.command),
                cell.circ_id
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tor::dir::fallback::FALLBACK_DIRS;

    /// Live check against the real network: open a channel to a fallback
    /// directory mirror and authenticate it from its CERTS cell.
    ///
    /// Run with `cargo test -- --ignored --nocapture`.
    #[test]
    #[ignore = "requires network access to the Tor network"]
    fn connects_to_a_fallback_relay() {
        crate::log::init();
        let mut last_error = None;
        let mut tried = 0;
        for index in random_order(FALLBACK_DIRS.len()) {
            let fb = &FALLBACK_DIRS[index];
            let addr = SocketAddrV4::new(Ipv4Addr::from(fb.ipv4), fb.or_port);
            tried += 1;
            match Channel::connect(addr, None) {
                Ok(chan) => {
                    println!(
                        "connected to {addr} (link v{}) ed25519 identity {}",
                        chan.link_version(),
                        crate::util::hex_encode(chan.ed_identity())
                    );
                    assert_ne!(chan.ed_identity(), &[0u8; 32]);
                    chan.close();
                    return;
                }
                Err(e) => {
                    println!("{addr}: {e}");
                    last_error = Some(e);
                }
            }
            if tried >= 8 {
                break;
            }
        }
        panic!("no fallback relay accepted a channel: {last_error:?}");
    }

    fn random_order(len: usize) -> Vec<usize> {
        let mut order: Vec<usize> = (0..len).collect();
        for i in (1..len).rev() {
            let j = rand::below(i as u64 + 1).unwrap() as usize;
            order.swap(i, j);
        }
        order
    }
}
