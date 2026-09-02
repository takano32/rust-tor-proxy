//! The client: guards, a small circuit pool, and `connect(host, port)`.
//!
//! Directory documents after the first bootstrap are fetched through the
//! guard, over a one-hop CREATE_FAST circuit -- the "directory guard" pattern.
//! That keeps the set of relays that learn about this client small and stable,
//! which is the same reason the guard itself is pinned.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::channel::Channel;
use super::circuit::{Circuit, TorStream};
use super::dir::cache::Cache;
use super::dir::consensus::RouterStatus;
use super::dir::microdesc::Microdesc;
use super::dir::{DirCircuit, Directory};
use super::path::{self, PathConstraints};
use super::RelayInfo;
use crate::util::{hex_decode, hex_encode, invalid_data};

/// Retire a circuit this long after it was built.
const MAX_CIRCUIT_AGE: Duration = Duration::from_secs(600);
/// Never keep more than this many circuits alive at once.
const MAX_CIRCUITS: usize = 8;
/// How many exit candidates to look at before filtering by port policy.
const EXIT_SAMPLE: usize = 40;
/// How many middle candidates to fetch microdescriptors for.
const MIDDLE_SAMPLE: usize = 8;
/// Cap on the in-memory microdescriptor cache.
const MAX_CACHED_MICRODESCS: usize = 2000;
/// How many times to rebuild a circuit before giving up on a request.
const CONNECT_ATTEMPTS: usize = 3;
/// How many guards to try before giving up on reaching the network. The
/// consensus says a relay is Running, but that is a global judgement: it can
/// still be unreachable from here.
const GUARD_ATTEMPTS: usize = 5;

const GUARD_FILE: &str = "guard";

pub struct TorClient {
    directory: Directory,
    state_dir: PathBuf,
    guard: Mutex<Option<GuardState>>,
    /// Guards that would not accept a connection, so we stop choosing them.
    failed_guards: Mutex<Vec<[u8; 20]>>,
    circuits: Mutex<Vec<PooledCircuit>>,
    microdescs: Mutex<HashMap<[u8; 32], Arc<Microdesc>>>,
}

struct GuardState {
    relay: RelayInfo,
    identity: [u8; 20],
    channel: Option<Channel>,
}

struct PooledCircuit {
    circuit: Circuit,
    exit_policy: Arc<Microdesc>,
    built: Instant,
}

impl TorClient {
    /// Bootstrap: get a verified consensus, then pick and pin a guard.
    pub fn bootstrap(state_dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&state_dir)?;
        let directory = Directory::bootstrap(Cache::new(&state_dir))?;
        let client = Self {
            directory,
            state_dir,
            guard: Mutex::new(None),
            failed_guards: Mutex::new(Vec::new()),
            circuits: Mutex::new(Vec::new()),
            microdescs: Mutex::new(HashMap::new()),
        };
        // Open the guard channel now: an unreachable guard should be replaced
        // during startup, not on the first request.
        let (channel, _) = client.guard_channel()?;
        crate::info!(
            "guard {} (link v{})",
            channel.peer(),
            channel.link_version()
        );
        Ok(client)
    }

    /// Open a stream to `host:port` through a three-hop circuit.
    pub fn connect(&self, host: &str, port: u16) -> io::Result<TorStream> {
        let mut last: Option<io::Error> = None;
        for attempt in 0..CONNECT_ATTEMPTS {
            let circuit = match self.circuit_for(port) {
                Ok(circuit) => circuit,
                Err(e) => {
                    crate::debug!("attempt {}: no circuit: {e}", attempt + 1);
                    last = Some(e);
                    continue;
                }
            };
            match circuit.begin_stream(host, port) {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    crate::debug!("attempt {}: BEGIN failed: {e}", attempt + 1);
                    // An exit policy rejection is about this exit, not the
                    // host, so drop the circuit and pick a different one.
                    self.discard(&circuit);
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("could not open a stream")))
    }

    /// A live circuit whose exit accepts `port`, reusing one if possible.
    fn circuit_for(&self, port: u16) -> io::Result<Circuit> {
        {
            let mut pool = self.circuits.lock().unwrap();
            pool.retain(|c| !c.circuit.is_closed() && c.built.elapsed() < MAX_CIRCUIT_AGE);
            if let Some(found) = pool.iter().find(|c| c.exit_policy.exit_policy.allows(port)) {
                return Ok(found.circuit.clone());
            }
        }

        let (circuit, exit_md) = self.build_circuit(port)?;
        let mut pool = self.circuits.lock().unwrap();
        pool.retain(|c| !c.circuit.is_closed() && c.built.elapsed() < MAX_CIRCUIT_AGE);
        while pool.len() >= MAX_CIRCUITS {
            let oldest = pool.remove(0);
            oldest.circuit.close();
        }
        pool.push(PooledCircuit {
            circuit: circuit.clone(),
            exit_policy: exit_md,
            built: Instant::now(),
        });
        Ok(circuit)
    }

    fn discard(&self, circuit: &Circuit) {
        let mut pool = self.circuits.lock().unwrap();
        pool.retain(|c| c.circuit.circ_id() != circuit.circ_id());
        circuit.close();
    }

    fn build_circuit(&self, port: u16) -> io::Result<(Circuit, Arc<Microdesc>)> {
        // Take the channel first: it decides which guard the path starts at.
        let (channel, guard) = self.guard_channel()?;
        let guard_identity = guard.rsa_identity;

        let mut constraints = PathConstraints::default();
        let guard_md = self.cached_microdesc(&guard_identity);
        if let Some(status) = self.router(&guard_identity) {
            constraints.add(&status, guard_md.as_deref());
        }

        // Sample exit and middle candidates together so their microdescriptors
        // come back in one directory request.
        let consensus = &self.directory.consensus;
        let exit_pool = path::exit_candidates(consensus, &constraints);
        let exits = path::sample(&exit_pool, EXIT_SAMPLE)?;
        let middle_pool = path::middle_candidates(consensus, &constraints);
        let middles = path::sample(&middle_pool, MIDDLE_SAMPLE)?;

        let mut wanted: Vec<[u8; 32]> = Vec::with_capacity(exits.len() + middles.len());
        wanted.extend(exits.iter().map(|r| r.microdesc_digest));
        wanted.extend(middles.iter().map(|r| r.microdesc_digest));
        let fetched = self.load_microdescs(&wanted)?;

        // Pick the exit first: its policy is the binding constraint.
        let allowing: Vec<&RouterStatus> = exits
            .iter()
            .copied()
            .filter(|r| {
                fetched
                    .get(&r.microdesc_digest)
                    .is_some_and(|md| !md.exit_policy.is_empty() && md.exit_policy.allows(port))
            })
            .collect();
        if allowing.is_empty() {
            return Err(invalid_data(format!(
                "none of {} sampled exits allows port {port}",
                exits.len()
            )));
        }
        let exit = path::weighted_choice(&allowing)?;
        let exit_md = fetched
            .get(&exit.microdesc_digest)
            .cloned()
            .ok_or_else(|| invalid_data("exit microdescriptor vanished"))?;
        constraints.add(exit, Some(&exit_md));

        let middle_choices: Vec<&RouterStatus> = middles
            .iter()
            .copied()
            .filter(|r| {
                fetched
                    .get(&r.microdesc_digest)
                    .is_some_and(|md| constraints.accepts(r, Some(md)))
            })
            .collect();
        let middle = path::weighted_choice(&middle_choices)?;
        let middle_md = fetched
            .get(&middle.microdesc_digest)
            .cloned()
            .ok_or_else(|| invalid_data("middle microdescriptor vanished"))?;

        let circuit = Circuit::create(&channel, &guard)?;
        let build = (|| {
            circuit.extend(&relay_info(middle, &middle_md))?;
            circuit.extend(&relay_info(exit, &exit_md))
        })();
        if let Err(e) = build {
            circuit.close();
            return Err(e);
        }
        crate::debug!(
            "circuit {} built with {} hops: {} -> {} -> {}",
            circuit.circ_id(),
            circuit.hop_count(),
            guard.addr,
            Ipv4Addr::from(middle.ipv4),
            Ipv4Addr::from(exit.ipv4)
        );
        Ok((circuit, exit_md))
    }

    /// The microdescriptor for a relay we have already fetched one for.
    fn cached_microdesc(&self, identity: &[u8; 20]) -> Option<Arc<Microdesc>> {
        let status = self.router(identity)?;
        self.microdescs
            .lock()
            .unwrap()
            .get(&status.microdesc_digest)
            .cloned()
    }

    fn router(&self, identity: &[u8; 20]) -> Option<RouterStatus> {
        self.directory
            .consensus
            .routers
            .iter()
            .find(|r| &r.identity == identity)
            .cloned()
    }

    /// The pinned guard, loading it from disk or choosing a new one.
    fn ensure_guard(&self) -> io::Result<RelayInfo> {
        {
            let guard = self.guard.lock().unwrap();
            if let Some(state) = guard.as_ref() {
                return Ok(state.relay.clone());
            }
        }

        let status = self.choose_guard()?;
        // The guard's microdescriptor is fetched over a fallback directory
        // circuit: we have no guard channel to fetch it through yet.
        let relay = self.resolve_relay(&status)?;
        self.save_guard(&status.identity);
        let mut guard = self.guard.lock().unwrap();
        if let Some(existing) = guard.as_ref() {
            return Ok(existing.relay.clone());
        }
        *guard = Some(GuardState {
            relay: relay.clone(),
            identity: status.identity,
            channel: None,
        });
        Ok(relay)
    }

    /// Prefer the guard saved on disk; otherwise draw a new one. Guards that
    /// have already failed this run are never chosen.
    fn choose_guard(&self) -> io::Result<RouterStatus> {
        let failed = self.failed_guards.lock().unwrap().clone();
        let saved = self
            .load_saved_guard()
            .filter(|id| !failed.contains(id))
            .and_then(|id| self.router(&id))
            .filter(|r| r.has(path::GUARD_FLAGS));
        if let Some(status) = saved {
            return Ok(status);
        }
        let candidates: Vec<&RouterStatus> = path::guard_candidates(&self.directory.consensus)
            .into_iter()
            .filter(|r| !failed.contains(&r.identity))
            .collect();
        path::weighted_choice(&candidates).cloned()
    }

    /// Give up on the current guard and forget the saved choice.
    fn forget_guard(&self, identity: &[u8; 20]) {
        let mut guard = self.guard.lock().unwrap();
        if guard
            .as_ref()
            .is_some_and(|state| &state.identity == identity)
        {
            if let Some(channel) = guard.as_ref().and_then(|s| s.channel.as_ref()) {
                channel.close();
            }
            *guard = None;
        }
        drop(guard);
        let mut failed = self.failed_guards.lock().unwrap();
        if !failed.contains(identity) {
            failed.push(*identity);
        }
        let _ = fs::remove_file(self.state_dir.join(GUARD_FILE));
    }

    /// Turn a consensus entry into everything needed for a handshake.
    fn resolve_relay(&self, status: &RouterStatus) -> io::Result<RelayInfo> {
        let mds = self.load_microdescs(&[status.microdesc_digest])?;
        let md = mds
            .get(&status.microdesc_digest)
            .ok_or_else(|| invalid_data("could not fetch the relay's microdescriptor"))?;
        Ok(relay_info(status, md))
    }

    fn load_saved_guard(&self) -> Option<[u8; 20]> {
        let text = fs::read_to_string(self.state_dir.join(GUARD_FILE)).ok()?;
        hex_decode(text.trim()).ok()?.try_into().ok()
    }

    fn save_guard(&self, identity: &[u8; 20]) {
        let path = self.state_dir.join(GUARD_FILE);
        if let Err(e) = fs::write(&path, hex_encode(identity)) {
            crate::warn!("could not persist the guard choice: {e}");
        }
    }

    /// An open channel to the guard together with the guard it belongs to,
    /// reconnecting or re-choosing as needed.
    ///
    /// The two are returned together on purpose: a circuit built on this
    /// channel must run ntor against *this* guard's keys, and failover can
    /// change which guard that is.
    fn guard_channel(&self) -> io::Result<(Channel, RelayInfo)> {
        let mut last: Option<io::Error> = None;
        for _ in 0..GUARD_ATTEMPTS {
            if let Some(open) = self.open_guard_channel() {
                return Ok(open);
            }
            let relay = self.ensure_guard()?;
            let identity = relay.rsa_identity;
            match Channel::connect(relay.addr, relay.ed_identity.as_ref()) {
                Ok(channel) => {
                    crate::debug!(
                        "guard channel to {} up: link v{}, identity {}",
                        relay.addr,
                        channel.link_version(),
                        hex_encode(&channel.ed_identity()[..8])
                    );
                    return Ok(self.store_guard_channel(channel, relay));
                }
                Err(e) => {
                    // The consensus called it Running, but we cannot reach it.
                    crate::warn!("guard {} unusable ({e}); choosing another", relay.addr);
                    self.forget_guard(&identity);
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("no guard would accept a connection")))
    }

    fn open_guard_channel(&self) -> Option<(Channel, RelayInfo)> {
        let guard = self.guard.lock().unwrap();
        let state = guard.as_ref()?;
        let channel = state.channel.clone()?;
        if channel.is_closed() {
            return None;
        }
        Some((channel, state.relay.clone()))
    }

    /// Publish a freshly opened channel, deferring to one another thread may
    /// have stored first.
    fn store_guard_channel(&self, channel: Channel, relay: RelayInfo) -> (Channel, RelayInfo) {
        let mut guard = self.guard.lock().unwrap();
        if let Some(state) = guard.as_mut() {
            match state.channel.as_ref() {
                Some(existing) if !existing.is_closed() => {
                    let open = (existing.clone(), state.relay.clone());
                    drop(guard);
                    channel.close();
                    return open;
                }
                _ => state.channel = Some(channel.clone()),
            }
        }
        (channel, relay)
    }

    /// Microdescriptors for these digests, from memory, disk, or the network.
    fn load_microdescs(
        &self,
        digests: &[[u8; 32]],
    ) -> io::Result<HashMap<[u8; 32], Arc<Microdesc>>> {
        let mut result: HashMap<[u8; 32], Arc<Microdesc>> = HashMap::new();
        let mut missing: Vec<[u8; 32]> = Vec::new();
        {
            let cached = self.microdescs.lock().unwrap();
            for digest in digests {
                match cached.get(digest) {
                    Some(md) => {
                        result.insert(*digest, Arc::clone(md));
                    }
                    None => missing.push(*digest),
                }
            }
        }
        if missing.is_empty() {
            return Ok(result);
        }

        let dir_circuit = self.dir_circuit()?;
        let fetched = self.directory.microdescs(&missing, &dir_circuit);
        dir_circuit.close();
        let fetched = fetched?;

        let mut cached = self.microdescs.lock().unwrap();
        if cached.len() + fetched.len() > MAX_CACHED_MICRODESCS {
            // The disk cache still has them; this only bounds resident memory.
            cached.clear();
        }
        for (digest, md) in fetched {
            let md = Arc::new(md);
            cached.insert(digest, Arc::clone(&md));
            result.insert(digest, md);
        }
        Ok(result)
    }

    /// A one-hop directory circuit, on the guard channel when one is already
    /// open, so a directory fetch costs no extra connection.
    fn dir_circuit(&self) -> io::Result<DirCircuit> {
        if let Some((channel, _)) = self.open_guard_channel() {
            let peer = channel.peer();
            match DirCircuit::on(channel) {
                Ok(dir_circuit) => return Ok(dir_circuit),
                Err(e) => crate::debug!("guard {peer} refused a directory circuit: {e}"),
            }
        }
        DirCircuit::to_random_fallback()
    }

    pub fn consensus_summary(&self) -> String {
        self.directory.summary()
    }
}

fn relay_info(status: &RouterStatus, md: &Microdesc) -> RelayInfo {
    RelayInfo {
        addr: SocketAddrV4::new(Ipv4Addr::from(status.ipv4), status.or_port),
        rsa_identity: status.identity,
        ed_identity: md.ed_identity,
        ntor_onion_key: md.ntor_onion_key,
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use std::io::{Read, Write};

    /// Live check: bootstrap, pin a guard, build a three-hop circuit and pull
    /// a page through it.
    ///
    /// Run with `cargo test -- --ignored --nocapture`.
    #[test]
    #[ignore = "requires network access to the Tor network"]
    fn three_hop_circuit_carries_http() {
        crate::log::init();
        let dir = std::env::temp_dir().join(format!("tor-client-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let client = TorClient::bootstrap(dir.clone()).expect("bootstrap");
        println!("consensus: {}", client.consensus_summary());

        let mut stream = client.connect("check.torproject.org", 80).expect("connect");
        stream
            .write_all(
                b"GET /api/ip HTTP/1.0\r\nHost: check.torproject.org\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        stream.flush().unwrap();

        let mut response = Vec::new();
        let mut chunk = [0u8; 2048];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&chunk[..n]),
                Err(e) => panic!("read failed: {e}"),
            }
        }
        let text = String::from_utf8_lossy(&response);
        println!("--- response ---\n{}", &text[..text.len().min(400)]);
        assert!(text.starts_with("HTTP/1."), "not an HTTP response");

        // The pooled circuit must be reused for a second request on the same
        // port rather than being rebuilt.
        let before = client.circuits.lock().unwrap().len();
        assert_eq!(before, 1);
        let second = client
            .connect("check.torproject.org", 80)
            .expect("second connect");
        assert_eq!(client.circuits.lock().unwrap().len(), 1);
        second.close();

        // The guard is pinned on disk, so a restart keeps the same one.
        let saved = fs::read_to_string(dir.join(GUARD_FILE)).unwrap();
        assert_eq!(saved.len(), 40, "guard file should hold a hex fingerprint");

        let _ = fs::remove_dir_all(&dir);
    }
}
