//! The client: guards, a small circuit pool, and `connect(host, port)`.
//!
//! Directory documents after the first bootstrap are fetched through the
//! guard, over a one-hop CREATE_FAST circuit -- the "directory guard" pattern.
//! That keeps the set of relays that learn about this client small and stable,
//! which is the same reason the guard itself is pinned.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use super::certs::now_unix;
use super::channel::Channel;
use super::circuit::{self, Circuit, TorStream};
use super::dir::cache::Cache;
use super::dir::consensus::{RouterStatus, FLAG_HSDIR};
use super::dir::microdesc::Microdesc;
use super::dir::{fallback, DirCircuit, Directory};
use super::hs::address::OnionAddress;
use super::hs::blind::TimePeriod;
use super::hs::descriptor::{self, Descriptor};
use super::hs::hsdir::{self, RingNode};
use super::hs::rendezvous;
use super::path::{self, PathConstraints};
use super::pool::{self, Pool, Stub, MAX_CIRCUITS};
use super::RelayInfo;
use crate::ffi::rand;
use crate::util::{base64_encode_unpadded, hex_decode, hex_encode, invalid_data};

/// Retire a rendezvous circuit this long after it was built.
const MAX_CIRCUIT_AGE: Duration = Duration::from_secs(600);
/// How many exit candidates to look at before filtering by port policy.
const EXIT_SAMPLE: usize = 40;
/// How many middle candidates to fetch microdescriptors for.
const MIDDLE_SAMPLE: usize = 8;
/// How many rendezvous point candidates to fetch microdescriptors for.
const RENDEZVOUS_SAMPLE: usize = 8;
/// Cap on the in-memory microdescriptor cache.
const MAX_CACHED_MICRODESCS: usize = 2000;
/// How many times to rebuild a circuit before giving up on a request.
const CONNECT_ATTEMPTS: usize = 3;
/// How many guards to try before giving up on reaching the network. The
/// consensus says a relay is Running, but that is a global judgement: it can
/// still be unreachable from here.
const GUARD_ATTEMPTS: usize = 5;

/// How many of the responsible directory nodes to ask for a descriptor before
/// giving up -- unless every one of them answered "not here", in which case
/// the rest are worth trying too (rend-spec's time-period boundary case).
const HSDIR_TRIES: usize = 3;

/// Where the chosen guards are remembered between runs, newest choice last.
const GUARDS_FILE: &str = "guards";
/// The single-guard file written by earlier versions, read once and replaced.
const LEGACY_GUARD_FILE: &str = "guard";
/// How many guards to keep on the list. Pinning one relay is what guards are
/// for; a short ordered list only says which to fall back to while the first
/// is unreachable, and the first is resumed as soon as it answers again.
const MAX_GUARDS: usize = 3;
/// How long a guard that refused a connection is left alone before it is
/// tried again.
pub const GUARD_RETRY_INTERVAL: Duration = Duration::from_secs(600);
/// How long to wait for the TCP handshake when checking whether it is the
/// network that is down rather than the guard.
const REACHABILITY_TIMEOUT: Duration = Duration::from_secs(5);
/// How many fallback mirrors that check tries before concluding we are cut
/// off. Two, because one of them may simply be down.
const REACHABILITY_PROBES: usize = 2;

pub struct TorClient {
    /// Swapped wholesale when the maintenance thread verifies a newer
    /// consensus. Readers take a clone of the `Arc` and let go of the lock at
    /// once, so a refresh never waits on a circuit being built.
    directory: RwLock<Arc<Directory>>,
    state_dir: PathBuf,
    guards: Mutex<Guards>,
    /// Circuits built ahead of time and the ones currently carrying streams.
    pool: Pool,
    microdescs: Mutex<HashMap<[u8; 32], Arc<Microdesc>>>,
    /// Built the first time a `.onion` address is asked for, because it costs
    /// thousands of microdescriptors that a client with no onion traffic
    /// never needs.
    hsdir_ring: Mutex<Option<Arc<HsdirRing>>>,
    /// Held while the ring is being built, so that two `.onion` requests
    /// arriving together do not both pay for it.
    hsdir_build: Mutex<()>,
    /// Set once a `.onion` request has needed the ring. Only then is it worth
    /// the maintenance thread rebuilding it after a consensus change; a client
    /// that never touches onion services should never pay for one.
    hsdir_wanted: AtomicBool,
    /// Onion service descriptors, in memory only: they name the service's
    /// introduction points, which is not something to leave on disk.
    descriptors: Mutex<HashMap<[u8; 32], CachedDescriptor>>,
    /// One rendezvous circuit per onion service, carrying every stream to it.
    onion_circuits: Mutex<HashMap<[u8; 32], PooledOnionCircuit>>,
}

struct PooledOnionCircuit {
    circuit: Circuit,
    built: Instant,
}

struct CachedDescriptor {
    descriptor: Arc<Descriptor>,
    /// The time period it was fetched for; a new period means a new blinded
    /// key, so the old descriptor is not merely stale but unrelated.
    period: u64,
    expires_at: Instant,
}

/// The HSDir hash ring for one time period, and the period itself: the two
/// always travel together, and both are fixed by the consensus.
pub struct HsdirRing {
    pub period: TimePeriod,
    /// The consensus this was built from, so a newer one invalidates it.
    valid_after: u64,
    nodes: Vec<RingNode>,
    n_replicas: u8,
    spread_fetch: usize,
}

/// The guard list and the one channel currently open to a guard.
struct Guards {
    /// In priority order: the first entry is the primary, and the client goes
    /// back to it as soon as it will talk to us again.
    entries: Vec<GuardEntry>,
    open: Option<OpenGuard>,
}

struct GuardEntry {
    identity: [u8; 20],
    /// Where it was last reached, remembered across restarts so that the very
    /// first thing a new process does can be to reconnect to its guard --
    /// before it has a consensus to look the address up in.
    contact: Option<GuardContact>,
    /// When it last refused a connection that we are confident was its fault
    /// rather than ours. `None` means it is believed good.
    failed_at: Option<Instant>,
}

#[derive(Clone, Copy)]
struct GuardContact {
    addr: SocketAddrV4,
    /// `KP_relayid_ed`, so the channel can be authenticated straight away.
    ed_identity: [u8; 32],
}

struct OpenGuard {
    identity: [u8; 20],
    /// Filled in once the consensus and the guard's microdescriptor are to
    /// hand: a channel needs only an address, but CREATE2 needs the onion key.
    relay: Option<RelayInfo>,
    channel: Channel,
}

impl GuardEntry {
    /// Open a channel from the remembered address alone.
    fn reconnect(&self) -> Option<OpenGuard> {
        let contact = self.contact?;
        match Channel::connect(contact.addr, Some(&contact.ed_identity)) {
            Ok(channel) => Some(OpenGuard {
                identity: self.identity,
                relay: None,
                channel,
            }),
            Err(e) => {
                crate::debug!("saved guard {} did not answer: {e}", contact.addr);
                None
            }
        }
    }
}

impl Guards {
    /// The first entry worth trying: unfailed ones in order, then any whose
    /// cool-off has elapsed.
    fn next_candidate(&self) -> Option<[u8; 20]> {
        if let Some(entry) = self.entries.iter().find(|e| e.failed_at.is_none()) {
            return Some(entry.identity);
        }
        self.entries
            .iter()
            .find(|e| {
                e.failed_at
                    .is_some_and(|at| at.elapsed() >= GUARD_RETRY_INTERVAL)
            })
            .map(|e| e.identity)
    }

    fn mark_failed(&mut self, identity: &[u8; 20]) {
        if let Some(entry) = self.entries.iter_mut().find(|e| &e.identity == identity) {
            entry.failed_at = Some(Instant::now());
        }
        if self
            .open
            .as_ref()
            .is_some_and(|open| &open.identity == identity)
        {
            if let Some(open) = self.open.take() {
                open.channel.close();
            }
        }
    }

    fn mark_working(&mut self, identity: &[u8; 20]) {
        if let Some(entry) = self.entries.iter_mut().find(|e| &e.identity == identity) {
            entry.failed_at = None;
        }
    }

    /// Copy the open channel's address and identity onto its list entry, so a
    /// restart can go straight back to it.
    fn record_contact(&mut self, identity: &[u8; 20]) {
        let Some(open) = self.open.as_ref().filter(|o| &o.identity == identity) else {
            return;
        };
        let contact = GuardContact {
            addr: open.channel.peer(),
            ed_identity: *open.channel.ed_identity(),
        };
        if let Some(entry) = self.entries.iter_mut().find(|e| &e.identity == identity) {
            entry.contact = Some(contact);
        }
    }
}

impl TorClient {
    /// Bootstrap: get a verified consensus, then pick and pin a guard.
    ///
    /// When guards are already on disk the consensus is fetched through one of
    /// them rather than through a fallback mirror, which saves a whole TLS
    /// connection on every start after the first.
    pub fn bootstrap(state_dir: PathBuf) -> io::Result<Arc<Self>> {
        fs::create_dir_all(&state_dir)?;
        let entries = load_guards(&state_dir);

        // Reconnect to a saved guard before anything else. Its address and
        // Ed25519 identity were saved with it, which is all a channel needs --
        // the consensus is only needed later, for the onion key that CREATE2
        // wants -- so the consensus itself can come through the guard.
        let open = entries.iter().find_map(GuardEntry::reconnect);
        if let Some(open) = &open {
            crate::debug!("reconnected to the saved guard at {}", open.channel.peer());
        }

        let directory = Self::bootstrap_directory(&state_dir, open.as_ref())?;
        let client = Arc::new(Self {
            directory: RwLock::new(Arc::new(directory)),
            state_dir,
            guards: Mutex::new(Guards { entries, open }),
            pool: Pool::new(),
            microdescs: Mutex::new(HashMap::new()),
            hsdir_ring: Mutex::new(None),
            hsdir_build: Mutex::new(()),
            hsdir_wanted: AtomicBool::new(false),
            descriptors: Mutex::new(HashMap::new()),
            onion_circuits: Mutex::new(HashMap::new()),
        });
        // Open the guard channel now: an unreachable guard should be replaced
        // during startup, not on the first request.
        let (channel, _) = client.guard_channel()?;
        crate::info!(
            "guard {} (link v{})",
            channel.peer(),
            channel.link_version()
        );
        super::maintain::spawn(&client);
        pool::spawn(&client);
        Ok(client)
    }

    /// Get a verified consensus, preferring the already-open guard channel and
    /// falling back to a directory mirror if that does not work out.
    fn bootstrap_directory(state_dir: &Path, open: Option<&OpenGuard>) -> io::Result<Directory> {
        if let Some(open) = open {
            let channel = open.channel.clone();
            let attempt =
                Directory::bootstrap(Cache::new(state_dir), || DirCircuit::on(channel.clone()));
            match attempt {
                Ok(directory) => return Ok(directory),
                Err(e) => crate::warn!(
                    "could not get a consensus through the guard at {} ({e}); \
                     falling back to a directory mirror",
                    open.channel.peer()
                ),
            }
        }
        Directory::bootstrap(Cache::new(state_dir), DirCircuit::to_random_fallback)
    }

    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    /// The current view of the network. Take a clone and use it; holding the
    /// lock across a circuit build would block every refresh behind it.
    pub fn directory(&self) -> Arc<Directory> {
        Arc::clone(&self.directory.read().unwrap())
    }

    /// Adopt a newly verified consensus.
    ///
    /// The HSDir ring is derived from the consensus and from its `valid-after`
    /// in particular, so it is always thrown away here. Descriptors survive
    /// only while the time period is unchanged, which their stored period
    /// number already decides. Circuits and cached microdescriptors are keyed
    /// by things that do not move, so they stay.
    pub fn install_directory(&self, next: Directory) {
        let summary = next.summary();
        *self.directory.write().unwrap() = Arc::new(next);
        *self.hsdir_ring.lock().unwrap() = None;
        // Pre-built circuits were chosen from the old relay list; keep the
        // ones already carrying traffic and start the stock again.
        self.pool.clear();
        crate::info!("consensus updated: {summary}");
    }

    /// Fetch and adopt a newer consensus. Called only by the maintenance
    /// thread; a failure leaves the client on the consensus it already has.
    pub fn refresh_consensus(&self) -> io::Result<()> {
        let directory = self.directory();
        let dir_circuit = self.dir_circuit()?;
        let fetched = directory.refresh(&dir_circuit, now_unix());
        dir_circuit.close();
        self.install_directory(fetched?);
        self.reconcile_guards();
        Ok(())
    }

    /// Rebuild the HSDir ring in the background, but only for a client that
    /// has actually used one.
    pub fn prefetch_hsdir_ring(&self) {
        if !self.hsdir_wanted.load(Ordering::Relaxed) {
            return;
        }
        if let Err(e) = self.hsdir_ring() {
            crate::warn!("could not rebuild the HSDir ring: {e}");
        }
    }

    /// Open a stream to `host:port` through a three-hop circuit.
    pub fn connect(self: &Arc<Self>, host: &str, port: u16) -> io::Result<TorStream> {
        // Remember the port even if this attempt fails: the builder uses the
        // recent history to decide what a pre-built circuit should allow.
        self.pool.note_port(port);
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
                Ok(stream) => {
                    // The BEGIN has gone but nothing has come back yet. If the
                    // exit turns out to refuse this destination, or the
                    // circuit dies, the stream moves itself to another one and
                    // replays what the client has written meanwhile.
                    let client = Arc::clone(self);
                    let host = host.to_string();
                    stream.set_reattach(Box::new(move |failed| {
                        client.discard(failed);
                        client.circuit_for(port)?.begin_stream(&host, port)
                    }));
                    return Ok(stream);
                }
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

    /// A live circuit whose exit accepts `port`, reusing one from the pool
    /// when there is a suitable one that is not already busy.
    fn circuit_for(&self, port: u16) -> io::Result<Circuit> {
        if let Some(circuit) = self.pool.circuit_for(port) {
            return Ok(circuit);
        }
        let (circuit, exit) = self.build_exit_circuit(&[port])?;
        // Built to serve a request that is waiting, so it counts as dirty from
        // this moment rather than from its first stream.
        self.pool.insert(circuit.clone(), exit, true);
        Ok(circuit)
    }

    fn discard(&self, circuit: &Circuit) {
        self.pool.discard(circuit);
    }

    /// A two-hop circuit -- guard, then a middle relay -- with its last hop
    /// still to be chosen. Called by the builder thread.
    pub fn build_stub(&self) -> io::Result<Stub> {
        let (channel, guard) = self.guard_channel()?;
        let mut constraints = PathConstraints::default();
        self.constrain(&mut constraints, &guard);
        let middle = self.choose_middle(&constraints)?;

        let circuit = Circuit::create(&channel, &guard)?;
        if let Err(e) = circuit.extend(&middle) {
            circuit.close();
            return Err(e);
        }
        self.constrain(&mut constraints, &middle);
        Ok(Stub::new(circuit, constraints))
    }

    /// A three-hop circuit whose exit allows `ports`, extending a waiting stub
    /// if there is one.
    pub fn build_exit_circuit(&self, ports: &[u16]) -> io::Result<(Circuit, Arc<Microdesc>)> {
        // Any stub will do: the exit has not been chosen yet, so it can be
        // chosen to fit whichever stub we get.
        if let Some(stub) = self.pool.take_stub(&|_| true) {
            match self.extend_to_exit(&stub, ports) {
                Ok(exit) => return Ok((stub.circuit, exit)),
                Err(e) => {
                    crate::debug!("stub could not be extended to an exit: {e}");
                    stub.circuit.close();
                }
            }
        }

        let (channel, guard) = self.guard_channel()?;
        let mut constraints = PathConstraints::default();
        self.constrain(&mut constraints, &guard);
        let middle = self.choose_middle(&constraints)?;
        let circuit = Circuit::create(&channel, &guard)?;
        let built = (|| {
            circuit.extend(&middle)?;
            self.constrain(&mut constraints, &middle);
            let stub = Stub::new(circuit.clone(), constraints);
            self.extend_to_exit(&stub, ports)
        })();
        match built {
            Ok(exit) => Ok((circuit, exit)),
            Err(e) => {
                circuit.close();
                Err(e)
            }
        }
    }

    /// Choose an exit that fits what is already on `stub` and allows `ports`,
    /// and extend the circuit to it.
    fn extend_to_exit(&self, stub: &Stub, ports: &[u16]) -> io::Result<Arc<Microdesc>> {
        let directory = self.directory();
        let candidates = path::exit_candidates(&directory.consensus, &stub.constraints);
        let sampled = path::sample(&candidates, EXIT_SAMPLE)?;
        let wanted: Vec<[u8; 32]> = sampled.iter().map(|r| r.microdesc_digest).collect();
        let fetched = self.load_microdescs(&wanted)?;

        let usable = |r: &&RouterStatus, all: bool| {
            fetched.get(&r.microdesc_digest).is_some_and(|md| {
                !md.exit_policy.is_empty()
                    && stub.constraints.accepts(r, Some(md))
                    && if all {
                        ports.iter().all(|p| md.exit_policy.allows(*p))
                    } else {
                        ports.iter().any(|p| md.exit_policy.allows(*p))
                    }
            })
        };
        // Prefer an exit that allows every predicted port, but do not give up
        // if none does: one that allows some of them still serves most
        // requests, and the rest get a circuit of their own.
        let mut allowing: Vec<&RouterStatus> = sampled
            .iter()
            .copied()
            .filter(|r| usable(r, true))
            .collect();
        if allowing.is_empty() {
            allowing = sampled
                .iter()
                .copied()
                .filter(|r| usable(r, false))
                .collect();
        }
        if allowing.is_empty() {
            return Err(invalid_data(format!(
                "none of {} sampled exits allows any of {ports:?}",
                sampled.len()
            )));
        }

        let exit = path::weighted_choice(&allowing)?;
        let exit_md = fetched
            .get(&exit.microdesc_digest)
            .cloned()
            .ok_or_else(|| invalid_data("exit microdescriptor vanished"))?;
        stub.circuit.extend(&relay_info(exit, &exit_md))?;
        crate::debug!(
            "circuit {} completed to exit {}",
            stub.circuit.circ_id(),
            exit_md
                .ed_identity
                .map(|id| hex_encode(&id[..4]))
                .unwrap_or_default()
        );
        Ok(exit_md)
    }

    /// Build a three-hop circuit that ends at a relay the caller names.
    ///
    /// Directory, introduction and rendezvous circuits all have this shape:
    /// the last hop is fixed by the protocol rather than chosen for its exit
    /// policy, and only the middle is ours to pick.
    pub fn build_circuit_to(&self, last: &RelayInfo) -> io::Result<Circuit> {
        // A waiting stub is two of the three hops already done, so long as its
        // middle does not clash with where we are going.
        let family = self
            .cached_microdesc(&last.rsa_identity)
            .map(|md| md.family.clone())
            .unwrap_or_default();
        let octets = last.addr.ip().octets();
        let subnet = [octets[0], octets[1]];
        let fits = |c: &PathConstraints| c.accepts_relay(&last.rsa_identity, subnet, &family);
        if let Some(stub) = self.pool.take_stub(&fits) {
            match stub.circuit.extend(last) {
                Ok(()) => {
                    crate::debug!(
                        "circuit {} completed to {} from a stub",
                        stub.circuit.circ_id(),
                        last.addr
                    );
                    return Ok(stub.circuit);
                }
                Err(e) => {
                    crate::debug!("stub could not be extended to {}: {e}", last.addr);
                    stub.circuit.close();
                }
            }
        }

        let (channel, guard) = self.guard_channel()?;
        let mut constraints = PathConstraints::default();
        self.constrain(&mut constraints, &guard);
        self.constrain(&mut constraints, last);
        let middle = self.choose_middle(&constraints)?;
        extend_path(&channel, &guard, &middle, last)
    }

    /// Keep a path from doubling up on `relay`: by identity and /16 always,
    /// and by declared family when its microdescriptor is to hand.
    fn constrain(&self, constraints: &mut PathConstraints, relay: &RelayInfo) {
        let md = self.cached_microdesc(&relay.rsa_identity);
        match self.router(&relay.rsa_identity) {
            Some(status) => constraints.add(&status, md.as_deref()),
            // An introduction point may be named only by a descriptor, and
            // need not appear in our consensus at all.
            None => constraints.add_relay(
                relay.rsa_identity,
                [relay.addr.ip().octets()[0], relay.addr.ip().octets()[1]],
                md.map(|m| m.family.clone()).unwrap_or_default(),
            ),
        }
    }

    /// Draw a middle relay that fits the constraints, with its onion key.
    fn choose_middle(&self, constraints: &PathConstraints) -> io::Result<RelayInfo> {
        let directory = self.directory();
        let pool = path::middle_candidates(&directory.consensus, constraints);
        let sampled = path::sample(&pool, MIDDLE_SAMPLE)?;
        let wanted: Vec<[u8; 32]> = sampled.iter().map(|r| r.microdesc_digest).collect();
        let fetched = self.load_microdescs(&wanted)?;
        let usable: Vec<&RouterStatus> = sampled
            .iter()
            .copied()
            .filter(|r| {
                fetched
                    .get(&r.microdesc_digest)
                    .is_some_and(|md| constraints.accepts(r, Some(md)))
            })
            .collect();
        let chosen = path::weighted_choice(&usable)?;
        let md = fetched
            .get(&chosen.microdesc_digest)
            .ok_or_else(|| invalid_data("middle microdescriptor vanished"))?;
        Ok(relay_info(chosen, md))
    }

    /// Pick a rendezvous point. It never sees the destination, only that two
    /// circuits met, so the only requirements are that it is fast, stable and
    /// not somewhere the rest of the path already goes.
    pub fn choose_rendezvous_point(&self) -> io::Result<RelayInfo> {
        let mut constraints = PathConstraints::default();
        if let Ok(guard) = self.ensure_guard().and_then(|id| self.guard_relay(&id)) {
            self.constrain(&mut constraints, &guard);
        }
        let directory = self.directory();
        let pool = path::rendezvous_candidates(&directory.consensus, &constraints);
        let sampled = path::sample(&pool, RENDEZVOUS_SAMPLE)?;
        let wanted: Vec<[u8; 32]> = sampled.iter().map(|r| r.microdesc_digest).collect();
        let fetched = self.load_microdescs(&wanted)?;
        let usable: Vec<&RouterStatus> = sampled
            .iter()
            .copied()
            .filter(|r| fetched.contains_key(&r.microdesc_digest))
            .collect();
        let chosen = path::weighted_choice(&usable)?;
        let md = fetched
            .get(&chosen.microdesc_digest)
            .ok_or_else(|| invalid_data("rendezvous point microdescriptor vanished"))?;
        Ok(relay_info(chosen, md))
    }

    /// Everything needed to extend a circuit to the relay with this identity.
    fn relay_for(&self, identity: &[u8; 20]) -> io::Result<RelayInfo> {
        let status = self
            .router(identity)
            .ok_or_else(|| invalid_data("relay is not in the consensus"))?;
        self.resolve_relay(&status)
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
        self.directory()
            .consensus
            .routers
            .iter()
            .find(|r| &r.identity == identity)
            .cloned()
    }

    /// The pinned guard, choosing and recording a new one if the list is
    /// empty or every entry on it is in its cool-off period.
    fn ensure_guard(&self) -> io::Result<[u8; 20]> {
        if let Some(identity) = self.guards.lock().unwrap().next_candidate() {
            return Ok(identity);
        }
        let directory = self.directory();
        let chosen = {
            let guards = self.guards.lock().unwrap();
            // Racing threads must not each add a guard, so re-check under the
            // lock we are about to extend the list with.
            if let Some(identity) = guards.next_candidate() {
                return Ok(identity);
            }
            if guards.entries.len() >= MAX_GUARDS {
                // Every guard we have is cooling off, and adding a fourth
                // would defeat the point of pinning. Retry the least recently
                // failed one instead.
                let soonest = guards
                    .entries
                    .iter()
                    .min_by_key(|e| e.failed_at)
                    .map(|e| e.identity);
                return soonest.ok_or_else(|| io::Error::other("no guard to try"));
            }
            let taken: Vec<[u8; 20]> = guards.entries.iter().map(|e| e.identity).collect();
            let candidates: Vec<&RouterStatus> = path::guard_candidates(&directory.consensus)
                .into_iter()
                .filter(|r| !taken.contains(&r.identity))
                .collect();
            path::weighted_choice(&candidates)?.identity
        };
        let mut guards = self.guards.lock().unwrap();
        if !guards.entries.iter().any(|e| e.identity == chosen) {
            crate::info!("adding guard {}", hex_encode(&chosen[..8]));
            guards.entries.push(GuardEntry {
                identity: chosen,
                contact: None,
                failed_at: None,
            });
        }
        self.save_guards(&guards);
        Ok(chosen)
    }

    /// Everything needed to run ntor with a guard: its address, onion key and
    /// identities, from the consensus and its microdescriptor.
    fn guard_relay(&self, identity: &[u8; 20]) -> io::Result<RelayInfo> {
        let status = self
            .router(identity)
            .ok_or_else(|| invalid_data("the guard is no longer in the consensus"))?;
        self.resolve_relay(&status)
    }

    /// Turn a consensus entry into everything needed for a handshake.
    fn resolve_relay(&self, status: &RouterStatus) -> io::Result<RelayInfo> {
        let mds = self.load_microdescs(&[status.microdesc_digest])?;
        let md = mds
            .get(&status.microdesc_digest)
            .ok_or_else(|| invalid_data("could not fetch the relay's microdescriptor"))?;
        Ok(relay_info(status, md))
    }

    /// Drop guards this consensus no longer lists at all, and write the list
    /// back out. A guard that is merely not Running stays: that judgement is
    /// the network's, and it may not be true from here.
    pub fn reconcile_guards(&self) {
        let directory = self.directory();
        let mut guards = self.guards.lock().unwrap();
        let before = guards.entries.len();
        guards.entries.retain(|entry| {
            let known = directory
                .consensus
                .routers
                .iter()
                .any(|r| r.identity == entry.identity);
            if !known {
                crate::info!(
                    "guard {} has left the consensus; dropping it",
                    hex_encode(&entry.identity[..8])
                );
            }
            known
        });
        if guards.entries.len() != before {
            self.save_guards(&guards);
        }
    }

    /// Try the primary guard again after it failed. Called by the maintenance
    /// thread, so that a moment's network trouble does not move us off it for
    /// good.
    pub fn retry_primary_guard(&self) {
        let primary = {
            let guards = self.guards.lock().unwrap();
            let Some(entry) = guards.entries.first() else {
                return;
            };
            // Nothing to do when the primary is the one already in use.
            if entry.failed_at.is_none()
                && guards
                    .open
                    .as_ref()
                    .is_some_and(|open| open.identity == entry.identity)
            {
                return;
            }
            if entry
                .failed_at
                .is_some_and(|at| at.elapsed() < GUARD_RETRY_INTERVAL)
            {
                return;
            }
            entry.identity
        };
        let Ok(relay) = self.guard_relay(&primary) else {
            return;
        };
        match Channel::connect(relay.addr, relay.ed_identity.as_ref()) {
            Ok(channel) => {
                crate::info!("primary guard {} is reachable again", relay.addr);
                let mut guards = self.guards.lock().unwrap();
                guards.mark_working(&primary);
                // Existing circuits keep the channel they were built on; only
                // new ones follow the primary back.
                let displaced = guards.open.replace(OpenGuard {
                    identity: primary,
                    relay: Some(relay),
                    channel,
                });
                guards.record_contact(&primary);
                self.save_guards(&guards);
                drop(guards);
                if let Some(old) = displaced {
                    // Do not close it: circuits built on it are still running.
                    crate::debug!("guard {} is no longer the default", old.channel.peer());
                }
            }
            Err(e) => crate::debug!("primary guard still unreachable: {e}"),
        }
    }

    fn save_guards(&self, guards: &Guards) {
        let text = serialize_guards(&guards.entries);
        if let Err(e) = fs::write(self.state_dir.join(GUARDS_FILE), text) {
            crate::warn!("could not persist the guard list: {e}");
        }
    }

    /// An open channel to a guard together with the guard it belongs to,
    /// reconnecting or falling back to the next guard as needed.
    ///
    /// The two are returned together on purpose: a circuit built on this
    /// channel must run ntor against *this* guard's keys, and failover can
    /// change which guard that is.
    fn guard_channel(&self) -> io::Result<(Channel, RelayInfo)> {
        let mut last: Option<io::Error> = None;
        for _ in 0..GUARD_ATTEMPTS {
            match self.open_guard_channel() {
                Ok(Some(open)) => return Ok(open),
                Ok(None) => {}
                // Whatever stopped us using the open channel will be
                // rediscovered below, with the guard named in the message.
                Err(e) => crate::debug!("the open guard channel is unusable: {e}"),
            }
            let identity = self.ensure_guard()?;
            let relay = match self.guard_relay(&identity) {
                Ok(relay) => relay,
                Err(e) => {
                    crate::warn!(
                        "guard {} cannot be resolved ({e})",
                        hex_encode(&identity[..8])
                    );
                    self.guards.lock().unwrap().mark_failed(&identity);
                    last = Some(e);
                    continue;
                }
            };
            match Channel::connect(relay.addr, relay.ed_identity.as_ref()) {
                Ok(channel) => {
                    crate::debug!(
                        "guard channel to {} up: link v{}, identity {}",
                        relay.addr,
                        channel.link_version(),
                        hex_encode(&channel.ed_identity()[..8])
                    );
                    return Ok(self.store_guard_channel(identity, channel, relay));
                }
                Err(e) => {
                    // Before blaming the guard, check that anything at all is
                    // reachable. Losing the network for a moment must not cost
                    // us the guard we have been pinned to.
                    if !network_reachable() {
                        crate::warn!(
                            "guard {} unreachable and so is everything else; \
                                      keeping the guard",
                            relay.addr
                        );
                        return Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            format!("the network is unreachable ({e})"),
                        ));
                    }
                    crate::warn!("guard {} unusable ({e}); trying the next one", relay.addr);
                    let mut guards = self.guards.lock().unwrap();
                    guards.mark_failed(&identity);
                    self.save_guards(&guards);
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("no guard would accept a connection")))
    }

    /// The channel currently in use, if it is still up and we know enough
    /// about its guard to build circuits on it.
    fn open_guard_channel(&self) -> io::Result<Option<(Channel, RelayInfo)>> {
        let (identity, channel, relay) = {
            let guards = self.guards.lock().unwrap();
            let Some(open) = guards.open.as_ref() else {
                return Ok(None);
            };
            if open.channel.is_closed() {
                return Ok(None);
            }
            (open.identity, open.channel.clone(), open.relay.clone())
        };
        match relay {
            Some(relay) => Ok(Some((channel, relay))),
            // The channel was opened from the saved address alone, before
            // there was a consensus to look the onion key up in.
            None => {
                let relay = self.guard_relay(&identity)?;
                let mut guards = self.guards.lock().unwrap();
                if let Some(open) = guards.open.as_mut() {
                    if open.identity == identity {
                        open.relay = Some(relay.clone());
                    }
                }
                guards.record_contact(&identity);
                self.save_guards(&guards);
                Ok(Some((channel, relay)))
            }
        }
    }

    /// The open guard channel alone, without resolving the guard's keys.
    fn open_guard_channel_only(&self) -> Option<Channel> {
        let guards = self.guards.lock().unwrap();
        let channel = guards.open.as_ref()?.channel.clone();
        (!channel.is_closed()).then_some(channel)
    }

    /// Publish a freshly opened channel, deferring to one another thread may
    /// have stored first.
    fn store_guard_channel(
        &self,
        identity: [u8; 20],
        channel: Channel,
        relay: RelayInfo,
    ) -> (Channel, RelayInfo) {
        let mut guards = self.guards.lock().unwrap();
        guards.mark_working(&identity);
        if let Some(open) = guards.open.as_ref() {
            if !open.channel.is_closed() {
                if let Some(relay) = open.relay.clone() {
                    let existing = (open.channel.clone(), relay);
                    drop(guards);
                    channel.close();
                    return existing;
                }
            }
        }
        guards.open = Some(OpenGuard {
            identity,
            relay: Some(relay.clone()),
            channel: channel.clone(),
        });
        guards.record_contact(&identity);
        self.save_guards(&guards);
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
        let fetched = self.directory().microdescs(&missing, &dir_circuit);
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
        // The relay details are not needed for a one-hop CREATE_FAST circuit,
        // so take the channel directly rather than through the accessor that
        // would go and fetch a microdescriptor first.
        if let Some(channel) = self.open_guard_channel_only() {
            let peer = channel.peer();
            match DirCircuit::on(channel) {
                Ok(dir_circuit) => return Ok(dir_circuit),
                Err(e) => crate::debug!("guard {peer} refused a directory circuit: {e}"),
            }
        }
        DirCircuit::to_random_fallback()
    }

    /// The HSDir hash ring for the current time period, building it if this
    /// is the first `.onion` request.
    ///
    /// The first build fetches a microdescriptor for every HSDir in the
    /// consensus -- some five thousand of them, in batches of 92 -- which
    /// takes the better part of a minute. Afterwards the disk cache makes it
    /// quick, and the ring itself is kept until the consensus changes.
    pub fn hsdir_ring(&self) -> io::Result<Arc<HsdirRing>> {
        self.hsdir_wanted.store(true, Ordering::Relaxed);
        let directory = self.directory();
        let valid_after = directory.consensus.valid_after;
        if let Some(ring) = self.cached_hsdir_ring(valid_after) {
            return Ok(ring);
        }
        // Thousands of directory requests is not something to do twice over,
        // so whoever gets here first builds and the rest wait for it.
        let _building = self.hsdir_build.lock().unwrap();
        if let Some(ring) = self.cached_hsdir_ring(valid_after) {
            return Ok(ring);
        }

        let started = Instant::now();
        let consensus = &directory.consensus;
        let period = TimePeriod::containing(valid_after, consensus.params.hsdir_interval);
        let srv = hsdir::shared_random_value(consensus, &period);

        let hsdirs: Vec<&RouterStatus> = consensus
            .routers
            .iter()
            .filter(|r| r.has(FLAG_HSDIR))
            .collect();
        crate::info!(
            "building the HSDir ring for time period {} from {} relays",
            period.number,
            hsdirs.len()
        );
        let digests: Vec<[u8; 32]> = hsdirs.iter().map(|r| r.microdesc_digest).collect();

        let dir_circuit = self.dir_circuit()?;
        let ed_ids = directory.microdesc_ed_ids(&digests, &dir_circuit);
        dir_circuit.close();

        let nodes = hsdir::build_ring(
            hsdirs
                .iter()
                .filter_map(|r| ed_ids.get(&r.microdesc_digest).map(|ed| (r.identity, *ed))),
            &srv,
            &period,
        );
        if nodes.is_empty() {
            return Err(invalid_data(
                "no HSDir in the consensus has an Ed25519 identity",
            ));
        }
        crate::info!(
            "HSDir ring ready in {:.1}s: {} of {} relays placed",
            started.elapsed().as_secs_f32(),
            nodes.len(),
            hsdirs.len()
        );

        let ring = Arc::new(HsdirRing {
            period,
            valid_after,
            nodes,
            n_replicas: consensus.params.hsdir_n_replicas,
            spread_fetch: consensus.params.hsdir_spread_fetch,
        });
        *self.hsdir_ring.lock().unwrap() = Some(Arc::clone(&ring));
        Ok(ring)
    }

    fn cached_hsdir_ring(&self, valid_after: u64) -> Option<Arc<HsdirRing>> {
        self.hsdir_ring
            .lock()
            .unwrap()
            .as_ref()
            .filter(|ring| ring.valid_after == valid_after)
            .map(Arc::clone)
    }

    pub fn consensus_summary(&self) -> String {
        self.directory().summary()
    }

    /// The verified consensus. Only the live tests reach for this; everything
    /// the client itself needs is already folded into the ring and the path
    /// selection above.
    #[cfg(test)]
    pub fn consensus(&self) -> Arc<Directory> {
        self.directory()
    }
}

impl HsdirRing {
    /// The relays that should be holding this descriptor: `hsdir_n_replicas`
    /// groups of `hsdir_spread_fetch`, in ring order, without repeats.
    pub fn responsible_for(&self, blinded_key: &[u8; 32]) -> Vec<[u8; 20]> {
        hsdir::responsible(
            &self.nodes,
            blinded_key,
            &self.period,
            self.n_replicas,
            self.spread_fetch,
        )
    }
}

impl TorClient {
    /// The current descriptor for `address`, fetched from the directory nodes
    /// responsible for it if it is not already in hand.
    pub fn descriptor(&self, address: &OnionAddress) -> io::Result<Arc<Descriptor>> {
        let ring = self.hsdir_ring()?;
        let blinded = ring.period.blinded_key(&address.public_key)?;

        {
            let mut cache = self.descriptors.lock().unwrap();
            cache.retain(|_, entry| entry.expires_at > Instant::now());
            if let Some(entry) = cache.get(&address.public_key) {
                if entry.period == ring.period.number {
                    return Ok(Arc::clone(&entry.descriptor));
                }
            }
        }

        let subcredential = address.subcredential(&blinded);
        let descriptor = Arc::new(self.fetch_descriptor(&ring, &blinded, &subcredential)?);
        // A descriptor also expires when the time period turns over, which the
        // stored period number catches: the blinded key changes with it.
        let lifetime = Duration::from_secs(descriptor.lifetime_minutes.min(720) * 60);
        self.descriptors.lock().unwrap().insert(
            address.public_key,
            CachedDescriptor {
                descriptor: Arc::clone(&descriptor),
                period: ring.period.number,
                expires_at: Instant::now() + lifetime,
            },
        );
        Ok(descriptor)
    }

    /// Drop a cached descriptor, so the next request fetches a fresh one.
    /// Used when the introduction points reject the authentication key they
    /// name, which means the descriptor we hold has been replaced.
    fn forget_descriptor(&self, address: &OnionAddress) {
        self.descriptors.lock().unwrap().remove(&address.public_key);
    }

    /// Open a stream to `address:port` through a rendezvous circuit.
    pub fn connect_onion(
        self: &Arc<Self>,
        address: &OnionAddress,
        port: u16,
    ) -> io::Result<TorStream> {
        let mut last: Option<io::Error> = None;
        for attempt in 0..CONNECT_ATTEMPTS {
            let circuit = match self.onion_circuit(address) {
                Ok(circuit) => circuit,
                Err(e) => {
                    // A service that is simply not published will fail the
                    // same way every time; do not spend three tries on it.
                    if e.kind() == io::ErrorKind::NotFound
                        || e.kind() == io::ErrorKind::PermissionDenied
                    {
                        return Err(e);
                    }
                    crate::debug!("attempt {}: no rendezvous circuit: {e}", attempt + 1);
                    last = Some(e);
                    continue;
                }
            };
            match circuit.begin_stream_onion(port) {
                Ok(stream) => {
                    let client = Arc::clone(self);
                    let address = *address;
                    stream.set_reattach(Box::new(move |_failed| {
                        // Only a circuit failure gets here: the service's own
                        // refusals are about the destination, not the path.
                        client.discard_onion_circuit(&address);
                        client.onion_circuit(&address)?.begin_stream_onion(port)
                    }));
                    return Ok(stream);
                }
                // A RELAY_END means the service itself answered: it is not
                // listening on that port. Another rendezvous circuit would
                // reach the same service and get the same answer, so keep the
                // circuit and report what it said.
                Err(e) if circuit::is_stream_end(&e) => return Err(e),
                Err(e) => {
                    crate::debug!("attempt {}: onion BEGIN failed: {e}", attempt + 1);
                    self.discard_onion_circuit(address);
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("could not reach the onion service")))
    }

    /// The rendezvous circuit for this service, reusing the open one if there
    /// is one: every stream to a service shares a single circuit, as C Tor
    /// does.
    fn onion_circuit(&self, address: &OnionAddress) -> io::Result<Circuit> {
        {
            let mut open = self.onion_circuits.lock().unwrap();
            open.retain(|_, c| !c.circuit.is_closed() && c.built.elapsed() < MAX_CIRCUIT_AGE);
            self.pool.set_onion_in_use(open.len());
            if let Some(found) = open.get(&address.public_key) {
                return Ok(found.circuit.clone());
            }
        }

        let subcredential = self.onion_keys(address)?.1;
        let descriptor = self.descriptor(address)?;
        let circuit = match rendezvous::establish(self, &descriptor, &subcredential) {
            Ok(circuit) => circuit,
            Err(failure) if failure.descriptor_is_stale => {
                // The introduction points do not recognise the keys we named,
                // so the descriptor moved on without us. Try once more with a
                // fresh one, and no further: a service that keeps saying this
                // is one we cannot reach.
                crate::debug!("descriptor looks stale; refetching once");
                self.forget_descriptor(address);
                let descriptor = self.descriptor(address)?;
                rendezvous::establish(self, &descriptor, &subcredential)
                    .map_err(|failure| failure.error)?
            }
            Err(failure) => return Err(failure.error),
        };

        let mut open = self.onion_circuits.lock().unwrap();
        open.retain(|_, c| !c.circuit.is_closed() && c.built.elapsed() < MAX_CIRCUIT_AGE);
        while open.len() >= MAX_CIRCUITS {
            let oldest = open
                .iter()
                .min_by_key(|(_, c)| c.built)
                .map(|(key, _)| *key)
                .expect("the map is not empty");
            if let Some(retired) = open.remove(&oldest) {
                retired.circuit.close();
            }
        }
        // Another thread may have built one for this service while we were
        // busy; whichever loses gets closed rather than left running.
        if let Some(displaced) = open.insert(
            address.public_key,
            PooledOnionCircuit {
                circuit: circuit.clone(),
                built: Instant::now(),
            },
        ) {
            displaced.circuit.close();
        }
        self.pool.set_onion_in_use(open.len());
        Ok(circuit)
    }

    fn discard_onion_circuit(&self, address: &OnionAddress) {
        let mut open = self.onion_circuits.lock().unwrap();
        if let Some(retired) = open.remove(&address.public_key) {
            retired.circuit.close();
        }
        self.pool.set_onion_in_use(open.len());
    }

    /// The blinded key and subcredential for this address in the current time
    /// period. Both change when the period turns over.
    fn onion_keys(&self, address: &OnionAddress) -> io::Result<([u8; 32], [u8; 32])> {
        let ring = self.hsdir_ring()?;
        let blinded = ring.period.blinded_key(&address.public_key)?;
        Ok((blinded, address.subcredential(&blinded)))
    }

    fn fetch_descriptor(
        &self,
        ring: &HsdirRing,
        blinded: &[u8; 32],
        subcredential: &[u8; 32],
    ) -> io::Result<Descriptor> {
        let mut responsible = ring.responsible_for(blinded);
        rand::shuffle(&mut responsible)?;
        let path = format!("/tor/hs/3/{}", base64_encode_unpadded(blinded));

        let mut last: Option<io::Error> = None;
        let mut all_absent = true;
        for (attempt, identity) in responsible.iter().enumerate() {
            // Three nodes is the usual budget. If all three simply had no
            // copy, the remaining ones are still worth asking: around a time
            // period boundary the service may not have finished uploading.
            if attempt >= HSDIR_TRIES && !all_absent {
                break;
            }
            match self.fetch_descriptor_from(identity, &path, blinded, subcredential) {
                Ok(descriptor) => return Ok(descriptor),
                // We have the descriptor and it says the service wants client
                // authorization. Every other copy says the same thing.
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Err(e),
                Err(e) => {
                    crate::debug!("hsdir {}: {e}", hex_encode(&identity[..4]));
                    all_absent &= e.kind() == io::ErrorKind::NotFound;
                    last = Some(e);
                }
            }
        }
        Err(match last {
            // Every directory node that answered said it had no such
            // descriptor: the service is not published, not unreachable.
            Some(e) if e.kind() == io::ErrorKind::NotFound || all_absent => io::Error::new(
                io::ErrorKind::NotFound,
                "no directory node holds a descriptor for this onion service",
            ),
            Some(e) => e,
            None => invalid_data("no directory node is responsible for this onion service"),
        })
    }

    fn fetch_descriptor_from(
        &self,
        identity: &[u8; 20],
        path: &str,
        blinded: &[u8; 32],
        subcredential: &[u8; 32],
    ) -> io::Result<Descriptor> {
        let relay = self.relay_for(identity)?;
        let circuit = self.build_circuit_to(&relay)?;
        let raw = super::dir::fetch::get(&circuit, path);
        circuit.close();
        let raw = raw?;
        if raw.len() > descriptor::MAX_DESCRIPTOR_BYTES {
            return Err(invalid_data(
                "onion service descriptor is implausibly large",
            ));
        }
        let text = String::from_utf8(raw)
            .map_err(|_| invalid_data("onion service descriptor is not UTF-8"))?;
        let descriptor = Descriptor::parse(&text, blinded, subcredential, now_unix())?;
        crate::debug!(
            "descriptor from {}: revision {}, {} introduction points",
            hex_encode(&identity[..4]),
            descriptor.revision_counter,
            descriptor.intro_points.len()
        );
        Ok(descriptor)
    }
}

/// Create a circuit on `channel` and extend it through `middle` to `last`.
fn extend_path(
    channel: &Channel,
    guard: &RelayInfo,
    middle: &RelayInfo,
    last: &RelayInfo,
) -> io::Result<Circuit> {
    let circuit = Circuit::create(channel, guard)?;
    let build = (|| {
        circuit.extend(middle)?;
        circuit.extend(last)
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
        middle.addr,
        last.addr
    );
    Ok(circuit)
}

impl Drop for TorClient {
    fn drop(&mut self) {
        // The builder and maintenance threads hold only weak references, so
        // they would stop on their own; this makes them stop at once rather
        // than at their next tick.
        self.pool.stop();
    }
}

/// Read `state/guards`: one guard per line, in priority order, as
/// `<RSA identity hex> [<ip:port> <Ed25519 identity hex>]`.
///
/// The contact fields are optional so that a hand-written file naming only a
/// fingerprint still works; they are filled in the first time the guard is
/// reached. A line that will not parse is skipped rather than fatal -- a
/// corrupt state file should cost a guard choice, not a start-up.
fn load_guards(state_dir: &Path) -> Vec<GuardEntry> {
    let mut text = fs::read_to_string(state_dir.join(GUARDS_FILE)).unwrap_or_default();
    if text.trim().is_empty() {
        // Earlier versions kept a single guard in a file of its own.
        text = fs::read_to_string(state_dir.join(LEGACY_GUARD_FILE)).unwrap_or_default();
    }

    let mut entries: Vec<GuardEntry> = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(identity) = fields
            .next()
            .and_then(|hex| hex_decode(hex).ok())
            .and_then(|bytes| <[u8; 20]>::try_from(bytes).ok())
        else {
            continue;
        };
        if entries.iter().any(|e| e.identity == identity) {
            continue;
        }
        let contact = (|| {
            let addr: SocketAddrV4 = fields.next()?.parse().ok()?;
            let ed_identity = <[u8; 32]>::try_from(hex_decode(fields.next()?).ok()?).ok()?;
            Some(GuardContact { addr, ed_identity })
        })();
        entries.push(GuardEntry {
            identity,
            contact,
            failed_at: None,
        });
        if entries.len() == MAX_GUARDS {
            break;
        }
    }
    entries
}

fn serialize_guards(entries: &[GuardEntry]) -> String {
    let mut out = String::new();
    for entry in entries.iter().take(MAX_GUARDS) {
        out.push_str(&hex_encode(&entry.identity));
        if let Some(contact) = entry.contact {
            out.push(' ');
            out.push_str(&contact.addr.to_string());
            out.push(' ');
            out.push_str(&hex_encode(&contact.ed_identity));
        }
        out.push('\n');
    }
    out
}

/// Is anything on the Tor network reachable from here at all?
///
/// Asked when a guard refuses a connection, to tell "the guard is down" from
/// "our network is down". Only the former should cost us the guard, so a
/// couple of fallback mirrors are probed with a bare TCP connect -- two,
/// because any one of them may itself be down.
fn network_reachable() -> bool {
    let dirs = fallback::FALLBACK_DIRS;
    for _ in 0..REACHABILITY_PROBES {
        let Ok(index) = rand::below(dirs.len() as u64) else {
            return true;
        };
        let entry = &dirs[index as usize];
        let addr = SocketAddrV4::new(Ipv4Addr::from(entry.ipv4), entry.or_port);
        if TcpStream::connect_timeout(&addr.into(), REACHABILITY_TIMEOUT).is_ok() {
            return true;
        }
    }
    false
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
        let (_, circuits) = client.pool().counts();
        let second = client
            .connect("check.torproject.org", 80)
            .expect("second connect");
        assert_eq!(
            client.pool().counts().1,
            circuits,
            "a second stream on the same port must reuse a circuit"
        );
        second.close();

        // The guard is pinned on disk, so a restart keeps the same one, and
        // its address is saved with it so the restart can reconnect before it
        // has a consensus.
        let saved = fs::read_to_string(dir.join(GUARDS_FILE)).unwrap();
        let fields: Vec<&str> = saved.lines().next().unwrap().split(' ').collect();
        assert_eq!(fields.len(), 3, "identity, address and Ed25519 identity");
        assert_eq!(fields[0].len(), 40, "a hex RSA fingerprint");
        assert!(fields[1].parse::<SocketAddrV4>().is_ok(), "{}", fields[1]);
        assert_eq!(fields[2].len(), 64, "a hex Ed25519 identity");
        assert!(saved.lines().count() <= MAX_GUARDS);

        let _ = fs::remove_dir_all(&dir);
    }
}
