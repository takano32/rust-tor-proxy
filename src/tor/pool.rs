//! The circuit pool and the thread that keeps it stocked.
//!
//! Building a circuit costs three round trips -- CREATE2 to the guard, then an
//! EXTEND2 for each further hop -- and a request that waits for all of them
//! before it can even send a BEGIN spends most of its life idle. So the pool
//! keeps work done in advance:
//!
//! * **stubs**: two-hop circuits, guard then middle, with no last hop chosen.
//!   Whatever the next request turns out to want -- an exit, a directory node,
//!   an introduction or rendezvous point -- is one EXTEND2 away. This is the
//!   piece that helps every kind of circuit, because only the last hop depends
//!   on what is being asked for.
//! * **clean circuits**: a finished three-hop circuit whose exit allows the
//!   ports this client has been using, so the common case is a BEGIN and
//!   nothing else.
//!
//! A circuit becomes "dirty" when its first stream is attached, not when it is
//! built, or a circuit made ahead of time would be retired before anyone used
//! it. New streams are spread across circuits rather than piled onto one:
//! window-based flow control caps each circuit at a thousand cells per round
//! trip, so several circuits carry more in total than one can.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

use super::circuit::Circuit;
use super::client::TorClient;
use super::dir::microdesc::Microdesc;
use super::path::PathConstraints;

/// How many two-hop stubs to keep ready. Two covers a request arriving while
/// another is being served without keeping much idle capacity around.
const STUB_TARGET: usize = 2;

/// Circuits of every kind that may exist at once.
pub const MAX_CIRCUITS: usize = 8;

/// How many circuits concurrent streams spread across before they start
/// sharing one. Each circuit gets its own thousand-cell window, so a parallel
/// download goes about as many times faster as it has circuits -- and this is
/// the number that decides how many exits see the traffic at once, which is
/// why it is a small constant and not the whole budget.
const SPREAD_CIRCUITS: usize = 4;

/// Once the spread is used up, a circuit takes this many streams before
/// another is built.
const STREAMS_PER_CIRCUIT: usize = 4;

/// A circuit stops taking new streams this long after its first one, so that
/// activity spread over hours is not all tied to one path.
const MAX_DIRTY_AGE: Duration = Duration::from_secs(600);

/// A circuit nobody ever used is still retired eventually: its relays may have
/// left the consensus since it was built.
const MAX_IDLE_AGE: Duration = Duration::from_secs(1800);

/// A stub older than this is dropped rather than extended.
const STUB_MAX_AGE: Duration = Duration::from_secs(300);

/// How long a port stays worth pre-building a circuit for.
const PREDICTION_WINDOW: Duration = Duration::from_secs(3600);

/// What to assume before anything has been asked for.
const DEFAULT_PORTS: [u16; 2] = [80, 443];

/// The builder wakes at least this often even when nothing signals it.
const BUILDER_TICK: Duration = Duration::from_secs(30);

/// After a failure to build, wait this long before trying again, doubling up
/// to the cap. A guard that is down should not be hammered.
const BUILD_RETRY_MIN: Duration = Duration::from_secs(2);
const BUILD_RETRY_MAX: Duration = Duration::from_secs(120);

/// A two-hop circuit waiting for its last hop.
pub struct Stub {
    pub circuit: Circuit,
    /// The guard and middle already on it, so the last hop can be checked
    /// against them without going back to the consensus.
    pub constraints: PathConstraints,
    built: Instant,
}

impl Stub {
    pub fn new(circuit: Circuit, constraints: PathConstraints) -> Self {
        Self {
            circuit,
            constraints,
            built: Instant::now(),
        }
    }

    fn usable(&self) -> bool {
        !self.circuit.is_closed() && self.built.elapsed() < STUB_MAX_AGE
    }
}

struct Pooled {
    circuit: Circuit,
    /// The exit's microdescriptor, for its port policy.
    exit: Arc<Microdesc>,
    built: Instant,
    /// When the first stream was attached. `None` means still clean.
    first_used: Option<Instant>,
}

impl Pooled {
    fn usable(&self) -> bool {
        if self.circuit.is_closed() || self.built.elapsed() >= MAX_IDLE_AGE {
            return false;
        }
        match self.first_used {
            Some(at) => at.elapsed() < MAX_DIRTY_AGE,
            None => true,
        }
    }
}

struct Prediction {
    port: u16,
    last: Instant,
}

#[derive(Default)]
struct State {
    stubs: Vec<Stub>,
    circuits: Vec<Pooled>,
    predicted: Vec<Prediction>,
    /// Rendezvous circuits, which the client owns but which count against the
    /// same budget.
    onion_in_use: usize,
}

impl State {
    fn retire(&mut self) {
        self.stubs.retain(|s| {
            let keep = s.usable();
            if !keep {
                s.circuit.close();
            }
            keep
        });
        self.circuits.retain(|c| {
            let keep = c.usable();
            if !keep && c.circuit.open_streams() == 0 {
                c.circuit.close();
                return false;
            }
            // A circuit past its dirty age but still carrying streams is left
            // alone until they finish; only new streams are kept off it.
            keep || c.circuit.open_streams() > 0
        });
        self.predicted
            .retain(|p| p.last.elapsed() < PREDICTION_WINDOW);
    }

    fn total(&self) -> usize {
        self.stubs.len() + self.circuits.len() + self.onion_in_use
    }

    /// Circuits that are still taking new streams.
    fn open_for_streams(&self) -> impl Iterator<Item = &Pooled> {
        self.circuits.iter().filter(|c| c.usable())
    }
}

pub struct Pool {
    state: Mutex<State>,
    /// Signals the builder: stock was taken, or the consensus changed.
    wake: Condvar,
    stopping: AtomicBool,
}

impl Default for Pool {
    fn default() -> Self {
        Self::new()
    }
}

impl Pool {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State::default()),
            wake: Condvar::new(),
            stopping: AtomicBool::new(false),
        }
    }

    /// Remember that a stream wanted this port, so the builder can have an
    /// exit that allows it ready next time.
    pub fn note_port(&self, port: u16) {
        let mut state = self.state.lock().unwrap();
        match state.predicted.iter_mut().find(|p| p.port == port) {
            Some(existing) => existing.last = Instant::now(),
            None => state.predicted.push(Prediction {
                port,
                last: Instant::now(),
            }),
        }
    }

    /// The ports a pre-built circuit should allow: everything asked for
    /// recently, or the web's two before anything has been.
    pub fn predicted_ports(&self) -> Vec<u16> {
        let mut state = self.state.lock().unwrap();
        state.retire();
        if state.predicted.is_empty() {
            return DEFAULT_PORTS.to_vec();
        }
        state.predicted.iter().map(|p| p.port).collect()
    }

    /// A live circuit whose exit allows `port`, chosen for the lightest load.
    ///
    /// Returns `None` when a new circuit would be better: either none allows
    /// the port, or every one that does is already carrying enough streams and
    /// there is room in the budget for another.
    pub fn circuit_for(&self, port: u16) -> Option<Circuit> {
        let mut state = self.state.lock().unwrap();
        state.retire();
        let room = state.total() < MAX_CIRCUITS;
        let allowing = state
            .open_for_streams()
            .filter(|c| c.exit.exit_policy.allows(port))
            .count();
        let limit = stream_limit(allowing);
        let best = state
            .circuits
            .iter_mut()
            .filter(|c| c.usable() && c.exit.exit_policy.allows(port))
            .min_by_key(|c| c.circuit.open_streams())?;
        if best.circuit.open_streams() >= limit && room {
            return None;
        }
        best.first_used.get_or_insert_with(Instant::now);
        let circuit = best.circuit.clone();
        drop(state);
        // Taking a circuit may have left the pool short of a clean one.
        self.wake.notify_all();
        Some(circuit)
    }

    /// Take a stub the caller can extend, if one is compatible with the hop it
    /// has in mind.
    pub fn take_stub(&self, fits: &dyn Fn(&PathConstraints) -> bool) -> Option<Stub> {
        let mut state = self.state.lock().unwrap();
        state.retire();
        let index = state
            .stubs
            .iter()
            .position(|stub| fits(&stub.constraints))?;
        let stub = state.stubs.remove(index);
        drop(state);
        self.wake.notify_all();
        Some(stub)
    }

    pub fn add_stub(&self, stub: Stub) {
        let mut state = self.state.lock().unwrap();
        if state.total() >= MAX_CIRCUITS {
            stub.circuit.close();
            return;
        }
        state.stubs.push(stub);
    }

    /// Put a finished circuit in the pool. `used` marks it dirty at once,
    /// which is what a circuit built to serve a waiting request is.
    pub fn insert(&self, circuit: Circuit, exit: Arc<Microdesc>, used: bool) {
        let mut state = self.state.lock().unwrap();
        state.retire();
        while state.total() >= MAX_CIRCUITS {
            // Drop the least useful thing first: an idle circuit before a
            // stub, and the oldest of those.
            let idle = state
                .circuits
                .iter()
                .enumerate()
                .filter(|(_, c)| c.circuit.open_streams() == 0)
                .min_by_key(|(_, c)| c.built)
                .map(|(i, _)| i);
            match idle {
                Some(index) => state.circuits.remove(index).circuit.close(),
                None if !state.stubs.is_empty() => {
                    state.stubs.remove(0).circuit.close();
                }
                // Everything left is carrying traffic; let the new circuit
                // push the total one over rather than cutting a live stream.
                None => break,
            }
        }
        state.circuits.push(Pooled {
            circuit,
            exit,
            built: Instant::now(),
            first_used: used.then(Instant::now),
        });
    }

    /// Drop a circuit that turned out not to work, and close it.
    pub fn discard(&self, circuit: &Circuit) {
        let mut state = self.state.lock().unwrap();
        state
            .circuits
            .retain(|c| c.circuit.circ_id() != circuit.circ_id());
        state
            .stubs
            .retain(|s| s.circuit.circ_id() != circuit.circ_id());
        drop(state);
        circuit.close();
        self.wake.notify_all();
    }

    /// Tell the pool how many rendezvous circuits the client is holding, so
    /// they count against the same budget.
    pub fn set_onion_in_use(&self, count: usize) {
        self.state.lock().unwrap().onion_in_use = count;
    }

    /// Every circuit is built on the guard channel, so a change of guard or of
    /// consensus makes the stock stale.
    pub fn clear(&self) {
        let mut state = self.state.lock().unwrap();
        for stub in state.stubs.drain(..) {
            stub.circuit.close();
        }
        // Finished circuits carrying traffic are left alone; they are still
        // perfectly good paths, they simply will not be reused.
        state.circuits.retain(|c| c.circuit.open_streams() > 0);
        drop(state);
        self.wake.notify_all();
    }

    pub fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        self.wake.notify_all();
    }

    /// Counts for the logs and the tests: stubs, then finished circuits.
    pub fn counts(&self) -> (usize, usize) {
        let mut state = self.state.lock().unwrap();
        state.retire();
        (state.stubs.len(), state.circuits.len())
    }

    /// What the builder should do next, if anything.
    fn next_job(&self, ports: &[u16]) -> Option<Job> {
        let mut state = self.state.lock().unwrap();
        state.retire();
        if state.total() >= MAX_CIRCUITS {
            return None;
        }
        // A clean circuit first: it is what a waiting request needs, and it
        // consumes a stub, which the next pass will replace.
        let have_clean = state
            .open_for_streams()
            .any(|c| c.first_used.is_none() && ports.iter().all(|p| c.exit.exit_policy.allows(*p)));
        if !have_clean {
            return Some(Job::Clean);
        }
        if state.stubs.len() < STUB_TARGET {
            return Some(Job::Stub);
        }
        None
    }
}

/// How many streams a circuit takes before another is worth building, given
/// how many already allow the port in question.
///
/// While there are few circuits each new stream gets one of its own, because
/// that is what makes concurrent transfers add up; past the spread they share,
/// because the budget is finite and every extra circuit is another exit
/// watching this client's traffic.
fn stream_limit(allowing: usize) -> usize {
    if allowing < SPREAD_CIRCUITS {
        1
    } else {
        STREAMS_PER_CIRCUIT
    }
}

enum Job {
    Stub,
    Clean,
}

/// Start the builder thread. It holds a weak reference, so it stops by itself
/// once the client is dropped.
pub fn spawn(client: &Arc<TorClient>) {
    let weak = Arc::downgrade(client);
    let started = std::thread::Builder::new()
        .name("circuit-builder".into())
        .spawn(move || run(weak));
    if let Err(e) = started {
        crate::warn!("could not start the circuit builder: {e}");
    }
}

fn run(client: Weak<TorClient>) {
    let mut backoff = BUILD_RETRY_MIN;
    loop {
        let Some(client) = client.upgrade() else {
            return;
        };
        if client.pool().stopping.load(Ordering::Acquire) {
            return;
        }

        // Work first, then wait: the pool is empty at start-up, and a client
        // that sleeps thirty seconds before building anything has missed the
        // request it was meant to be ready for.
        let ports = client.pool().predicted_ports();
        let wait = match client.pool().next_job(&ports) {
            None => BUILDER_TICK,
            Some(job) => match build(&client, job, &ports) {
                Ok(()) => {
                    backoff = BUILD_RETRY_MIN;
                    let (stubs, circuits) = client.pool().counts();
                    crate::debug!("pool: {stubs} stubs, {circuits} circuits");
                    // There may be more to do; come straight back round.
                    Duration::from_millis(50)
                }
                Err(e) => {
                    crate::debug!("pre-building a circuit failed: {e}");
                    let delay = backoff;
                    backoff = (backoff * 2).min(BUILD_RETRY_MAX);
                    delay
                }
            },
        };

        let pool = client.pool();
        let state = pool.state.lock().unwrap();
        let _unused = pool.wake.wait_timeout(state, wait).unwrap();
        // Do not hold the client alive across the wait: dropping it here is
        // what lets the weak reference go stale when the program shuts down.
        drop(_unused);
        drop(client);
    }
}

fn build(client: &Arc<TorClient>, job: Job, ports: &[u16]) -> std::io::Result<()> {
    match job {
        Job::Stub => {
            let stub = client.build_stub()?;
            crate::debug!("stub circuit {} ready", stub.circuit.circ_id());
            client.pool().add_stub(stub);
        }
        Job::Clean => {
            let (circuit, exit) = client.build_exit_circuit(ports)?;
            crate::debug!(
                "clean circuit {} ready for ports {ports:?}",
                circuit.circ_id()
            );
            client.pool().insert(circuit, exit, false);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Predictions expire, and an empty history stands in for the web.
    #[test]
    fn predicted_ports_start_with_the_web_and_then_follow_use() {
        let pool = Pool::new();
        assert_eq!(pool.predicted_ports(), vec![80, 443]);
        pool.note_port(9418);
        assert_eq!(pool.predicted_ports(), vec![9418]);
        pool.note_port(9418);
        assert_eq!(
            pool.predicted_ports(),
            vec![9418],
            "a repeat must not duplicate the entry"
        );
        pool.note_port(22);
        let ports = pool.predicted_ports();
        assert_eq!(ports.len(), 2);
        assert!(ports.contains(&22) && ports.contains(&9418));

        // An entry older than the window is forgotten.
        {
            let mut state = pool.state.lock().unwrap();
            state.predicted[0].last = Instant::now() - PREDICTION_WINDOW - Duration::from_secs(1);
        }
        assert_eq!(pool.predicted_ports(), vec![22]);
    }

    /// Four concurrent transfers should end up on four circuits, and only
    /// then start sharing.
    #[test]
    fn streams_spread_before_they_stack() {
        // A circuit already carrying a stream is passed over while the spread
        // has room, which is what makes the caller build another.
        for allowing in 0..SPREAD_CIRCUITS {
            assert_eq!(stream_limit(allowing), 1, "with {allowing} circuits");
        }
        // Past the spread they are shared rather than multiplied.
        assert_eq!(stream_limit(SPREAD_CIRCUITS), STREAMS_PER_CIRCUIT);
        assert_eq!(stream_limit(MAX_CIRCUITS), STREAMS_PER_CIRCUIT);
        // The spread has to fit inside the budget, or it could never be
        // reached and streams would never be shared.
        const _: () = assert!(SPREAD_CIRCUITS < MAX_CIRCUITS);
    }

    /// With nothing in it the pool always has work; once stocked it has none.
    #[test]
    fn the_builder_stops_when_the_pool_is_full() {
        let pool = Pool::new();
        assert!(matches!(pool.next_job(&[80]), Some(Job::Clean)));

        // Pretend a clean circuit and two stubs exist by filling the budget.
        {
            let mut state = pool.state.lock().unwrap();
            state.onion_in_use = MAX_CIRCUITS;
        }
        assert!(
            pool.next_job(&[80]).is_none(),
            "a full budget stops the builder"
        );
    }
}
