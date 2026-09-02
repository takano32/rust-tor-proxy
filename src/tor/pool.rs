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

use super::circuit::{Circuit, Delivery};
use super::client::TorClient;
use super::dir::microdesc::Microdesc;
use super::path::PathConstraints;
use crate::ffi::rand;

/// How many two-hop stubs to keep ready. Two covers a request arriving while
/// another is being served without keeping much idle capacity around.
const STUB_TARGET: usize = 3;

/// How many circuits the builder raises at once.
///
/// Building one at a time is what actually limited the pool: a circuit takes
/// three round trips, so filling a pool serially takes a minute or more, and
/// after a guard change or a bad patch that is exactly when the circuits are
/// wanted. Kept small so that the burst stays far inside what a relay will
/// accept from one client.
const BUILD_PARALLEL: usize = 3;

/// Circuits of every kind that may exist at once.
///
/// Not bounded by this client's resources: measured, a pooled circuit costs
/// about 30kB and one thread, so scores of them would fit in the memory
/// budget. It is bounded by the network's. A relay limits circuit creation per
/// client address (dos-spec, `DoSCircuit*`; C Tor's defaults are three per
/// second with a burst of ninety, and an hour's refusal past that), and every
/// circuit here is three relays holding state for one client. A pool this size
/// rebuilds at a fraction of a circuit per second even as circuits age out.
pub const MAX_CIRCUITS: usize = 16;

/// How many circuits concurrent streams spread across before they start
/// sharing one. Each circuit gets its own thousand-cell window, so a parallel
/// download goes about as many times faster as it has circuits -- and this is
/// the number that decides how many exits see the traffic at once, which is
/// why it is a small constant and not the whole budget.
const SPREAD_CIRCUITS: usize = 4;

/// How many finished circuits to keep ready for the ports this client uses.
///
/// More than one so that a request has a choice: a circuit is picked at random
/// from those that have not proved bad, which spreads load, keeps one unlucky
/// path from serving everything, and gives a bad one somewhere to be replaced
/// from at once.
const CLEAN_TARGET: usize = 6;

/// A circuit that has delivered at least this much, over at least this much
/// time actually spent receiving, has been measured; less than that and the
/// figure is the congestion window still opening rather than the path's
/// capacity.
const MEASURE_MIN_BYTES: u64 = 1 << 20;
const MEASURE_MIN_ACTIVE_MS: u64 = 2_000;

/// Below this, a measured circuit is thrown away rather than used again.
///
/// This is an absolute floor, not a ranking. Measured on the live network a
/// working path delivers 400-1100 KB/s and a hopeless one 0-200, so the two
/// populations separate cleanly and a fixed threshold can sit between them.
/// A floor also refuses an adversary the gradient a ranking would offer: a
/// relay gains nothing by being marginally quicker than its neighbours, only
/// by not being unusable.
const FLOOR_KBPS: u64 = 150;

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
    /// Which guard it starts at, carried forward onto the finished circuit.
    pub guard: [u8; 20],
    built: Instant,
}

impl Stub {
    pub fn new(circuit: Circuit, constraints: PathConstraints, guard: [u8; 20]) -> Self {
        Self {
            circuit,
            constraints,
            guard,
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
    /// The guard this circuit was built on, so a guard whose circuits keep
    /// turning out bad can be held responsible.
    guard: [u8; 20],
    /// Whether this circuit has already been counted against its guard. A
    /// circuit kept alive for its streams is swept repeatedly, and each one
    /// must be worth exactly one strike.
    blamed: bool,
    built: Instant,
    /// When the first stream was attached. `None` means still clean.
    first_used: Option<Instant>,
}

/// Why a circuit is no longer wanted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// Still wanted.
    Keep,
    /// Old, closed, or past its dirty age. Nothing to do with performance.
    Expired,
    /// Measured, and too slow to be worth using again.
    TooSlow(u64),
    /// Asked a question it had to answer, and did not.
    Unresponsive,
}

impl Verdict {
    /// Whether this verdict is a judgement on the path rather than the clock.
    pub fn blames_the_path(&self) -> bool {
        matches!(self, Self::TooSlow(_) | Self::Unresponsive)
    }
}

/// Judge a circuit from what it has delivered.
///
/// Split out from [`Pooled`] so it can be tested without a network: everything
/// it needs is three numbers.
fn judge(delivery: Delivery) -> Verdict {
    match delivery.kbps(MEASURE_MIN_BYTES, MEASURE_MIN_ACTIVE_MS) {
        Some(kbps) if kbps < FLOOR_KBPS => Verdict::TooSlow(kbps),
        _ => Verdict::Keep,
    }
}

impl Pooled {
    /// Why this circuit should go, if it should.
    fn verdict(&self) -> Verdict {
        if self.circuit.is_closed() || self.built.elapsed() >= MAX_IDLE_AGE {
            return Verdict::Expired;
        }
        if self
            .first_used
            .is_some_and(|at| at.elapsed() >= MAX_DIRTY_AGE)
        {
            return Verdict::Expired;
        }
        judge(self.circuit.delivery())
    }

    fn usable(&self) -> bool {
        self.verdict() == Verdict::Keep
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
    /// Circuits dropped for being too slow, waiting to be counted against
    /// their guard.
    ///
    /// Held here rather than returned, because `retire` is called from six
    /// places and five of them have no interest in the answer -- returning it
    /// meant five of them silently threw the evidence away.
    blamed: Vec<([u8; 20], Verdict)>,
}

impl State {
    /// Drop what is no longer wanted.
    ///
    /// Circuits judged too slow are recorded in `blamed` for the guard
    /// accounting, and any circuit that should be closed is handed back rather
    /// than closed here: `Circuit::close` sends a DESTROY, which can block on
    /// the channel's outbound queue, and blocking there with the pool lock
    /// held would stop every other request in the process.
    fn retire(&mut self) -> Vec<Circuit> {
        let mut closing = Vec::new();

        self.stubs.retain(|s| {
            let keep = s.usable();
            if !keep {
                closing.push(s.circuit.clone());
            }
            keep
        });

        let blamed = &mut self.blamed;
        self.circuits.retain(|c| {
            let verdict = c.verdict();
            if verdict == Verdict::Keep {
                return true;
            }
            if verdict.blames_the_path() {
                if !c.blamed {
                    crate::info!(
                        "circuit {} dropped: {}",
                        c.circuit.circ_id(),
                        match verdict {
                            Verdict::TooSlow(kbps) =>
                                format!("only {kbps} KB/s, below the {FLOOR_KBPS} KB/s floor"),
                            Verdict::Unresponsive => "it answered nothing".to_string(),
                            _ => String::new(),
                        }
                    );
                    if blamed.len() < MAX_PENDING_BLAME {
                        blamed.push((c.guard, verdict));
                    }
                }
                // A stream cannot be moved to another circuit once it is
                // running -- Tor has no way to resume one elsewhere -- so
                // "switch to a better path" can only ever mean the *next*
                // request, which dropping it from the pool already achieves.
                // Closing it would break a transfer that is slow but working,
                // and the same numbers appear when it is the origin server
                // that is slow rather than the path.
                if c.circuit.open_streams() == 0 {
                    closing.push(c.circuit.clone());
                    return false;
                }
                return true;
            }
            // Merely expired: leave it alone until its streams finish, and
            // only keep new ones off it.
            if c.circuit.open_streams() == 0 {
                closing.push(c.circuit.clone());
                return false;
            }
            true
        });

        // Once blamed, a circuit must not be blamed again on the next sweep.
        for c in self.circuits.iter_mut() {
            if c.verdict().blames_the_path() {
                c.blamed = true;
            }
        }

        self.predicted
            .retain(|p| p.last.elapsed() < PREDICTION_WINDOW);
        closing
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

/// Close circuits the pool has finished with, having let go of its lock.
///
/// `Circuit::close` sends a DESTROY cell, and that can block waiting for room
/// in the channel's outbound queue. Doing it under the pool lock would stop
/// every other request in the process behind one slow socket.
fn close_all(circuits: Vec<Circuit>) {
    for circuit in circuits {
        circuit.close();
    }
}

/// Cap on unread blame, so a guard nobody asks about cannot grow the list.
const MAX_PENDING_BLAME: usize = 64;

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
        let closing = state.retire();
        let ports = if state.predicted.is_empty() {
            DEFAULT_PORTS.to_vec()
        } else {
            state.predicted.iter().map(|p| p.port).collect()
        };
        drop(state);
        close_all(closing);
        ports
    }

    /// A live circuit whose exit allows `port`, drawn at random from the
    /// least-loaded of those that have not proved bad.
    ///
    /// Random rather than "the fastest": a ranking would give a relay a reason
    /// to look quick, and this project's own measurements say the ranking
    /// would be noise anyway -- neither round trip nor consensus bandwidth
    /// predicts throughput. What the measurements do support is throwing out
    /// the hopeless, which `retire` has already done by the time we get here.
    /// Among what is left, spreading the choice keeps one path from carrying
    /// everything.
    ///
    /// Returns `None` when a new circuit would be better: either none allows
    /// the port, or every one that does is already carrying enough streams and
    /// there is room in the budget for another.
    pub fn circuit_for(&self, port: u16) -> Option<Circuit> {
        let mut state = self.state.lock().unwrap();
        let closing = state.retire();
        let room = state.total() < MAX_CIRCUITS;

        // One pass, not two. `usable()` and `open_streams()` both read state
        // that other threads change without this lock, so a second pass could
        // disagree with the first -- and a candidate list that came back empty
        // after a non-empty minimum would index out of bounds.
        let mut usable: Vec<(usize, usize)> = Vec::new();
        for (index, c) in state.circuits.iter().enumerate() {
            if c.usable() && c.exit.exit_policy.allows(port) {
                usable.push((index, c.circuit.open_streams()));
            }
        }
        let Some(fewest) = usable.iter().map(|(_, n)| *n).min() else {
            drop(state);
            close_all(closing);
            return None;
        };
        if fewest >= stream_limit(usable.len()) && room {
            drop(state);
            close_all(closing);
            return None;
        }

        let candidates: Vec<usize> = usable
            .iter()
            .filter(|(_, n)| *n == fewest)
            .map(|(i, _)| *i)
            .collect();
        // Non-empty by construction: `fewest` came from this same list.
        let pick = match rand::below(candidates.len() as u64) {
            Ok(n) => candidates[n as usize],
            // Without randomness any of them will do; they are equally loaded.
            Err(_) => candidates[0],
        };
        let chosen = &mut state.circuits[pick];
        chosen.first_used.get_or_insert_with(Instant::now);
        let circuit = chosen.circuit.clone();
        drop(state);
        close_all(closing);
        // Taking a circuit may have left the pool short of a clean one.
        self.wake.notify_all();
        Some(circuit)
    }

    /// Circuits with a reader that has been waiting long enough to be worth
    /// testing.
    pub fn wanting_probe(&self) -> Vec<Circuit> {
        let state = self.state.lock().unwrap();
        state
            .circuits
            .iter()
            .filter(|c| c.circuit.wants_probe())
            .map(|c| c.circuit.clone())
            .collect()
    }

    /// Throw a circuit out because it failed its liveness probe, and count it
    /// against its guard.
    pub fn condemn(&self, circuit: &Circuit) {
        let mut state = self.state.lock().unwrap();
        if let Some(index) = state
            .circuits
            .iter()
            .position(|c| c.circuit.circ_id() == circuit.circ_id())
        {
            let dead = state.circuits.remove(index);
            if !dead.blamed && state.blamed.len() < MAX_PENDING_BLAME {
                state.blamed.push((dead.guard, Verdict::Unresponsive));
            }
        }
        drop(state);
        // A circuit that answers nothing has nothing to preserve: closing it
        // turns an indefinite hang into an error its streams can see.
        circuit.close();
        self.wake.notify_all();
    }

    /// Take the accumulated "this path was too slow" reports, for the guard
    /// accounting.
    pub fn take_blame(&self) -> Vec<([u8; 20], Verdict)> {
        std::mem::take(&mut self.state.lock().unwrap().blamed)
    }

    /// Take a stub the caller can extend, if one is compatible with the hop it
    /// has in mind.
    pub fn take_stub(&self, fits: &dyn Fn(&PathConstraints) -> bool) -> Option<Stub> {
        let mut state = self.state.lock().unwrap();
        let closing = state.retire();
        let index = state.stubs.iter().position(|stub| fits(&stub.constraints));
        let stub = index.map(|index| state.stubs.remove(index));
        drop(state);
        close_all(closing);
        self.wake.notify_all();
        stub
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
    pub fn insert(&self, circuit: Circuit, exit: Arc<Microdesc>, guard: [u8; 20], used: bool) {
        let mut state = self.state.lock().unwrap();
        let mut closing = state.retire();
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
                Some(index) => closing.push(state.circuits.remove(index).circuit),
                None if !state.stubs.is_empty() => {
                    closing.push(state.stubs.remove(0).circuit);
                }
                // Everything left is carrying traffic; let the new circuit
                // push the total one over rather than cutting a live stream.
                None => break,
            }
        }
        state.circuits.push(Pooled {
            circuit,
            exit,
            guard,
            blamed: false,
            built: Instant::now(),
            first_used: used.then(Instant::now),
        });
        drop(state);
        close_all(closing);
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
        let closing = state.retire();
        let counts = (state.stubs.len(), state.circuits.len());
        drop(state);
        close_all(closing);
        counts
    }

    /// What the builder should do next, up to `limit` jobs at once.
    ///
    /// Counts the work the pool is short of rather than returning one job at a
    /// time, so the builder can raise several circuits in parallel; the total
    /// is still bounded by `MAX_CIRCUITS`, including whatever is already in
    /// flight.
    fn next_jobs(&self, ports: &[u16], limit: usize) -> Vec<Job> {
        let mut jobs = Vec::new();
        let mut budget = match self.next_job(ports) {
            None => return jobs,
            Some(first) => {
                jobs.push(first);
                1
            }
        };
        let state = self.state.lock().unwrap();
        let clean = state
            .open_for_streams()
            .filter(|c| {
                c.first_used.is_none() && ports.iter().all(|p| c.exit.exit_policy.allows(*p))
            })
            .count();
        let mut clean_short = CLEAN_TARGET.saturating_sub(clean + 1);
        let mut stubs_short = STUB_TARGET.saturating_sub(state.stubs.len());
        let room = MAX_CIRCUITS.saturating_sub(state.total() + 1);
        drop(state);

        while budget < limit && jobs.len() < room + 1 && (clean_short > 0 || stubs_short > 0) {
            // Alternate, so neither kind starves the other.
            if stubs_short > 0 {
                jobs.push(Job::Stub);
                stubs_short -= 1;
            } else {
                jobs.push(Job::Clean);
                clean_short -= 1;
            }
            budget += 1;
        }
        jobs
    }

    /// The single most useful thing to build next, if anything.
    fn next_job(&self, ports: &[u16]) -> Option<Job> {
        let mut state = self.state.lock().unwrap();
        let closing = state.retire();
        drop(state);
        close_all(closing);

        let state = self.state.lock().unwrap();
        if state.total() >= MAX_CIRCUITS {
            return None;
        }
        let clean = state
            .open_for_streams()
            .filter(|c| {
                c.first_used.is_none() && ports.iter().all(|p| c.exit.exit_policy.allows(*p))
            })
            .count();

        // One clean circuit first -- that is what a waiting request needs --
        // and then a stub, before stocking up further. Filling the clean
        // target first would leave directory, introduction and rendezvous
        // circuits with no stub to extend, which is the case stubs help most:
        // an onion connection needs three circuits to a named last hop.
        if clean == 0 {
            return Some(Job::Clean);
        }
        if state.stubs.is_empty() {
            return Some(Job::Stub);
        }
        if clean < CLEAN_TARGET {
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
        let jobs = client.pool().next_jobs(&ports, BUILD_PARALLEL);
        let wait = if jobs.is_empty() {
            BUILDER_TICK
        } else {
            // Several at once: each is three round trips, and doing them one
            // after another is what kept the pool thin.
            let results: Vec<std::io::Result<()>> = std::thread::scope(|scope| {
                let handles: Vec<_> = jobs
                    .into_iter()
                    .map(|job| scope.spawn(|| build(&client, job, &ports)))
                    .collect();
                handles
                    .into_iter()
                    .map(|h| {
                        h.join().unwrap_or_else(|_| {
                            Err(std::io::Error::other("builder thread panicked"))
                        })
                    })
                    .collect()
            });
            if results.iter().any(|r| r.is_ok()) {
                backoff = BUILD_RETRY_MIN;
                let (stubs, circuits) = client.pool().counts();
                crate::debug!("pool: {stubs} stubs, {circuits} circuits");
                // There may be more to do; come straight back round.
                Duration::from_millis(50)
            } else {
                for e in results.iter().filter_map(|r| r.as_ref().err()) {
                    crate::debug!("pre-building a circuit failed: {e}");
                }
                let delay = backoff;
                backoff = (backoff * 2).min(BUILD_RETRY_MAX);
                delay
            }
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
            let (circuit, exit, guard) = client.build_exit_circuit(ports)?;
            crate::debug!(
                "clean circuit {} ready for ports {ports:?}",
                circuit.circ_id()
            );
            client.pool().insert(circuit, exit, guard, false);
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

    fn delivered(bytes: u64, active_ms: u64) -> Delivery {
        Delivery { bytes, active_ms }
    }

    /// A circuit is judged on what it delivered, and only once it has
    /// delivered enough for the figure to mean anything.
    #[test]
    fn a_circuit_is_judged_only_once_it_has_carried_something() {
        // A brand new circuit has no verdict against it.
        assert_eq!(judge(delivered(0, 0)), Verdict::Keep);
        // Nor has one that has carried a little: below the floor the number is
        // the congestion window opening, not the path. This is the trap a
        // cheap threshold would fall into -- a second transfer on a warm
        // circuit measured 1.7x the first.
        assert_eq!(
            judge(delivered(200 << 10, 8_000)),
            Verdict::Keep,
            "200kB at 25 KB/s must not condemn a circuit that is still ramping"
        );
        // Once it has carried a megabyte over a couple of seconds, a rate
        // below the floor is a real verdict.
        let slow = delivered(2 << 20, 30_000);
        assert_eq!(
            slow.kbps(MEASURE_MIN_BYTES, MEASURE_MIN_ACTIVE_MS),
            Some(69)
        );
        assert_eq!(judge(slow), Verdict::TooSlow(69));
        // And a working one is kept.
        let fine = delivered(8 << 20, 16_000);
        assert_eq!(judge(fine), Verdict::Keep);
        assert!(fine.kbps(MEASURE_MIN_BYTES, MEASURE_MIN_ACTIVE_MS).unwrap() > FLOOR_KBPS);
    }

    /// The measurement is of time spent receiving, not of the clock. A
    /// circuit reused across a browsing session is idle for most of its life,
    /// and judging it on wall-clock would condemn every one of them.
    #[test]
    fn idle_time_between_transfers_is_not_counted_against_a_circuit() {
        // 8MB carried in 16 seconds of actual transfer, sitting idle for the
        // ten minutes a circuit is allowed to live.
        let busy = delivered(8 << 20, 16_000);
        assert_eq!(judge(busy), Verdict::Keep);
        // The same bytes measured against wall-clock would be 14 KB/s and
        // would be thrown out; `active_ms` is what stops that.
        let against_the_clock = (8u64 << 20) / 600_000;
        assert!(against_the_clock < FLOOR_KBPS);
    }

    /// Only a judgement about the path counts against the guard; expiry and
    /// old age say nothing about anyone.
    #[test]
    fn only_performance_verdicts_blame_the_guard() {
        assert!(Verdict::TooSlow(10).blames_the_path());
        assert!(Verdict::Unresponsive.blames_the_path());
        assert!(!Verdict::Expired.blames_the_path());
        assert!(!Verdict::Keep.blames_the_path());
    }

    /// The floor has to sit between the two populations the measurements
    /// found, or it is either useless or a ranking in disguise.
    #[test]
    fn the_floor_separates_hopeless_from_working() {
        // Measured: hopeless circuits delivered 0-200 KB/s, working ones
        // 400-1100. Everything at or above 400 must survive; the clearly
        // hopeless must not.
        for kbps in [0u64, 68, 136] {
            let bytes = 8u64 << 20;
            // A byte per millisecond is a kilobyte per second, so the active
            // time for a given rate is just bytes / rate; a rate of zero means
            // a transfer that never finished, standing in as a long one.
            let active = bytes.checked_div(kbps).unwrap_or(60_000);
            let d = delivered(bytes, active);
            assert!(
                matches!(judge(d), Verdict::TooSlow(_)),
                "{kbps} KB/s should be refused"
            );
        }
        for kbps in [400u64, 500, 1100] {
            let bytes = 8u64 << 20;
            let d = delivered(bytes, bytes / kbps);
            assert_eq!(judge(d), Verdict::Keep, "{kbps} KB/s should be kept");
        }
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
