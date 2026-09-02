//! Client-side congestion control: proposal 324, `cc_alg=2` (Tor Vegas).
//!
//! A circuit negotiates congestion control with its terminating hop only --
//! the exit, or the onion service at the far end of a rendezvous circuit --
//! so this state machine exists only for a circuit that got a positive
//! answer; the others keep the fixed 100-cell windows. Nothing here does any
//! I/O. The sending side is asked whether a cell may go out, and told when
//! one went out and when a SENDME came back; the receiving side is a
//! counter. Every method that needs a clock is handed one, which is what
//! makes the algorithm testable without a network.
//!
//! Section numbers in the comments below refer to
//! `proposals/324-rtt-congestion-control.txt`.

// Nothing outside this module drives the state machine yet -- wiring it into
// `circuit.rs` is the rest of M19 -- so the binary target would otherwise
// warn about every item here. Drop this once a circuit constructs a `Vegas`.
use std::collections::VecDeque;
use std::io;
use std::time::Instant;

use crate::util::invalid_data;

/// The relay outbuf size C tor's tuning is expressed in (§6.5.3). It only
/// appears here to keep the derivation of the Vegas defaults visible.
const OUTBUF_CELLS: u32 = 62;

/// `INT32_MAX`, which several parameters use as their upper bound.
const INT32_MAX: u32 = 2_147_483_647;

/// Ratio between a new RTT sample and the smoothed one beyond which
/// [CLOCK_HEURISTICS] (§2.1.1) calls the clock broken rather than the
/// network slow.
const CLOCK_JUMP_RATIO: u64 = 5000;

/// Which parameter set applies: exits and onion services are tuned apart.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Position {
    Exit,
    Onion,
}

impl Position {
    /// The suffix the consensus uses for this position's copy of a
    /// parameter.
    fn suffix(self) -> &'static str {
        match self {
            Position::Exit => "_exit",
            Position::Onion => "_onion",
        }
    }
}

/// The `cc_*` consensus parameters, already resolved for one position.
///
/// Ranges and defaults are from proposal 324 §6.5, which is the only
/// normative source for them: the published `param-spec.md` does not list
/// the `cc_*` parameters at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CcParams {
    /// `cc_alg`: 0 disables congestion control, 2 selects Vegas. Range
    /// {0, 2}, default 2. Not used by the state machine itself -- the caller
    /// reads it to decide whether to ask for congestion control at all
    /// (§10.1).
    pub alg: u8,
    /// `cc_sendme_inc`: how many cells one SENDME acknowledges. Range
    /// [1, 254], default 31. This is only the value we offer, and the one a
    /// descriptor is checked against; the value a circuit runs on is the
    /// negotiated one handed to [`Vegas::new`].
    pub sendme_inc: u8,
    /// `cc_cwnd_init`: the window a circuit starts with. Range [31, 10000],
    /// default 4*31.
    pub cwnd_init: u32,
    /// `cc_cwnd_min`: the smallest window Vegas may settle on. Range
    /// [31, 1000], default 31.
    pub cwnd_min: u32,
    /// `cc_cwnd_max`: the largest. Range [500, INT32_MAX], default
    /// INT32_MAX.
    pub cwnd_max: u32,
    /// `cc_cwnd_inc`: the steady-state step. Range [1, 1000], default 31.
    pub cwnd_inc: u32,
    /// `cc_cwnd_inc_rate`: how many times per window the steady-state rules
    /// run. Range [1, 250], default 1.
    pub cwnd_inc_rate: u32,
    /// `cc_cwnd_inc_pct_ss`: slow-start growth, as a percentage of one
    /// increment per ack. Range [1, 500], default 50.
    pub cwnd_inc_pct_ss: u32,
    /// `cc_ewma_cwnd_pct`: the N of the RTT smoothing, as a percentage of
    /// the acks in one window. Range [1, 255], default 50.
    pub ewma_cwnd_pct: u32,
    /// `cc_ewma_max`: cap on that N. Range [2, INT32_MAX], default 10.
    pub ewma_max: u32,
    /// `cc_ewma_ss`: the N used during slow start. Range [2, INT32_MAX],
    /// default 2.
    pub ewma_ss: u32,
    /// `cc_rtt_reset_pct`: how much of `RTT_min` the current smoothed RTT
    /// replaces when the window bottoms out. Range [0, 100], default 100.
    pub rtt_reset_pct: u32,
    /// `cc_vegas_alpha_{exit,onion}`: below this queue estimate the window
    /// may grow. Range [0, 1000], default 3*62.
    pub vegas_alpha: u32,
    /// `cc_vegas_beta_{exit,onion}`: above this queue estimate the window
    /// shrinks. Range [0, 1000], defaults 4*62 (exit) and 6*62 (onion).
    pub vegas_beta: u32,
    /// `cc_vegas_gamma_{exit,onion}`: the queue estimate that ends slow
    /// start. Range [0, 1000], defaults 3*62 (exit) and 4*62 (onion).
    pub vegas_gamma: u32,
    /// `cc_vegas_delta_{exit,onion}`: the queue estimate that forces the
    /// window straight back onto the BDP. Range [0, INT32_MAX], defaults
    /// 5*62 (exit) and 7*62 (onion).
    pub vegas_delta: u32,
    /// `cc_sscap_{exit,onion}`: the RFC3742 cap past which slow start slows
    /// down. Range [100, INT32_MAX], defaults 600 (exit) and 475 (onion).
    pub ss_cap: u32,
    /// `cc_ss_max`: a hard ceiling on the window during slow start. Range
    /// [500, INT32_MAX], default 5000.
    pub ss_max: u32,
    /// `cc_cwnd_full_gap`: how many increments the outstanding cells may
    /// fall short of the window and still count as filling it. Range
    /// [0, INT16_MAX], default 4.
    pub cwnd_full_gap: u32,
    /// `cc_cwnd_full_minpct`: below this percentage of the window, the
    /// window is immediately declared not full. Range [0, 100], default 25.
    pub cwnd_full_minpct: u32,
    /// `cc_cwnd_full_per_cwnd`: whether the window has to be filled once per
    /// window (true) or once per update (false). Default true.
    pub cwnd_full_per_cwnd: bool,
    /// `cc_xoff_client`: how many cells' worth of data may pile up unread for
    /// one stream before its far end is asked to stop (§6.5.5). Range
    /// [1, 10000], default 500. Congestion control acknowledges circuit cells
    /// as soon as they are decrypted, so this, rather than a stream window, is
    /// what stops a slow reader being flooded.
    pub xoff_client: u32,
}

impl CcParams {
    /// The defaults from proposal 324 §6.5.
    pub fn defaults(position: Position) -> Self {
        let (beta, gamma, delta, ss_cap) = match position {
            // §6.5.3, in multiples of OUTBUF_CELLS.
            Position::Exit => (4, 3, 5, 600),
            // An onion service circuit is more than twice as long, so it is
            // allowed more outbuf delay before Vegas reacts.
            Position::Onion => (6, 4, 7, 475),
        };
        Self {
            alg: 2,
            sendme_inc: 31,
            cwnd_init: 4 * 31,
            cwnd_min: 31,
            cwnd_max: INT32_MAX,
            cwnd_inc: 31,
            cwnd_inc_rate: 1,
            cwnd_inc_pct_ss: 50,
            ewma_cwnd_pct: 50,
            ewma_max: 10,
            ewma_ss: 2,
            rtt_reset_pct: 100,
            vegas_alpha: 3 * OUTBUF_CELLS,
            vegas_beta: beta * OUTBUF_CELLS,
            vegas_gamma: gamma * OUTBUF_CELLS,
            vegas_delta: delta * OUTBUF_CELLS,
            ss_cap,
            ss_max: 5000,
            cwnd_full_gap: 4,
            cwnd_full_minpct: 25,
            cwnd_full_per_cwnd: true,
            xoff_client: 500,
        }
    }

    /// Parse a consensus `params` line for one position, keeping the default
    /// for anything absent, unparsable or outside the range the proposal
    /// allows -- the policy `consensus::Params::parse` already uses.
    pub fn parse(args: &str, position: Position) -> Self {
        let mut out = Self::defaults(position);
        let mine = position.suffix();
        for field in args.split_whitespace() {
            let Some((key, value)) = field.split_once('=') else {
                continue;
            };
            // The Vegas thresholds and the slow-start cap come in three
            // flavours, `_exit`, `_onion` and `_sbws`. Reduce ours to the
            // bare name and drop the other positions' copies, so a circuit
            // can never pick up the wrong tuning.
            let key = match strip_position(key) {
                Some((stem, suffix)) if suffix == mine => stem,
                Some(_) => continue,
                None => key,
            };
            match key {
                // Only 0 and 2 are defined; Westwood (1) and NOLA (3) were
                // removed, so anything else falls back to the default like
                // any other out-of-range value.
                "cc_alg" => {
                    if let Some(v) = value.parse().ok().filter(|v| *v == 0 || *v == 2) {
                        out.alg = v;
                    }
                }
                "cc_sendme_inc" => {
                    if let Some(v) = bounded(value, 1, 254) {
                        out.sendme_inc = v;
                    }
                }
                // Only the client's own limit matters here: we are always the
                // client edge, never the exit's.
                "cc_xoff_client" => {
                    if let Some(v) = bounded(value, 1, 10_000) {
                        out.xoff_client = v;
                    }
                }
                "cc_cwnd_init" => {
                    if let Some(v) = bounded(value, 31, 10_000) {
                        out.cwnd_init = v;
                    }
                }
                "cc_cwnd_min" => {
                    if let Some(v) = bounded(value, 31, 1000) {
                        out.cwnd_min = v;
                    }
                }
                "cc_cwnd_max" => {
                    if let Some(v) = bounded(value, 500, INT32_MAX) {
                        out.cwnd_max = v;
                    }
                }
                "cc_cwnd_inc" => {
                    if let Some(v) = bounded(value, 1, 1000) {
                        out.cwnd_inc = v;
                    }
                }
                "cc_cwnd_inc_rate" => {
                    if let Some(v) = bounded(value, 1, 250) {
                        out.cwnd_inc_rate = v;
                    }
                }
                "cc_cwnd_inc_pct_ss" => {
                    if let Some(v) = bounded(value, 1, 500) {
                        out.cwnd_inc_pct_ss = v;
                    }
                }
                "cc_ewma_cwnd_pct" => {
                    if let Some(v) = bounded(value, 1, 255) {
                        out.ewma_cwnd_pct = v;
                    }
                }
                "cc_ewma_max" => {
                    if let Some(v) = bounded(value, 2, INT32_MAX) {
                        out.ewma_max = v;
                    }
                }
                "cc_ewma_ss" => {
                    if let Some(v) = bounded(value, 2, INT32_MAX) {
                        out.ewma_ss = v;
                    }
                }
                "cc_rtt_reset_pct" => {
                    if let Some(v) = bounded(value, 0, 100) {
                        out.rtt_reset_pct = v;
                    }
                }
                "cc_vegas_alpha" => {
                    if let Some(v) = bounded(value, 0, 1000) {
                        out.vegas_alpha = v;
                    }
                }
                "cc_vegas_beta" => {
                    if let Some(v) = bounded(value, 0, 1000) {
                        out.vegas_beta = v;
                    }
                }
                "cc_vegas_gamma" => {
                    if let Some(v) = bounded(value, 0, 1000) {
                        out.vegas_gamma = v;
                    }
                }
                "cc_vegas_delta" => {
                    if let Some(v) = bounded(value, 0, INT32_MAX) {
                        out.vegas_delta = v;
                    }
                }
                "cc_sscap" => {
                    if let Some(v) = bounded(value, 100, INT32_MAX) {
                        out.ss_cap = v;
                    }
                }
                "cc_ss_max" => {
                    if let Some(v) = bounded(value, 500, INT32_MAX) {
                        out.ss_max = v;
                    }
                }
                "cc_cwnd_full_gap" => {
                    if let Some(v) = bounded(value, 0, 32_767) {
                        out.cwnd_full_gap = v;
                    }
                }
                "cc_cwnd_full_minpct" => {
                    if let Some(v) = bounded(value, 0, 100) {
                        out.cwnd_full_minpct = v;
                    }
                }
                "cc_cwnd_full_per_cwnd" => {
                    if let Some(v) = bounded::<u32>(value, 0, 1) {
                        out.cwnd_full_per_cwnd = v == 1;
                    }
                }
                _ => {}
            }
        }
        out
    }
}

/// Split a `_exit` / `_onion` / `_sbws` suffix off a parameter name.
fn strip_position(key: &str) -> Option<(&str, &str)> {
    for suffix in ["_exit", "_onion", "_sbws"] {
        if let Some(stem) = key.strip_suffix(suffix) {
            return Some((stem, suffix));
        }
    }
    None
}

/// Parse a value, keeping it only if it lands inside the spec's range.
fn bounded<T: std::str::FromStr + PartialOrd>(value: &str, low: T, high: T) -> Option<T> {
    value.parse().ok().filter(|v| *v >= low && *v <= high)
}

/// The sending half of congestion control for one circuit: Tor Vegas over a
/// window of cells that have been sent but not yet acknowledged.
pub struct Vegas {
    params: CcParams,
    /// The negotiated increment. Held as a `u32` because nearly every
    /// expression multiplies it; it is never zero, so it is always safe to
    /// divide by.
    sendme_inc: u32,
    cwnd: u32,
    /// Cells handed to the channel, and cells a SENDME has acknowledged.
    /// Both only ever move forward, and `acked` only ever moves behind
    /// `sent`, so `inflight` is their difference and can never go negative.
    sent: u64,
    acked: u64,
    in_slow_start: bool,
    /// Whether the window was seen full during the current period.
    cwnd_full: bool,
    /// Acks left before the steady-state rules run, and before the current
    /// window's worth of acks is over (§3.3).
    next_cc_event: u32,
    next_cwnd_event: u32,
    /// Send times of the cells that will make the far end emit a SENDME,
    /// oldest first. It holds one entry per increment of outstanding cells,
    /// so the window bounds it.
    marks: VecDeque<Instant>,
    /// Smoothed and smallest round trip, in microseconds. Zero means "not
    /// measured yet", which is unambiguous because a zero sample is treated
    /// as a stalled clock and thrown away.
    ewma_rtt_us: u64,
    min_rtt_us: u64,
    /// The congestion-window BDP estimator of §3.1.2, in cells.
    bdp: u32,
    /// Sticky "this clock has stalled before" flag from §2.1.1. C tor keeps
    /// it globally; per circuit is both simpler and deterministic, and the
    /// two differ only on a machine whose clock is already broken.
    clock_broken: bool,
}

impl Vegas {
    /// Start congestion control for a circuit that negotiated `sendme_inc`
    /// with its terminating hop.
    pub fn new(params: CcParams, sendme_inc: u8) -> Self {
        // Negotiation constrains this to [1, 254]; a zero would only mean a
        // division by zero further down, so refuse to believe it.
        let sendme_inc = sendme_inc.max(1) as u32;
        let mut vegas = Self {
            params,
            sendme_inc,
            cwnd: 0,
            sent: 0,
            acked: 0,
            in_slow_start: true,
            cwnd_full: false,
            next_cc_event: 0,
            next_cwnd_event: 0,
            marks: VecDeque::new(),
            ewma_rtt_us: 0,
            min_rtt_us: 0,
            bdp: 0,
            clock_broken: false,
        };
        vegas.cwnd = vegas.clamp_cwnd(params.cwnd_init);
        vegas.next_cc_event = vegas.cwnd_update_rate();
        vegas.next_cwnd_event = vegas.sendme_per_cwnd();
        vegas
    }

    pub fn sendme_inc(&self) -> u8 {
        // Set from a `u8` in `new`, so this cannot truncate.
        self.sendme_inc as u8
    }

    pub fn cwnd(&self) -> u32 {
        self.cwnd
    }

    pub fn inflight(&self) -> u32 {
        // `saturating_sub` rather than `-`: `on_sendme` is what enforces
        // that `acked` never passes `sent`, and a bug elsewhere should not
        // become a panic in the middle of a circuit's flow control.
        self.sent.saturating_sub(self.acked).min(u32::MAX as u64) as u32
    }

    /// May another data cell go out right now? §3 requires that cells stop
    /// when `cwnd - inflight <= 0`.
    pub fn can_send(&self) -> bool {
        self.inflight() < self.cwnd
    }

    /// One data cell was just handed to the channel.
    pub fn on_send(&mut self, now: Instant) {
        self.sent += 1;
        // §2.1: the cell whose sequence number is a multiple of the
        // increment is the one that will make the far end answer with a
        // SENDME, so its send time is what that SENDME is measured against.
        if self.sent.is_multiple_of(self.sendme_inc as u64) {
            self.marks.push_back(now);
        }
    }

    /// A circuit-level SENDME arrived. Errors only on a protocol violation
    /// (more SENDMEs than cells sent), which the caller turns into a closed
    /// circuit.
    pub fn on_sendme(&mut self, now: Instant) -> io::Result<()> {
        // One SENDME acknowledges exactly one increment. Fewer cells than
        // that outstanding means the far end is acknowledging cells we never
        // sent; this check is also what keeps `acked` from passing `sent`,
        // so `sent - acked` is the one subtraction here that cannot go
        // negative. It is written saturating anyway, so that a future caller
        // cannot turn a mistake into a panic.
        if self.sent.saturating_sub(self.acked) < self.sendme_inc as u64 {
            return Err(invalid_data(
                "SENDME acknowledged cells that were never sent",
            ));
        }

        // The two period counters run down first, as in the §3.3
        // pseudocode: they tick even on an ack whose RTT we end up throwing
        // away.
        self.next_cc_event = self.next_cc_event.saturating_sub(1);
        self.next_cwnd_event = self.next_cwnd_event.saturating_sub(1);

        let usable = match self.marks.pop_front() {
            Some(sent_at) => match now.checked_duration_since(sent_at) {
                // Microseconds, as §2.1.1 measures them. The clamp only
                // matters for a clock that jumped by half a million years,
                // and that sample is discarded a line later anyway.
                Some(delta) => self.update_rtt(delta.as_micros().min(u64::MAX as u128) as u64),
                // `Instant` promises to be monotonic, but a platform whose
                // clock goes backwards must not produce a negative RTT:
                // treat it as a stall and skip the round.
                None => {
                    self.clock_broken = true;
                    false
                }
            },
            // Unreachable while a whole increment is outstanding, but with
            // nothing to measure there is nothing to update either.
            None => false,
        };

        if usable {
            self.vegas_update();
        }
        self.acked += self.sendme_inc as u64;
        Ok(())
    }

    /// Fold one RTT sample into the smoothed estimate and recompute the BDP.
    /// Returns false when [CLOCK_HEURISTICS] (§2.1.1) says the sample is not
    /// a measurement of the network, in which case the whole ack is skipped.
    fn update_rtt(&mut self, rtt_us: u64) -> bool {
        // A zero delta is always a stalled clock, and the fact is
        // remembered: a later absurdly small RTT is only believable as a
        // stall if the clock has stalled before.
        if rtt_us == 0 {
            self.clock_broken = true;
            return false;
        }
        if self.ewma_rtt_us != 0 && !self.in_slow_start {
            if rtt_us > self.ewma_rtt_us.saturating_mul(CLOCK_JUMP_RATIO) {
                return false;
            }
            if rtt_us.saturating_mul(CLOCK_JUMP_RATIO) < self.ewma_rtt_us {
                if self.clock_broken {
                    return false;
                }
            } else {
                self.clock_broken = false;
            }
        }

        // N_EWMA (§2.1.2). The rearranged form is mandated so that rounding
        // matches other implementations. `u128` because the smoothed value
        // times N-1 has no useful bound once a consensus raises
        // `cc_ewma_max`.
        self.ewma_rtt_us = if self.ewma_rtt_us == 0 {
            rtt_us
        } else {
            let n = self.ewma_n() as u128;
            let smoothed = ((rtt_us as u128) * 2 + (self.ewma_rtt_us as u128) * (n - 1)) / (n + 1);
            smoothed.min(u64::MAX as u128) as u64
        };

        // §3.1.2: RTT_min is the smallest smoothed RTT of the circuit's
        // lifetime.
        if self.min_rtt_us == 0 || self.ewma_rtt_us < self.min_rtt_us {
            self.min_rtt_us = self.ewma_rtt_us;
        }

        // §3.1.2, the only BDP estimator C tor kept:
        //   BDP = cwnd * RTT_min / RTT_current_ewma
        // in `u128` so a large window times a long RTT cannot wrap, and
        // clamped back because a window is a `u32`.
        if self.ewma_rtt_us != 0 {
            let bdp = (self.cwnd as u128) * (self.min_rtt_us as u128) / (self.ewma_rtt_us as u128);
            self.bdp = bdp.min(u32::MAX as u128) as u32;
        }
        true
    }

    /// The N of the RTT smoothing (§2.1.2).
    fn ewma_n(&self) -> u64 {
        if self.in_slow_start {
            self.params.ewma_ss.max(2) as u64
        } else {
            let rate = self.cwnd_update_rate() as u64;
            (rate * self.params.ewma_cwnd_pct as u64 / 100)
                .min(self.params.ewma_max as u64)
                .max(2)
        }
    }

    /// The Vegas rules of §3.3, run once per usable SENDME ack.
    fn vegas_update(&mut self) {
        let p = self.params;

        // The queue is however much the window exceeds the BDP. Saturating:
        // a BDP estimate above the window simply means no queue, which is
        // the substitution §3.3 asks for.
        let queue_use = self.cwnd.saturating_sub(self.bdp);

        if self.cwnd_is_full() {
            self.cwnd_full = true;
        } else if self.cwnd_is_nonfull() {
            self.cwnd_full = false;
        }

        if self.in_slow_start {
            if queue_use < p.vegas_gamma {
                // Growing a window that was never filled would only build
                // queue, so a slack period costs the round's increment.
                if self.cwnd_full {
                    let inc = self.rfc3742_ss_inc();
                    self.cwnd = self.clamp_cwnd(self.cwnd.saturating_add(inc));
                    // Once RFC3742's increment over a whole window has
                    // fallen to the steady-state increment, slow start has
                    // nothing left to offer.
                    if (inc as u64) * (self.sendme_per_cwnd() as u64)
                        <= (p.cwnd_inc as u64) * (p.cwnd_inc_rate as u64)
                    {
                        self.in_slow_start = false;
                    }
                }
            } else {
                // A queue has formed: stop guessing and sit one gamma above
                // the BDP.
                self.in_slow_start = false;
                self.cwnd = self.clamp_cwnd(self.bdp.saturating_add(p.vegas_gamma));
            }
            // The emergency ceiling on slow start.
            if self.cwnd >= p.ss_max {
                self.cwnd = self.clamp_cwnd(p.ss_max);
                self.in_slow_start = false;
            }
        } else if self.next_cc_event == 0 {
            if queue_use > p.vegas_delta {
                self.cwnd = self
                    .bdp
                    .saturating_add(p.vegas_delta)
                    .saturating_sub(p.cwnd_inc);
            } else if queue_use > p.vegas_beta {
                self.cwnd = self.cwnd.saturating_sub(p.cwnd_inc);
            } else if self.cwnd_full && queue_use < p.vegas_alpha {
                // Only grow on a window that was actually filled.
                self.cwnd = self.cwnd.saturating_add(p.cwnd_inc);
            }
        }

        // §3.3 clamps to the floor inside the steady-state branch only; C
        // tor clamps unconditionally, which is the safer reading and the
        // only one that also bounds the slow-start assignments. (The
        // pseudocode calls the parameter `cc_circwindow_min`, an older name
        // for the `cc_cwnd_min` of §6.5.1.)
        self.cwnd = self.clamp_cwnd(self.cwnd);

        // A window pinned at the floor means the circuit is starving, and a
        // stale RTT_min would hold the BDP estimate -- and with it the
        // window -- down for the rest of the circuit's life. §3.1.2 allows
        // resetting RTT_min towards the current smoothed RTT by
        // `cc_rtt_reset_pct` percent; the default of 100 is a full reset,
        // which is the only reading under which the default does anything.
        if !self.in_slow_start && self.cwnd == self.clamp_cwnd(p.cwnd_min) {
            let pct = p.rtt_reset_pct.min(100) as u64;
            // Divide before multiplying, and saturate: both terms are
            // microsecond counts that a jumped clock can make enormous, and
            // losing the last two digits of a round trip changes nothing.
            let kept = (self.min_rtt_us / 100).saturating_mul(100 - pct);
            let fresh = (self.ewma_rtt_us / 100).saturating_mul(pct);
            self.min_rtt_us = kept.saturating_add(fresh).max(1);
        }

        // Re-arm the period counters, then start the new period with the
        // window not yet known to be full.
        if self.next_cc_event == 0 {
            self.next_cc_event = self.cwnd_update_rate();
        }
        if self.next_cwnd_event == 0 {
            self.next_cwnd_event = self.sendme_per_cwnd();
        }
        if p.cwnd_full_per_cwnd {
            if self.next_cwnd_event == self.sendme_per_cwnd() {
                self.cwnd_full = false;
            }
        } else if self.next_cc_event == self.cwnd_update_rate() {
            self.cwnd_full = false;
        }
    }

    /// `cwnd_is_full` (§3.3): several acks can arrive before the application
    /// refills the window, so the outstanding cells are allowed to fall
    /// `cc_cwnd_full_gap` increments short of it and still count.
    fn cwnd_is_full(&self) -> bool {
        let gap = self.params.cwnd_full_gap as u64 * self.sendme_inc as u64;
        self.inflight() as u64 + gap >= self.cwnd as u64
    }

    /// `cwnd_is_nonfull` (§3.3): a low watermark that clears the full state
    /// at once.
    fn cwnd_is_nonfull(&self) -> bool {
        100 * (self.inflight() as u64) < (self.params.cwnd_full_minpct as u64) * (self.cwnd as u64)
    }

    // The three helpers below do their arithmetic in `u64` and clamp on the
    // way out. Nothing a consensus can publish comes close to overflowing a
    // `u32` here, but `CcParams` has public fields, and window arithmetic
    // that panics in a debug build is not worth the casts saved.

    /// `rfc3742_ss_inc` (§3.3): full speed below the cap, then RFC3742's
    /// tapering increment.
    fn rfc3742_ss_inc(&self) -> u32 {
        let p = self.params;
        if self.cwnd <= p.ss_cap {
            // round(cc_cwnd_inc_pct_ss * cc_sendme_inc / 100).
            let scaled = p.cwnd_inc_pct_ss as u64 * self.sendme_inc as u64;
            ((scaled + 50) / 100).min(u32::MAX as u64) as u32
        } else {
            // round(cc_sendme_inc * cap / (2 * cwnd)), at least one. The
            // window is above `ss_cap`, which is at least 100, so the
            // divisor is never zero.
            let numerator = self.sendme_inc as u64 * p.ss_cap as u64;
            let divisor = 2 * self.cwnd as u64;
            (((numerator + divisor / 2) / divisor).min(u32::MAX as u64) as u32).max(1)
        }
    }

    /// `SENDME_PER_CWND` (§3.3): acks in one window, rounded, never zero.
    fn sendme_per_cwnd(&self) -> u32 {
        let acks = (self.cwnd as u64 + self.sendme_inc as u64 / 2) / self.sendme_inc as u64;
        (acks.min(u32::MAX as u64) as u32).max(1)
    }

    /// `CWND_UPDATE_RATE` (§3.3): every ack during slow start, otherwise
    /// `cc_cwnd_inc_rate` times per window.
    fn cwnd_update_rate(&self) -> u32 {
        if self.in_slow_start {
            return 1;
        }
        // `cc_cwnd_inc_rate` is at least one, so the divisor is at least the
        // increment.
        let step = (self.params.cwnd_inc_rate.max(1) as u64) * self.sendme_inc as u64;
        let rate = (self.cwnd as u64 + step / 2) / step;
        (rate.min(u32::MAX as u64) as u32).max(1)
    }

    /// Keep a window inside `[cc_cwnd_min, cc_cwnd_max]`. Not `u32::clamp`,
    /// which panics when a hostile consensus puts the minimum above the
    /// maximum; the floor of one cell keeps every divisor non-zero.
    fn clamp_cwnd(&self, cwnd: u32) -> u32 {
        cwnd.max(self.params.cwnd_min)
            .max(1)
            .min(self.params.cwnd_max.max(1))
    }
}

/// The receive side's counter: how many data cells since the last SENDME.
///
/// Getting this cadence wrong makes the far end tear the circuit down, so
/// this is deliberately the whole of the receiving side: count to the
/// negotiated increment, answer once, and start again from zero.
pub struct DeliverCounter {
    inc: u32,
    seen: u32,
}

impl DeliverCounter {
    pub fn new(sendme_inc: u8) -> Self {
        Self {
            inc: sendme_inc.max(1) as u32,
            seen: 0,
        }
    }

    /// Call once per received RELAY_DATA cell; true means "send a SENDME
    /// now".
    pub fn on_data(&mut self) -> bool {
        self.seen += 1;
        if self.seen < self.inc {
            return false;
        }
        // Reset rather than subtract: no arithmetic to drift, and no
        // counter that can run away if a caller ever drops an answer.
        self.seen = 0;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A clock far enough from the process start that a test can hand out a
    /// send time later than the ack time without underflowing an `Instant`.
    fn epoch() -> Instant {
        Instant::now() + Duration::from_secs(3600)
    }

    /// Fill the window at `now`, then deliver every SENDME it earned exactly
    /// `rtt` later. Every cell of the round leaves at the same instant, so
    /// each measured round trip is exactly `rtt`.
    fn fill_and_ack(vegas: &mut Vegas, now: Instant, rtt: Duration) -> Instant {
        while vegas.can_send() {
            vegas.on_send(now);
        }
        let arrival = now + rtt;
        while vegas.inflight() >= vegas.sendme_inc() as u32 {
            vegas.on_sendme(arrival).expect("acking cells we sent");
        }
        arrival
    }

    /// Ten quiet rounds and then slow ones, which is how a circuit leaves
    /// slow start when nothing else stops it.
    fn into_steady_state(vegas: &mut Vegas, mut now: Instant) -> Instant {
        for _ in 0..10 {
            now = fill_and_ack(vegas, now, Duration::from_millis(50));
        }
        while vegas.in_slow_start {
            now = fill_and_ack(vegas, now, Duration::from_millis(250));
        }
        now
    }

    #[test]
    fn params_take_real_values_and_ignore_out_of_range_ones() {
        let args = "cc_alg=2 cc_sendme_inc=33 cc_cwnd_init=200 cc_cwnd_inc=100 \
                    cc_ewma_max=20 cc_cwnd_full_gap=1 cc_cwnd_full_per_cwnd=0 \
                    hsdir-interval=1440 circwindow=1000";
        let p = CcParams::parse(args, Position::Exit);
        assert_eq!(p.alg, 2);
        assert_eq!(p.sendme_inc, 33);
        assert_eq!(p.cwnd_init, 200);
        assert_eq!(p.cwnd_inc, 100);
        assert_eq!(p.ewma_max, 20);
        assert_eq!(p.cwnd_full_gap, 1);
        assert!(!p.cwnd_full_per_cwnd);
        // Keys nobody published keep their defaults, and a `params` line
        // full of other parameters changes nothing else.
        assert_eq!(p.cwnd_min, CcParams::defaults(Position::Exit).cwnd_min);

        // Out of range, unparsable, and not a key=value pair at all: all
        // three fall back to the default, as `consensus::Params::parse`
        // does.
        let d = CcParams::defaults(Position::Exit);
        let bad = "cc_sendme_inc=0 cc_cwnd_init=10 cc_cwnd_min=5000 cc_alg=3 \
                   cc_cwnd_inc=notanumber cc_ewma_ss=1 cc_cwnd_full_minpct=101 \
                   cc_cwnd_full_gap cc_ss_max=499";
        let p = CcParams::parse(bad, Position::Exit);
        assert_eq!(p.sendme_inc, d.sendme_inc);
        assert_eq!(p.cwnd_init, d.cwnd_init);
        assert_eq!(p.cwnd_min, d.cwnd_min);
        assert_eq!(p.alg, d.alg, "only 0 and 2 are defined values for cc_alg");
        assert_eq!(p.cwnd_inc, d.cwnd_inc);
        assert_eq!(p.ewma_ss, d.ewma_ss);
        assert_eq!(p.cwnd_full_minpct, d.cwnd_full_minpct);
        assert_eq!(p.cwnd_full_gap, d.cwnd_full_gap);
        assert_eq!(p.ss_max, d.ss_max);
    }

    #[test]
    fn params_keep_the_positions_apart() {
        let args = "cc_vegas_alpha_exit=100 cc_vegas_alpha_onion=200 \
                    cc_vegas_beta_exit=150 cc_vegas_gamma_onion=250 \
                    cc_sscap_exit=700 cc_sscap_onion=800 cc_sscap_sbws=400";
        let exit = CcParams::parse(args, Position::Exit);
        let onion = CcParams::parse(args, Position::Onion);
        assert_eq!(exit.vegas_alpha, 100);
        assert_eq!(onion.vegas_alpha, 200);
        assert_eq!(exit.ss_cap, 700);
        assert_eq!(onion.ss_cap, 800);
        // A value published only for the other position must not leak
        // across, and the sbws copy is nobody's here.
        assert_eq!(exit.vegas_beta, 150);
        assert_eq!(
            onion.vegas_beta,
            CcParams::defaults(Position::Onion).vegas_beta
        );
        assert_eq!(onion.vegas_gamma, 250);
        assert_eq!(
            exit.vegas_gamma,
            CcParams::defaults(Position::Exit).vegas_gamma
        );

        // The defaults themselves differ by position (§6.5.3).
        let e = CcParams::defaults(Position::Exit);
        let o = CcParams::defaults(Position::Onion);
        assert_eq!(
            (e.vegas_beta, e.vegas_gamma, e.vegas_delta),
            (248, 186, 310)
        );
        assert_eq!(
            (o.vegas_beta, o.vegas_gamma, o.vegas_delta),
            (372, 248, 434)
        );
        assert_eq!((e.ss_cap, o.ss_cap), (600, 475));
    }

    #[test]
    fn a_sendme_is_due_every_increment_and_never_drifts() {
        for inc in [1u8, 2, 31, 33, 254] {
            let mut counter = DeliverCounter::new(inc);
            let mut sent = 0u32;
            for cell in 1..=2000u32 {
                if counter.on_data() {
                    sent += 1;
                    assert_eq!(
                        cell % inc as u32,
                        0,
                        "increment {inc}: SENDME after cell {cell}"
                    );
                }
            }
            assert_eq!(sent, 2000 / inc as u32, "increment {inc}: total SENDMEs");
        }

        // A negotiation that somehow produced zero must not divide by it.
        let mut counter = DeliverCounter::new(0);
        assert!(counter.on_data());
    }

    #[test]
    fn the_window_gates_sending_and_inflight_never_passes_it() {
        let mut vegas = Vegas::new(CcParams::defaults(Position::Exit), 31);
        let mut now = epoch();
        for round in 0..40 {
            let rtt = if round < 20 { 50 } else { 300 };
            while vegas.can_send() {
                assert!(vegas.inflight() < vegas.cwnd());
                vegas.on_send(now);
                assert!(vegas.inflight() <= vegas.cwnd());
            }
            assert!(!vegas.can_send());
            assert_eq!(vegas.inflight(), vegas.cwnd());
            now += Duration::from_millis(rtt);
            while vegas.inflight() >= vegas.sendme_inc() as u32 {
                vegas.on_sendme(now).expect("acking cells we sent");
            }
            assert!(vegas.can_send(), "an ack must free at least one cell");
        }
    }

    #[test]
    fn a_sendme_with_nothing_outstanding_is_an_error() {
        let mut vegas = Vegas::new(CcParams::defaults(Position::Exit), 31);
        let now = epoch();
        assert!(vegas.on_sendme(now).is_err(), "nothing has been sent");

        // One cell short of an increment is still short.
        for _ in 0..30 {
            vegas.on_send(now);
        }
        assert!(vegas.on_sendme(now + Duration::from_millis(50)).is_err());

        vegas.on_send(now);
        assert!(vegas.on_sendme(now + Duration::from_millis(50)).is_ok());
        assert_eq!(vegas.inflight(), 0);
        assert!(
            vegas.on_sendme(now + Duration::from_millis(60)).is_err(),
            "a second ack for the same increment acknowledges nothing"
        );
    }

    #[test]
    fn slow_start_grows_the_window_and_then_leaves() {
        let mut vegas = Vegas::new(CcParams::defaults(Position::Exit), 31);
        let start = vegas.cwnd();
        assert!(vegas.in_slow_start);

        let mut now = epoch();
        for _ in 0..10 {
            now = fill_and_ack(&mut vegas, now, Duration::from_millis(50));
        }
        let grown = vegas.cwnd();
        assert!(grown > start, "slow start grew {start} to {grown}");
        assert!(vegas.in_slow_start, "a quiet circuit stays in slow start");
        assert_eq!(vegas.min_rtt_us, 50_000, "a steady RTT is its own minimum");

        // A round trip that suddenly quintuples is a queue: slow start ends
        // and the window is pulled back to one gamma above the BDP.
        now = fill_and_ack(&mut vegas, now, Duration::from_millis(250));
        let _ = now;
        assert!(!vegas.in_slow_start);
        assert!(
            vegas.cwnd() < grown,
            "the window should fall back from {grown}, not to {}",
            vegas.cwnd()
        );
        assert!(vegas.cwnd() >= vegas.params.cwnd_min);
    }

    #[test]
    fn steady_state_shrinks_on_a_queue_and_never_goes_under_the_floor() {
        // The stock thresholds are hundreds of cells wide, so the floor is
        // out of reach with them; narrow ones put it a few rounds away.
        let mut params = CcParams::defaults(Position::Exit);
        params.vegas_alpha = 2;
        params.vegas_beta = 3;
        params.vegas_gamma = 4;
        params.vegas_delta = 400;
        let mut vegas = Vegas::new(params, 31);

        let mut now = into_steady_state(&mut vegas, epoch());
        let entered = vegas.cwnd();
        let mut lowest = u32::MAX;
        for _ in 0..200 {
            now = fill_and_ack(&mut vegas, now, Duration::from_millis(400));
            assert!(
                vegas.cwnd() >= params.cwnd_min,
                "the window fell to {} below cc_cwnd_min {}",
                vegas.cwnd(),
                params.cwnd_min
            );
            lowest = lowest.min(vegas.cwnd());
        }
        let _ = now;
        assert!(
            vegas.cwnd() < entered,
            "a standing queue must shrink {entered}"
        );
        assert_eq!(
            lowest, params.cwnd_min,
            "a queue this far above beta drives the window onto the floor"
        );
        // It does not stay there: `cc_rtt_reset_pct` throws RTT_min away
        // once the window bottoms out, so the circuit stops believing in a
        // queue and climbs back out. That is the starvation escape of
        // §3.1.2, and the point of the assertion above is that the climb
        // starts from the floor and never from below it.
        assert!(vegas.cwnd() > params.cwnd_min);
    }

    #[test]
    fn steady_state_grows_again_once_the_queue_drains() {
        let mut vegas = Vegas::new(CcParams::defaults(Position::Exit), 31);
        let mut now = into_steady_state(&mut vegas, epoch());
        let settled = vegas.cwnd();
        // The RTT the circuit exited slow start on was inflated; back at the
        // minimum there is no queue to answer for, so the window climbs.
        for _ in 0..40 {
            now = fill_and_ack(&mut vegas, now, Duration::from_millis(50));
        }
        let _ = now;
        assert!(
            vegas.cwnd() > settled,
            "an empty queue should grow {settled}, not leave {}",
            vegas.cwnd()
        );
        assert!(!vegas.in_slow_start, "growth here is the steady-state rule");
    }

    #[test]
    fn a_window_that_is_never_filled_does_not_grow() {
        // With no slack allowed, a sender that offers one increment per
        // round never fills a window this wide.
        let mut params = CcParams::defaults(Position::Exit);
        params.cwnd_full_gap = 0;
        params.cwnd_init = 1000;
        let mut vegas = Vegas::new(params, 31);

        let mut now = epoch();
        for _ in 0..50 {
            for _ in 0..31 {
                vegas.on_send(now);
            }
            now += Duration::from_millis(50);
            vegas.on_sendme(now).expect("acking cells we sent");
            assert_eq!(
                vegas.cwnd(),
                1000,
                "an unfilled window must not grow, in slow start or out"
            );
        }
        assert!(!vegas.cwnd_full);
    }

    #[test]
    fn a_stalled_or_backwards_clock_is_ignored() {
        let mut vegas = Vegas::new(CcParams::defaults(Position::Exit), 31);
        let now = epoch();

        // A clock that has not moved: no RTT, no window change, no panic.
        for _ in 0..31 {
            vegas.on_send(now);
        }
        vegas
            .on_sendme(now)
            .expect("a stalled clock is not a protocol error");
        assert_eq!(vegas.ewma_rtt_us, 0, "a zero delta is never an RTT");
        assert_eq!(vegas.cwnd(), 124);
        assert!(vegas.clock_broken);

        // A clock that ran backwards between the send and the ack.
        let later = now + Duration::from_secs(10);
        for _ in 0..31 {
            vegas.on_send(later);
        }
        vegas.on_sendme(now).expect("nor is a backwards clock");
        assert_eq!(vegas.ewma_rtt_us, 0);
        assert_eq!(vegas.cwnd(), 124);

        // Now measure normally, leave slow start, and offer a round trip
        // five thousand times the smoothed one: §2.1.1 throws it away.
        let mut vegas = Vegas::new(CcParams::defaults(Position::Exit), 31);
        let mut clock = into_steady_state(&mut vegas, epoch());
        let cwnd = vegas.cwnd();
        let ewma = vegas.ewma_rtt_us;
        while vegas.can_send() {
            vegas.on_send(clock);
        }
        clock += Duration::from_secs(4000);
        vegas
            .on_sendme(clock)
            .expect("a jumped clock is not an error");
        assert_eq!(vegas.ewma_rtt_us, ewma, "the jump must not move the RTT");
        assert_eq!(vegas.cwnd(), cwnd, "nor the window");
    }

    /// A deterministic peer behind a bottleneck link: every increment of
    /// cells is acknowledged one propagation delay after it was sent, but no
    /// sooner than the link can drain the increment ahead of it. That second
    /// term is what turns an oversized window into queueing delay, which is
    /// the only signal Vegas has.
    #[test]
    fn the_window_converges_against_a_bottleneck_peer() {
        const CELLS: u64 = 120_000;
        /// One cell every 100us, so the link carries ten cells per
        /// millisecond.
        const DRAIN_US: u64 = 100;
        const BASE_RTT: Duration = Duration::from_millis(50);
        /// 50ms at one cell per 100us: the window that exactly fills the
        /// pipe.
        const TRUE_BDP: u32 = 500;

        let params = CcParams::defaults(Position::Exit);
        let mut vegas = Vegas::new(params, 31);
        let increment = Duration::from_micros(31 * DRAIN_US);

        let mut now = epoch();
        let mut acks: VecDeque<Instant> = VecDeque::new();
        let mut last_arrival = now;
        let mut sent = 0u64;
        let mut history = Vec::new();

        while sent < CELLS || !acks.is_empty() {
            while sent < CELLS && vegas.can_send() {
                vegas.on_send(now);
                sent += 1;
                if sent.is_multiple_of(31) {
                    // The link is either idle, and the ack comes back after
                    // one round trip, or busy, and it comes back behind the
                    // increment in front of it.
                    let arrival = (now + BASE_RTT).max(last_arrival + increment);
                    last_arrival = arrival;
                    acks.push_back(arrival);
                }
            }
            let Some(&next) = acks.front() else {
                panic!("the sender stalled with no acks outstanding");
            };
            now = now.max(next);
            while acks.front().is_some_and(|a| *a <= now) {
                acks.pop_front();
                vegas
                    .on_sendme(now)
                    .expect("the peer only acks what it got");
                assert!(vegas.inflight() <= vegas.cwnd());
                history.push(vegas.cwnd());
            }
        }

        // Vegas aims at the bandwidth-delay product plus whatever queue it
        // is willing to tolerate, which is between alpha and beta.
        let tail = &history[history.len() * 3 / 4..];
        let low = *tail.iter().min().unwrap();
        let high = *tail.iter().max().unwrap();
        // The queue Vegas settles on is what it set out to hold: more than
        // alpha, or it would still be growing, and less than beta, or it
        // would still be shrinking.
        let queue = vegas.cwnd() - TRUE_BDP;
        assert!(
            queue >= params.vegas_alpha && queue <= params.vegas_beta,
            "settled on a queue of {queue} cells, outside alpha {} .. beta {}",
            params.vegas_alpha,
            params.vegas_beta
        );
        assert!(
            low >= TRUE_BDP,
            "the window fell to {low}, below the {TRUE_BDP}-cell pipe"
        );
        assert!(
            high <= TRUE_BDP + params.vegas_delta,
            "the window ran away to {high}"
        );
        assert!(
            high - low <= 4 * params.cwnd_inc,
            "the window oscillated between {low} and {high}"
        );
        assert!(
            !vegas.in_slow_start,
            "slow start should be long over after {CELLS} cells"
        );
    }
}
