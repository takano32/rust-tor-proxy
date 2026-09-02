//! Path selection.
//!
//! This is deliberately simpler than path-spec: relays are chosen in
//! proportion to their consensus bandwidth, scaled by the consensus
//! `bandwidth-weights` for the position being filled, and the guard is a
//! single relay pinned until it stops working. What it does enforce is the
//! structural part -- distinct relays, distinct /16s, and no two relays that
//! declare each other as family in one circuit -- and a guard that does not
//! change per circuit, which is the property that matters most for a client's
//! anonymity.

use std::io;

use super::dir::consensus::{
    BandwidthWeights, Consensus, RouterStatus, FLAG_BAD_EXIT, FLAG_EXIT, FLAG_FAST, FLAG_GUARD,
    FLAG_MIDDLE_ONLY, FLAG_RUNNING, FLAG_STABLE, FLAG_VALID, WEIGHT_SCALE,
};
use super::dir::microdesc::Microdesc;
use crate::ffi::rand;
use crate::util::invalid_data;

/// A relay must have all of these to be used at all.
const USABLE: u16 = FLAG_RUNNING | FLAG_VALID;

/// What we require of a guard.
pub const GUARD_FLAGS: u16 = USABLE | FLAG_GUARD | FLAG_STABLE | FLAG_FAST;

/// Relays already committed to the path under construction.
#[derive(Default, Clone)]
pub struct PathConstraints {
    identities: Vec<[u8; 20]>,
    subnets: Vec<[u8; 2]>,
    /// The family list declared by each relay already in the path.
    families: Vec<Vec<[u8; 20]>>,
}

impl PathConstraints {
    pub fn add(&mut self, router: &RouterStatus, microdesc: Option<&Microdesc>) {
        self.add_relay(
            router.identity,
            router.subnet16(),
            microdesc.map(|m| m.family.clone()).unwrap_or_default(),
        );
    }

    /// Add a relay known by address rather than by consensus entry -- an
    /// introduction point may be named only in a service's descriptor.
    pub fn add_relay(&mut self, identity: [u8; 20], subnet16: [u8; 2], family: Vec<[u8; 20]>) {
        self.identities.push(identity);
        self.subnets.push(subnet16);
        self.families.push(family);
    }

    /// True if a relay known only by identity, address and family may join --
    /// the form a pre-built circuit's hops are remembered in.
    pub fn accepts_relay(
        &self,
        identity: &[u8; 20],
        subnet16: [u8; 2],
        family: &[[u8; 20]],
    ) -> bool {
        !self.identities.contains(identity)
            && !self.subnets.contains(&subnet16)
            && !self.families.iter().any(|f| f.contains(identity))
            && !family.iter().any(|id| self.identities.contains(id))
    }

    /// True if `router` may join the path.
    ///
    /// Family is treated as conflicting if *either* side declares the other.
    /// Tor requires the declaration to be mutual; being stricter costs a few
    /// candidates and never puts two related relays on one circuit.
    pub fn accepts(&self, router: &RouterStatus, microdesc: Option<&Microdesc>) -> bool {
        if self.identities.contains(&router.identity) {
            return false;
        }
        if self.subnets.contains(&router.subnet16()) {
            return false;
        }
        for family in &self.families {
            if family.contains(&router.identity) {
                return false;
            }
        }
        if let Some(md) = microdesc {
            if self.identities.iter().any(|id| md.shares_family_with(id)) {
                return false;
            }
        }
        true
    }
}

/// The place in a circuit a relay is being drawn for. The authorities weight
/// a relay differently in each, so that the relays which could serve as
/// either guard or exit are not drawn away from the position where they are
/// scarce (path-spec, "Weighting node selection").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Position {
    Guard,
    Middle,
    Exit,
}

impl Position {
    /// The weight this position gives `router`, from the table in
    /// dir-spec/consensus-formats.md ("bandwidth-weights") and path-spec
    /// ("Weighting node selection"):
    ///
    /// ```text
    ///                    Guard+Exit   Guard   Exit   neither
    ///   guard position       Wgd       Wgg     --      Wgm
    ///   middle position      Wmd       Wmg    Wme      Wmm
    ///   exit position        Wed       Weg    Wee      Wem
    /// ```
    ///
    /// The spec names no guard-position weight for an Exit-flagged relay that
    /// is not also a Guard: such a relay is not a guard candidate at all, and
    /// `guard_candidates` never offers one. It falls back to Wgm, which the
    /// authorities set equal to Wgg to "handle bridges and strange exit
    /// policies" -- the same treatment every other unflagged relay gets.
    fn weight(self, router: &RouterStatus, weights: &BandwidthWeights) -> u32 {
        let guard = router.has(FLAG_GUARD);
        let exit = router.has(FLAG_EXIT);
        match (self, guard, exit) {
            (Position::Guard, true, true) => weights.wgd,
            (Position::Guard, true, false) => weights.wgg,
            (Position::Guard, false, _) => weights.wgm,
            (Position::Middle, true, true) => weights.wmd,
            (Position::Middle, true, false) => weights.wmg,
            (Position::Middle, false, true) => weights.wme,
            (Position::Middle, false, false) => weights.wmm,
            (Position::Exit, true, true) => weights.wed,
            (Position::Exit, true, false) => weights.weg,
            (Position::Exit, false, true) => weights.wee,
            (Position::Exit, false, false) => weights.wem,
        }
    }
}

/// A relay's share of an unweighted draw.
///
/// A relay with zero bandwidth still gets a small share, so that a consensus
/// where measurements are missing does not collapse to a single candidate.
fn bandwidth_share(router: &RouterStatus) -> u64 {
    router.bandwidth.max(1) as u64
}

/// A relay's share of a draw for `position`.
fn weighted_bandwidth(
    router: &RouterStatus,
    position: Position,
    weights: &BandwidthWeights,
) -> u64 {
    // Bandwidth is a u32 and a weight reaches 10000, so the product needs 64
    // bits. The same floor as the unweighted share applies afterwards: a
    // relay the weights push down to nothing stays selectable, which is what
    // keeps a draw from failing when such a relay is the only candidate left.
    let scaled = bandwidth_share(router) * position.weight(router, weights) as u64;
    (scaled / WEIGHT_SCALE as u64).max(1)
}

/// Choose one relay in proportion to its consensus bandwidth alone.
///
/// Every position in a real path is weighted, so this is only the reference
/// the tests below compare the weighted draw against: a consensus carrying no
/// `bandwidth-weights` line must reduce to exactly this, since every weight
/// then stands at the scale.
#[cfg(test)]
pub fn weighted_choice<'a>(candidates: &[&'a RouterStatus]) -> io::Result<&'a RouterStatus> {
    choose(candidates, bandwidth_share)
}

/// Choose one relay for `position`, in proportion to its consensus bandwidth
/// as the consensus weights it there.
pub fn weighted_choice_at<'a>(
    candidates: &[&'a RouterStatus],
    position: Position,
    weights: &BandwidthWeights,
) -> io::Result<&'a RouterStatus> {
    choose(candidates, |r| weighted_bandwidth(r, position, weights))
}

fn choose<'a>(
    candidates: &[&'a RouterStatus],
    weight: impl Fn(&RouterStatus) -> u64,
) -> io::Result<&'a RouterStatus> {
    if candidates.is_empty() {
        return Err(invalid_data("no relay matches the required flags"));
    }
    let total: u64 = candidates.iter().map(|r| weight(r)).sum();
    let mut pick = rand::below(total)?;
    for router in candidates {
        let w = weight(router);
        if pick < w {
            return Ok(router);
        }
        pick -= w;
    }
    Ok(candidates[candidates.len() - 1])
}

/// Candidate guards: stable, fast, flagged Guard, and not middle-only.
pub fn guard_candidates(consensus: &Consensus) -> Vec<&RouterStatus> {
    consensus
        .routers
        .iter()
        .filter(|r| r.has(GUARD_FLAGS) && !r.has(FLAG_MIDDLE_ONLY))
        .collect()
}

/// Candidate exits, before their port policy is known.
///
/// The microdescriptor holds the policy, so the caller samples from here,
/// fetches those microdescriptors and then filters by port.
pub fn exit_candidates<'a>(
    consensus: &'a Consensus,
    constraints: &PathConstraints,
) -> Vec<&'a RouterStatus> {
    consensus
        .routers
        .iter()
        .filter(|r| {
            r.has(USABLE | FLAG_EXIT | FLAG_FAST)
                && !r.has(FLAG_BAD_EXIT)
                && !r.has(FLAG_MIDDLE_ONLY)
                && constraints.accepts(r, None)
        })
        .collect()
}

/// Candidates for a rendezvous point. It only forwards cells between two
/// circuits, so nothing about exiting matters -- speed and stability do.
pub fn rendezvous_candidates<'a>(
    consensus: &'a Consensus,
    constraints: &PathConstraints,
) -> Vec<&'a RouterStatus> {
    consensus
        .routers
        .iter()
        .filter(|r| r.has(USABLE | FLAG_FAST | FLAG_STABLE) && constraints.accepts(r, None))
        .collect()
}

pub fn middle_candidates<'a>(
    consensus: &'a Consensus,
    constraints: &PathConstraints,
) -> Vec<&'a RouterStatus> {
    consensus
        .routers
        .iter()
        .filter(|r| r.has(USABLE | FLAG_FAST) && constraints.accepts(r, None))
        .collect()
}

/// Draw `count` distinct relays without replacement, weighted by bandwidth
/// alone. The unweighted reference, as `weighted_choice` above.
#[cfg(test)]
pub fn sample<'a>(
    candidates: &[&'a RouterStatus],
    count: usize,
) -> io::Result<Vec<&'a RouterStatus>> {
    sample_with(candidates, count, bandwidth_share)
}

/// Draw `count` distinct relays without replacement, weighted for the
/// position they are being sampled for.
pub fn sample_at<'a>(
    candidates: &[&'a RouterStatus],
    count: usize,
    position: Position,
    weights: &BandwidthWeights,
) -> io::Result<Vec<&'a RouterStatus>> {
    sample_with(candidates, count, |r| {
        weighted_bandwidth(r, position, weights)
    })
}

fn sample_with<'a>(
    candidates: &[&'a RouterStatus],
    count: usize,
    weight: impl Fn(&RouterStatus) -> u64,
) -> io::Result<Vec<&'a RouterStatus>> {
    let mut pool: Vec<&RouterStatus> = candidates.to_vec();
    let mut out = Vec::with_capacity(count.min(pool.len()));
    while out.len() < count && !pool.is_empty() {
        let chosen = choose(&pool, &weight)?;
        let identity = chosen.identity;
        out.push(chosen);
        pool.retain(|r| r.identity != identity);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router(id: u8, ip: [u8; 4], flags: u16, bandwidth: u32) -> RouterStatus {
        RouterStatus {
            identity: [id; 20],
            microdesc_digest: [id; 32],
            ipv4: ip,
            or_port: 9001,
            flags,
            bandwidth,
        }
    }

    fn consensus(routers: Vec<RouterStatus>) -> Consensus {
        Consensus {
            valid_after: 0,
            fresh_until: 0,
            valid_until: u64::MAX,
            routers,
            params: crate::tor::dir::consensus::Params::default(),
            shared_rand_current: None,
            shared_rand_previous: None,
        }
    }

    #[test]
    fn guard_candidates_need_every_guard_flag() {
        let c = consensus(vec![
            router(1, [1, 1, 1, 1], GUARD_FLAGS, 100),
            // Missing Stable.
            router(2, [2, 2, 2, 2], USABLE | FLAG_GUARD | FLAG_FAST, 100),
            // MiddleOnly relays are never guards.
            router(3, [3, 3, 3, 3], GUARD_FLAGS | FLAG_MIDDLE_ONLY, 100),
        ]);
        let candidates = guard_candidates(&c);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].identity[0], 1);
    }

    #[test]
    fn exit_candidates_exclude_bad_exits() {
        let c = consensus(vec![
            router(1, [1, 1, 1, 1], USABLE | FLAG_EXIT | FLAG_FAST, 100),
            router(
                2,
                [2, 2, 2, 2],
                USABLE | FLAG_EXIT | FLAG_FAST | FLAG_BAD_EXIT,
                100,
            ),
            router(3, [3, 3, 3, 3], USABLE | FLAG_FAST, 100),
        ]);
        let candidates = exit_candidates(&c, &PathConstraints::default());
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].identity[0], 1);
    }

    #[test]
    fn constraints_reject_repeats_subnets_and_families() {
        let guard = router(1, [10, 20, 1, 1], GUARD_FLAGS, 100);
        let same_relay = router(1, [99, 99, 1, 1], GUARD_FLAGS, 100);
        let same_subnet = router(2, [10, 20, 9, 9], GUARD_FLAGS, 100);
        let other = router(3, [30, 40, 1, 1], GUARD_FLAGS, 100);

        let mut constraints = PathConstraints::default();
        constraints.add(&guard, None);
        assert!(!constraints.accepts(&same_relay, None));
        assert!(!constraints.accepts(&same_subnet, None));
        assert!(constraints.accepts(&other, None));
    }

    #[test]
    fn family_conflicts_are_caught_from_either_side() {
        let a = router(1, [10, 1, 1, 1], GUARD_FLAGS, 100);
        let b = router(2, [20, 1, 1, 1], GUARD_FLAGS, 100);

        // a declares b.
        let a_md = md_with_family(vec![[2u8; 20]]);
        let mut constraints = PathConstraints::default();
        constraints.add(&a, Some(&a_md));
        assert!(!constraints.accepts(&b, None));

        // b declares a.
        let b_md = md_with_family(vec![[1u8; 20]]);
        let mut constraints = PathConstraints::default();
        constraints.add(&a, None);
        assert!(!constraints.accepts(&b, Some(&b_md)));
        // A relay whose family names nobody in the path is still fine.
        let unrelated = md_with_family(vec![[8u8; 20]]);
        assert!(constraints.accepts(&router(9, [90, 1, 1, 1], GUARD_FLAGS, 1), Some(&unrelated)));
    }

    fn md_with_family(family: Vec<[u8; 20]>) -> Microdesc {
        Microdesc {
            digest: [0u8; 32],
            ntor_onion_key: [0u8; 32],
            ed_identity: None,
            exit_policy: super::super::dir::microdesc::PortPolicy::reject_all(),
            family,
        }
    }

    /// Bandwidth must actually steer the choice, and a zero-bandwidth relay
    /// must still be reachable.
    #[test]
    fn choice_follows_bandwidth() {
        let heavy = router(1, [1, 1, 1, 1], GUARD_FLAGS, 100_000);
        let light = router(2, [2, 2, 2, 2], GUARD_FLAGS, 1);
        let candidates = vec![&heavy, &light];
        let mut heavy_hits = 0;
        for _ in 0..200 {
            if weighted_choice(&candidates).unwrap().identity[0] == 1 {
                heavy_hits += 1;
            }
        }
        assert!(
            heavy_hits > 180,
            "heavy relay chosen {heavy_hits}/200 times"
        );

        let zero = router(3, [3, 3, 3, 3], GUARD_FLAGS, 0);
        let only_zero = vec![&zero];
        assert_eq!(weighted_choice(&only_zero).unwrap().identity[0], 3);
        assert!(weighted_choice(&[]).is_err());
    }

    /// The weights the authorities published on 2026-09-02, when exit
    /// bandwidth was the scarce resource.
    fn live_weights() -> BandwidthWeights {
        BandwidthWeights {
            wgg: 6013,
            wgm: 6013,
            wgd: 103,
            wmg: 3987,
            wmm: 10000,
            wme: 0,
            wmd: 103,
            weg: 9793,
            wem: 10000,
            wee: 10000,
            wed: 9793,
        }
    }

    /// Every entry of the spec's table, with distinct values so that a
    /// transposed pair cannot pass.
    #[test]
    fn the_weight_table_follows_the_spec() {
        let w = BandwidthWeights {
            wgg: 1,
            wgm: 2,
            wgd: 3,
            wmg: 4,
            wmm: 5,
            wme: 6,
            wmd: 7,
            weg: 8,
            wem: 9,
            wee: 10,
            wed: 11,
        };
        let guard = router(1, [1, 1, 1, 1], USABLE | FLAG_GUARD, 1);
        let exit = router(2, [2, 2, 2, 2], USABLE | FLAG_EXIT, 1);
        let both = router(3, [3, 3, 3, 3], USABLE | FLAG_GUARD | FLAG_EXIT, 1);
        let neither = router(4, [4, 4, 4, 4], USABLE, 1);

        assert_eq!(Position::Guard.weight(&guard, &w), 1);
        assert_eq!(Position::Guard.weight(&neither, &w), 2);
        assert_eq!(Position::Guard.weight(&both, &w), 3);

        assert_eq!(Position::Middle.weight(&guard, &w), 4);
        assert_eq!(Position::Middle.weight(&neither, &w), 5);
        assert_eq!(Position::Middle.weight(&exit, &w), 6);
        assert_eq!(Position::Middle.weight(&both, &w), 7);

        assert_eq!(Position::Exit.weight(&guard, &w), 8);
        assert_eq!(Position::Exit.weight(&neither, &w), 9);
        assert_eq!(Position::Exit.weight(&exit, &w), 10);
        assert_eq!(Position::Exit.weight(&both, &w), 11);

        // The one combination the spec leaves out.
        assert_eq!(Position::Guard.weight(&exit, &w), 2);
    }

    /// Wgd is about a sixtieth of Wgg in this consensus, so a Guard+Exit relay must
    /// lose the guard draw to an equally fast Guard-only one -- while the
    /// unweighted draw between the same two stays a coin flip.
    #[test]
    fn weighting_steers_the_guard_draw_away_from_exits() {
        let weights = live_weights();
        let guard = router(1, [1, 1, 1, 1], GUARD_FLAGS, 10_000);
        let dual = router(2, [2, 2, 2, 2], GUARD_FLAGS | FLAG_EXIT, 10_000);
        let candidates = vec![&guard, &dual];

        let mut weighted_hits = 0;
        let mut plain_hits = 0;
        for _ in 0..300 {
            if weighted_choice_at(&candidates, Position::Guard, &weights)
                .unwrap()
                .identity[0]
                == 1
            {
                weighted_hits += 1;
            }
            if weighted_choice(&candidates).unwrap().identity[0] == 1 {
                plain_hits += 1;
            }
        }
        // 6013 against 103 is about 98% of draws.
        assert!(
            weighted_hits > 270,
            "guard-only relay chosen {weighted_hits}/300 times"
        );
        assert!(
            (100..=200).contains(&plain_hits),
            "unweighted draw gave {plain_hits}/300"
        );
    }

    /// Wme is zero here: an Exit-flagged relay contributes nothing to the
    /// middle position. It must still be selectable when it is all there is,
    /// the same guarantee the floor gives a zero-bandwidth relay.
    #[test]
    fn a_relay_weighted_to_nothing_is_still_reachable() {
        let weights = live_weights();
        let exit = router(1, [1, 1, 1, 1], USABLE | FLAG_EXIT | FLAG_FAST, 50_000);
        assert_eq!(weighted_bandwidth(&exit, Position::Middle, &weights), 1);

        let only = vec![&exit];
        assert_eq!(
            weighted_choice_at(&only, Position::Middle, &weights)
                .unwrap()
                .identity[0],
            1
        );
        assert_eq!(
            sample_at(&only, 3, Position::Middle, &weights)
                .unwrap()
                .len(),
            1
        );
        assert!(weighted_choice_at(&[], Position::Middle, &weights).is_err());
    }

    /// A consensus with no `bandwidth-weights` line must be drawn from
    /// exactly as the unweighted function draws it: same share for every
    /// flag combination in every position, and the same distribution.
    #[test]
    fn neutral_weights_reproduce_the_unweighted_draw() {
        let weights = BandwidthWeights::default();
        let flags = [
            USABLE,
            USABLE | FLAG_GUARD,
            USABLE | FLAG_EXIT,
            USABLE | FLAG_GUARD | FLAG_EXIT,
        ];
        for (i, f) in flags.iter().enumerate() {
            for bandwidth in [0, 1, 3, 1_000_000, u32::MAX] {
                let r = router(i as u8, [1, 2, 3, 4], *f, bandwidth);
                for position in [Position::Guard, Position::Middle, Position::Exit] {
                    assert_eq!(
                        weighted_bandwidth(&r, position, &weights),
                        bandwidth_share(&r)
                    );
                }
            }
        }

        let heavy = router(1, [1, 1, 1, 1], GUARD_FLAGS, 100_000);
        let light = router(2, [2, 2, 2, 2], GUARD_FLAGS, 1);
        let candidates = vec![&heavy, &light];
        let mut hits = 0;
        for _ in 0..300 {
            if weighted_choice_at(&candidates, Position::Guard, &weights)
                .unwrap()
                .identity[0]
                == 1
            {
                hits += 1;
            }
        }
        assert!(hits > 280, "heavy relay chosen {hits}/300 times");
    }

    #[test]
    fn sampling_never_repeats_a_relay() {
        let routers: Vec<RouterStatus> = (1..=10)
            .map(|i| router(i, [i, i, i, i], GUARD_FLAGS, 100))
            .collect();
        let candidates: Vec<&RouterStatus> = routers.iter().collect();
        let drawn = sample(&candidates, 6).unwrap();
        assert_eq!(drawn.len(), 6);
        let mut ids: Vec<u8> = drawn.iter().map(|r| r.identity[0]).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 6);
        // Asking for more than exist yields everything, once.
        assert_eq!(sample(&candidates, 50).unwrap().len(), 10);

        // The weighted sample is drawn from the same pool in the same way.
        let drawn = sample_at(&candidates, 6, Position::Exit, &live_weights()).unwrap();
        let mut ids: Vec<u8> = drawn.iter().map(|r| r.identity[0]).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 6);
    }
}
