//! Path selection.
//!
//! This is deliberately simpler than path-spec: relays are chosen in
//! proportion to their consensus bandwidth, with the position-dependent
//! `bandwidth-weights` ignored, and the guard is a single relay pinned until
//! it stops working. What it does enforce is the structural part -- distinct
//! relays, distinct /16s, and no two relays that declare each other as family
//! in one circuit -- and a guard that does not change per circuit, which is
//! the property that matters most for a client's anonymity.
//!
//! TODO: apply the consensus `bandwidth-weights` (Wgg/Wmg/Wee and friends) so
//! that guard and exit capacity is not over-drawn from the same relays.

use std::io;

use super::dir::consensus::{
    Consensus, RouterStatus, FLAG_BAD_EXIT, FLAG_EXIT, FLAG_FAST, FLAG_GUARD, FLAG_MIDDLE_ONLY,
    FLAG_RUNNING, FLAG_STABLE, FLAG_VALID,
};
use super::dir::microdesc::Microdesc;
use crate::ffi::rand;
use crate::util::invalid_data;

/// A relay must have all of these to be used at all.
const USABLE: u16 = FLAG_RUNNING | FLAG_VALID;

/// What we require of a guard.
pub const GUARD_FLAGS: u16 = USABLE | FLAG_GUARD | FLAG_STABLE | FLAG_FAST;

/// Relays already committed to the path under construction.
#[derive(Default)]
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

/// Choose one relay in proportion to its consensus bandwidth.
///
/// A relay with zero bandwidth still gets a small share, so that a consensus
/// where measurements are missing does not collapse to a single candidate.
pub fn weighted_choice<'a>(candidates: &[&'a RouterStatus]) -> io::Result<&'a RouterStatus> {
    if candidates.is_empty() {
        return Err(invalid_data("no relay matches the required flags"));
    }
    let weight = |r: &RouterStatus| r.bandwidth.max(1) as u64;
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

/// Draw `count` distinct relays without replacement, weighted by bandwidth.
pub fn sample<'a>(
    candidates: &[&'a RouterStatus],
    count: usize,
) -> io::Result<Vec<&'a RouterStatus>> {
    let mut pool: Vec<&RouterStatus> = candidates.to_vec();
    let mut out = Vec::with_capacity(count.min(pool.len()));
    while out.len() < count && !pool.is_empty() {
        let chosen = weighted_choice(&pool)?;
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
    }
}
