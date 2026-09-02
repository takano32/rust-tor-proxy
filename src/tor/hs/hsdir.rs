//! The HSDir hash ring (rend-spec/deriving-keys.md, [WHERE-HSDESC]).
//!
//! Every relay with the HSDir flag gets a position on a ring, computed from
//! its Ed25519 identity and the network's shared random value. A descriptor
//! gets `hsdir_n_replicas` positions of its own, derived from the blinded
//! key. The nodes responsible for it are the ones just clockwise of each of
//! those positions. Both sides compute the same ring from the same consensus,
//! so nobody has to be told where anything is.

use super::blind::TimePeriod;
use super::int8;
use crate::ffi::hash::sha3_256;
use crate::tor::dir::consensus::Consensus;

/// A relay's place on the ring, with the identity needed to look it up again
/// in the consensus.
pub struct RingNode {
    pub identity: [u8; 20],
    index: [u8; 32],
}

/// `hs_index(replica) = H("store-at-idx" | A' | INT_8(replica) |
/// INT_8(period_length) | INT_8(period_num))`.
pub fn hs_index(blinded_key: &[u8; 32], replica: u64, period: &TimePeriod) -> [u8; 32] {
    let mut input = Vec::with_capacity(12 + 32 + 24);
    input.extend_from_slice(b"store-at-idx");
    input.extend_from_slice(blinded_key);
    input.extend_from_slice(&int8(replica));
    input.extend_from_slice(&int8(period.length));
    input.extend_from_slice(&int8(period.number));
    sha3_256(&input)
}

/// `hsdir_index(node) = H("node-idx" | node_ed25519_id | SRV |
/// INT_8(period_num) | INT_8(period_length))`.
///
/// Note that the two `INT_8`s come in the opposite order from [`hs_index`].
/// That is what the spec says, and getting it wrong yields a ring that no
/// other Tor implementation agrees with.
pub fn hsdir_index(node_ed_identity: &[u8; 32], srv: &[u8; 32], period: &TimePeriod) -> [u8; 32] {
    let mut input = Vec::with_capacity(8 + 32 + 32 + 16);
    input.extend_from_slice(b"node-idx");
    input.extend_from_slice(node_ed_identity);
    input.extend_from_slice(srv);
    input.extend_from_slice(&int8(period.number));
    input.extend_from_slice(&int8(period.length));
    sha3_256(&input)
}

/// Place every node on the ring, sorted by index, ready for [`responsible`].
pub fn build_ring(
    nodes: impl IntoIterator<Item = ([u8; 20], [u8; 32])>,
    srv: &[u8; 32],
    period: &TimePeriod,
) -> Vec<RingNode> {
    let mut ring: Vec<RingNode> = nodes
        .into_iter()
        .map(|(identity, ed_identity)| RingNode {
            identity,
            index: hsdir_index(&ed_identity, srv, period),
        })
        .collect();
    ring.sort_unstable_by_key(|node| node.index);
    ring
}

/// The nodes a client should ask for this descriptor: `spread_fetch` of them
/// after each replica's index, wrapping past the end of the ring, with any
/// node that a lower-numbered replica already claimed skipped over.
pub fn responsible(
    ring: &[RingNode],
    blinded_key: &[u8; 32],
    period: &TimePeriod,
    n_replicas: u8,
    spread_fetch: usize,
) -> Vec<[u8; 20]> {
    let mut out: Vec<[u8; 20]> = Vec::with_capacity(n_replicas as usize * spread_fetch);
    if ring.is_empty() {
        return out;
    }
    // Replicas are numbered from one, not zero.
    for replica in 1..=n_replicas as u64 {
        let start = hs_index(blinded_key, replica, period);
        let first = ring.partition_point(|node| node.index < start);
        let mut taken = 0;
        for step in 0..ring.len() {
            if taken == spread_fetch {
                break;
            }
            let node = &ring[(first + step) % ring.len()];
            if out.contains(&node.identity) {
                continue;
            }
            out.push(node.identity);
            taken += 1;
        }
    }
    out
}

/// The shared random value a client uses with the *current* time period.
///
/// Time periods turn over at 12:00 UTC and shared random values at 00:00 UTC,
/// so half the day the current period was already running when today's value
/// appeared. rend-spec [CLIENTFETCH] resolves that by pairing period #N with
/// the value that was current when it began: after noon that is
/// `shared-rand-current-value`, before noon it is the previous one.
pub fn shared_random_value(consensus: &Consensus, period: &TimePeriod) -> [u8; 32] {
    let after_noon = consensus.valid_after % 86_400 >= 12 * 3600;
    let (published, number) = if after_noon {
        (consensus.shared_rand_current, period.number)
    } else {
        (
            consensus.shared_rand_previous,
            period.number.wrapping_sub(1),
        )
    };
    published.unwrap_or_else(|| disaster_srv(period.length, number))
}

/// What to use when the authorities published no shared random value at all:
/// `H("shared-random-disaster" | INT_8(period_length) | INT_8(period_num))`.
fn disaster_srv(period_length: u64, period_num: u64) -> [u8; 32] {
    crate::warn!("consensus has no shared random value; using the disaster value");
    let mut input = Vec::with_capacity(22 + 16);
    input.extend_from_slice(b"shared-random-disaster");
    input.extend_from_slice(&int8(period_length));
    input.extend_from_slice(&int8(period_num));
    sha3_256(&input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tor::dir::consensus::Params;
    use crate::util::parse_datetime;

    fn period() -> TimePeriod {
        TimePeriod {
            number: 19_000,
            length: 1440,
        }
    }

    /// Both index formulas, spelled out again from the spec so that a typo in
    /// the implementation cannot pass unnoticed.
    #[test]
    fn index_formulas_match_the_spec() {
        let period = period();
        let blinded = [0x33u8; 32];
        assert_eq!(
            hs_index(&blinded, 1, &period),
            sha3_256(
                &[
                    b"store-at-idx".as_slice(),
                    &blinded,
                    &1u64.to_be_bytes(),
                    &1440u64.to_be_bytes(),
                    &19_000u64.to_be_bytes(),
                ]
                .concat()
            )
        );
        let node = [0x44u8; 32];
        let srv = [0x55u8; 32];
        assert_eq!(
            hsdir_index(&node, &srv, &period),
            sha3_256(
                &[
                    b"node-idx".as_slice(),
                    &node,
                    &srv,
                    &19_000u64.to_be_bytes(),
                    &1440u64.to_be_bytes(),
                ]
                .concat()
            )
        );
        // Replicas land in different places, which is the whole point.
        assert_ne!(
            hs_index(&blinded, 1, &period),
            hs_index(&blinded, 2, &period)
        );
    }

    /// A ring of nodes with known indices, so the walk itself can be checked
    /// rather than the hashing.
    fn ring_of(indices: &[u8]) -> Vec<RingNode> {
        let mut ring: Vec<RingNode> = indices
            .iter()
            .map(|&i| {
                let mut index = [0u8; 32];
                index[0] = i;
                RingNode {
                    identity: [i; 20],
                    index,
                }
            })
            .collect();
        ring.sort_unstable_by_key(|node| node.index);
        ring
    }

    #[test]
    fn walk_starts_at_the_first_node_after_the_replica_index() {
        let ring = ring_of(&[10, 20, 30, 40]);
        let period = period();
        let blinded = [0x77u8; 32];
        let start = hs_index(&blinded, 1, &period);
        let expected = ring
            .iter()
            .find(|node| node.index >= start)
            .unwrap_or(&ring[0])
            .identity;
        assert_eq!(responsible(&ring, &blinded, &period, 1, 1), vec![expected]);
    }

    #[test]
    fn walk_wraps_past_the_end_of_the_ring() {
        let ring = ring_of(&[10, 20, 30, 40]);
        let period = period();
        // A key whose first replica index sits past the last node, so the
        // walk has to come back round to the beginning.
        let blinded = (0u8..=255)
            .map(|seed| [seed; 32])
            .find(|key| hs_index(key, 1, &period) > ring[ring.len() - 1].index)
            .expect("some key lands past the end of the ring");
        assert_eq!(
            responsible(&ring, &blinded, &period, 1, 2),
            vec![[10u8; 20], [20u8; 20]]
        );
    }

    /// A node already claimed by a lower-numbered replica is skipped over, so
    /// the same relay is never asked twice -- and a ring smaller than the
    /// total spread simply runs out instead of looping.
    #[test]
    fn replicas_never_name_the_same_node_twice() {
        let ring = ring_of(&[10, 20, 30, 40]);
        let period = period();
        let chosen = responsible(&ring, &[0x77u8; 32], &period, 2, 3);
        assert_eq!(chosen.len(), 4, "only four nodes exist to choose from");
        let mut sorted = chosen.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), chosen.len());

        let wide = ring_of(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13]);
        assert_eq!(responsible(&wide, &[0x77u8; 32], &period, 2, 3).len(), 6);
        assert!(responsible(&[], &[0x77u8; 32], &period, 2, 3).is_empty());
    }

    /// The ring is built in index order, whatever order the nodes arrive in.
    #[test]
    fn ring_is_sorted_by_index() {
        let period = period();
        let srv = [0x11u8; 32];
        let nodes: Vec<([u8; 20], [u8; 32])> = (1..=20u8).map(|i| ([i; 20], [i; 32])).collect();
        let ring = build_ring(nodes.clone(), &srv, &period);
        assert_eq!(ring.len(), 20);
        assert!(ring.windows(2).all(|w| w[0].index <= w[1].index));
        // Indices are the documented hash, not the arrival order.
        let first = ring[0].identity[0];
        assert_eq!(ring[0].index, hsdir_index(&[first; 32], &srv, &period));
    }

    fn consensus_at(valid_after: &str) -> Consensus {
        Consensus {
            valid_after: parse_datetime("2026-09-02", valid_after).unwrap(),
            fresh_until: 0,
            valid_until: u64::MAX,
            routers: Vec::new(),
            params: Params::default(),
            shared_rand_current: Some([0xccu8; 32]),
            shared_rand_previous: Some([0xbbu8; 32]),
        }
    }

    /// Noon UTC is the switchover: before it the previous value is the one
    /// that was current when this period began.
    #[test]
    fn srv_choice_turns_over_at_noon() {
        let period = period();
        assert_eq!(
            shared_random_value(&consensus_at("11:59:59"), &period),
            [0xbbu8; 32]
        );
        assert_eq!(
            shared_random_value(&consensus_at("12:00:00"), &period),
            [0xccu8; 32]
        );
        assert_eq!(
            shared_random_value(&consensus_at("23:59:59"), &period),
            [0xccu8; 32]
        );
        assert_eq!(
            shared_random_value(&consensus_at("00:00:00"), &period),
            [0xbbu8; 32]
        );
    }

    /// With no published values at all, both halves of the day fall back to
    /// the disaster value -- for different period numbers.
    #[test]
    fn falls_back_to_the_disaster_value() {
        let period = period();
        let mut afternoon = consensus_at("13:00:00");
        afternoon.shared_rand_current = None;
        afternoon.shared_rand_previous = None;
        assert_eq!(
            shared_random_value(&afternoon, &period),
            disaster_srv(1440, 19_000)
        );

        let mut morning = consensus_at("01:00:00");
        morning.shared_rand_current = None;
        morning.shared_rand_previous = None;
        assert_eq!(
            shared_random_value(&morning, &period),
            disaster_srv(1440, 18_999)
        );
        assert_ne!(disaster_srv(1440, 1), disaster_srv(720, 1));
    }
}
