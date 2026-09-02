//! Time periods and key blinding (rend-spec/deriving-keys.md, appendix
//! [KEYBLIND]).
//!
//! Every time period the service signs its descriptor with a different key
//! derived from its identity, and clients look the descriptor up under the
//! matching blinded public key `A' = h * A`. That is what stops a directory
//! node from recognising which service it is holding a descriptor for, and
//! what makes the set of nodes holding it move over time.

use std::io;

use super::int8;
use crate::crypto::ed25519_point;
use crate::ffi::hash::sha3_256;

/// `hsdir-interval` default, in minutes (one day).
pub const DEFAULT_PERIOD_LENGTH: u64 = 1440;

/// Time periods are offset from the Unix epoch by twelve hours, so that they
/// begin at 12:00 UTC rather than midnight -- half a day out of phase with the
/// shared random value, which rotates at 00:00 UTC.
const ROTATION_OFFSET_MINUTES: u64 = 12 * 60;

/// The blinding hash's fixed parts. `BLIND_STRING` ends in a NUL byte, and the
/// base point goes in as its *decimal* representation, brackets and all.
const BLIND_STRING: &[u8] = b"Derive temporary signing key\x00";
const BASEPOINT_STRING: &[u8] = b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)";

/// One time period: its number since the (offset) epoch and its length.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TimePeriod {
    pub number: u64,
    /// Length in minutes.
    pub length: u64,
}

impl TimePeriod {
    /// The period a moment falls in.
    ///
    /// Callers pass the consensus `valid-after`, not the system clock: every
    /// party on the network reads the same value out of the same document, so
    /// a skewed local clock cannot put us in a different period from the
    /// directory nodes.
    pub fn containing(valid_after_unix: u64, length_minutes: u64) -> Self {
        let length = length_minutes.max(1);
        let minutes = valid_after_unix / 60;
        Self {
            number: minutes.saturating_sub(ROTATION_OFFSET_MINUTES) / length,
            length,
        }
    }

    /// `h = H(BLIND_STRING | A | s | B | N)`, unclamped. `s` is the optional
    /// client-authorisation secret, which this client never has, so it is
    /// empty and contributes nothing.
    pub fn blinding_param(&self, public_key: &[u8; 32]) -> [u8; 32] {
        let mut input = Vec::with_capacity(BLIND_STRING.len() + 32 + BASEPOINT_STRING.len() + 25);
        input.extend_from_slice(BLIND_STRING);
        input.extend_from_slice(public_key);
        input.extend_from_slice(BASEPOINT_STRING);
        input.extend_from_slice(b"key-blind");
        input.extend_from_slice(&int8(self.number));
        input.extend_from_slice(&int8(self.length));
        sha3_256(&input)
    }

    /// `A' = h * A`: the key this period's descriptor is signed with and
    /// indexed under.
    pub fn blinded_key(&self, public_key: &[u8; 32]) -> io::Result<[u8; 32]> {
        ed25519_point::blind_public_key(public_key, &self.blinding_param(public_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tor::hs::address::OnionAddress;
    use crate::util::parse_datetime;

    /// The worked example in rend-spec: 2016-04-13 12:00 UTC is where period
    /// 16903 ends and 16904 begins.
    #[test]
    fn period_boundary_is_noon_utc() {
        let just_before = parse_datetime("2016-04-13", "11:59:59").unwrap();
        let at_noon = parse_datetime("2016-04-13", "12:00:00").unwrap();
        assert_eq!(
            TimePeriod::containing(just_before, DEFAULT_PERIOD_LENGTH).number,
            16903
        );
        assert_eq!(
            TimePeriod::containing(at_noon, DEFAULT_PERIOD_LENGTH).number,
            16904
        );
        // The spec's other example: 11:15:01 on the same day is still 16903.
        assert_eq!(
            TimePeriod::containing(1_460_546_101, DEFAULT_PERIOD_LENGTH).number,
            16903
        );
        // A day later is the next period, and only one.
        assert_eq!(
            TimePeriod::containing(at_noon + 86_399, DEFAULT_PERIOD_LENGTH).number,
            16904
        );
        assert_eq!(
            TimePeriod::containing(at_noon + 86_400, DEFAULT_PERIOD_LENGTH).number,
            16905
        );
    }

    /// A shorter interval, as the consensus may set, still starts from the
    /// same offset epoch.
    #[test]
    fn honours_a_non_default_interval() {
        let noon = parse_datetime("2016-04-13", "12:00:00").unwrap();
        assert_eq!(TimePeriod::containing(noon, 720).number, 16904 * 2);
        assert_eq!(
            TimePeriod::containing(noon + 720 * 60, 720).number,
            16904 * 2 + 1
        );
        // A nonsensical length must not divide by zero.
        assert!(TimePeriod::containing(noon, 0).number > 0);
    }

    #[test]
    fn blinding_param_covers_every_documented_field() {
        let period = TimePeriod {
            number: 16904,
            length: 1440,
        };
        let key = [0x11u8; 32];
        let expected = sha3_256(
            &[
                b"Derive temporary signing key\x00".as_slice(),
                &key,
                BASEPOINT_STRING,
                b"key-blind",
                &16904u64.to_be_bytes(),
                &1440u64.to_be_bytes(),
            ]
            .concat(),
        );
        assert_eq!(period.blinding_param(&key), expected);

        // Both the period number and its length must change the result.
        let other = TimePeriod {
            number: 16905,
            length: 1440,
        };
        assert_ne!(period.blinding_param(&key), other.blinding_param(&key));
        let shorter = TimePeriod {
            number: 16904,
            length: 720,
        };
        assert_ne!(period.blinding_param(&key), shorter.blinding_param(&key));
    }

    /// End to end: a real address blinds to a valid curve point, and to a
    /// different one each period.
    #[test]
    fn blinds_a_real_address() {
        let address =
            OnionAddress::parse("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion")
                .unwrap();
        let period = TimePeriod {
            number: 19_000,
            length: DEFAULT_PERIOD_LENGTH,
        };
        let blinded = period.blinded_key(&address.public_key).unwrap();
        assert_ne!(blinded, address.public_key);
        assert_ne!(blinded, [0u8; 32]);

        let next = TimePeriod {
            number: 19_001,
            length: DEFAULT_PERIOD_LENGTH,
        };
        assert_ne!(blinded, next.blinded_key(&address.public_key).unwrap());
        // Deterministic: the same period always gives the same key.
        assert_eq!(blinded, period.blinded_key(&address.public_key).unwrap());
    }
}
