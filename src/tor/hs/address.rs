//! `.onion` addresses (rend-spec/encoding-onion-addresses.md).
//!
//! ```text
//! onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
//! CHECKSUM      = SHA3_256(".onion checksum" | PUBKEY | VERSION)[:2]
//! ```
//!
//! so a v3 address is 35 bytes, which is 56 base32 characters. The 16-character
//! v2 addresses are a different (and retired) protocol, and are rejected here
//! with a message that says so.

use std::fmt;
use std::io;

use crate::crypto::base32;
use crate::ffi::hash::sha3_256;
use crate::util::invalid_data;

pub const SUFFIX: &str = ".onion";
const VERSION: u8 = 0x03;
const ADDRESS_CHARS: usize = 56;
const V2_ADDRESS_CHARS: usize = 16;

/// A validated v3 onion address: really just the service's master public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OnionAddress {
    /// `KP_hs_id`, the service's long-term Ed25519 identity.
    pub public_key: [u8; 32],
}

/// True if `host` ends in `.onion`, whatever case it was typed in.
pub fn is_onion(host: &str) -> bool {
    host.len() > SUFFIX.len() && host[host.len() - SUFFIX.len()..].eq_ignore_ascii_case(SUFFIX)
}

impl OnionAddress {
    /// Parse a host name that [`is_onion`] accepted.
    pub fn parse(host: &str) -> io::Result<Self> {
        let body = match host.len().checked_sub(SUFFIX.len()) {
            Some(cut) if host[cut..].eq_ignore_ascii_case(SUFFIX) => &host[..cut],
            _ => host,
        };
        if body.len() == V2_ADDRESS_CHARS {
            return Err(invalid_data(
                "version 2 onion addresses are no longer part of the Tor network",
            ));
        }
        if body.len() != ADDRESS_CHARS {
            return Err(invalid_data(format!(
                "an onion address is {ADDRESS_CHARS} characters, this one is {}",
                body.len()
            )));
        }
        let raw = base32::decode(body)?;
        if raw.len() != 35 {
            return Err(invalid_data("onion address does not decode to 35 bytes"));
        }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&raw[..32]);
        let version = raw[34];
        if version != VERSION {
            return Err(invalid_data(format!(
                "unsupported onion address version {version}"
            )));
        }
        if raw[32..34] != checksum(&public_key)[..] {
            return Err(invalid_data("onion address checksum does not match"));
        }
        Ok(Self { public_key })
    }

    /// `N_hs_cred = H("credential" | KP_hs_id)`.
    pub fn credential(&self) -> [u8; 32] {
        let mut input = Vec::with_capacity(10 + 32);
        input.extend_from_slice(b"credential");
        input.extend_from_slice(&self.public_key);
        sha3_256(&input)
    }

    /// `N_hs_subcred = H("subcredential" | N_hs_cred | A')`: the per-period
    /// secret that descriptor decryption and the introduction handshake share.
    pub fn subcredential(&self, blinded_key: &[u8; 32]) -> [u8; 32] {
        let mut input = Vec::with_capacity(13 + 32 + 32);
        input.extend_from_slice(b"subcredential");
        input.extend_from_slice(&self.credential());
        input.extend_from_slice(blinded_key);
        sha3_256(&input)
    }
}

fn checksum(public_key: &[u8; 32]) -> [u8; 2] {
    let mut input = Vec::with_capacity(15 + 32 + 1);
    input.extend_from_slice(b".onion checksum");
    input.extend_from_slice(public_key);
    input.push(VERSION);
    let digest = sha3_256(&input);
    [digest[0], digest[1]]
}

impl fmt::Display for OnionAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut raw = Vec::with_capacity(35);
        raw.extend_from_slice(&self.public_key);
        raw.extend_from_slice(&checksum(&self.public_key));
        raw.push(VERSION);
        write!(f, "{}{SUFFIX}", base32::encode(&raw))
    }
}

/// Addresses are only ever logged at `debug`, so `Debug` must not become a way
/// for one to escape into an `info` line by accident.
impl fmt::Debug for OnionAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OnionAddress(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three examples in rend-spec/encoding-onion-addresses.md.
    const EXAMPLES: [&str; 3] = [
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd",
        "sp3k262uwy4r2k3ycr5awluarykdpag6a7y33jxop4cs2lu5uz5sseqd",
        "xa4r2iadxm55fbnqgwwi5mymqdcofiu3w6rpbtqn7b2dyn7mgwj64jyd",
    ];

    #[test]
    fn parses_and_reprints_the_spec_examples() {
        for example in EXAMPLES {
            let with_suffix = format!("{example}.onion");
            let parsed = OnionAddress::parse(&with_suffix).expect(example);
            assert_eq!(parsed.to_string(), with_suffix);
            // The suffix is optional on input, and case does not matter.
            assert_eq!(OnionAddress::parse(example).unwrap(), parsed);
            assert_eq!(
                OnionAddress::parse(&with_suffix.to_uppercase()).unwrap(),
                parsed
            );
        }
    }

    #[test]
    fn recognises_the_suffix() {
        assert!(is_onion("abc.onion"));
        assert!(is_onion("ABC.ONION"));
        assert!(!is_onion(".onion"), "the suffix alone is not an address");
        assert!(!is_onion("example.com"));
        assert!(!is_onion("onion"));
    }

    #[test]
    fn rejects_a_broken_checksum() {
        // Flip one character of the payload; the checksum must catch it.
        let mut chars: Vec<char> = EXAMPLES[0].chars().collect();
        chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
        let broken: String = chars.into_iter().collect();
        let err = OnionAddress::parse(&broken).unwrap_err();
        assert!(err.to_string().contains("checksum"), "{err}");
    }

    #[test]
    fn rejects_v2_and_malformed_addresses() {
        let err = OnionAddress::parse("expyuzz4wqqyqhjn.onion").unwrap_err();
        assert!(err.to_string().contains("version 2"), "{err}");
        assert!(OnionAddress::parse("short.onion").is_err());
        assert!(OnionAddress::parse("").is_err());
        // Right length, but not base32.
        assert!(OnionAddress::parse(&"1".repeat(56)).is_err());
    }

    /// The two derivations feed descriptor decryption and hs-ntor, so they
    /// have to be exactly the documented hashes and nothing else.
    #[test]
    fn credential_and_subcredential_follow_the_formulas() {
        let address = OnionAddress::parse(EXAMPLES[0]).unwrap();
        let credential = sha3_256(&[b"credential".as_slice(), &address.public_key].concat());
        assert_eq!(address.credential(), credential);

        let blinded = [0x5au8; 32];
        assert_eq!(
            address.subcredential(&blinded),
            sha3_256(&[b"subcredential".as_slice(), &credential, &blinded].concat())
        );
        // A different period gives a different subcredential.
        assert_ne!(
            address.subcredential(&blinded),
            address.subcredential(&[0x5bu8; 32])
        );
    }

    #[test]
    fn debug_does_not_leak_the_address() {
        let address = OnionAddress::parse(EXAMPLES[0]).unwrap();
        assert_eq!(format!("{address:?}"), "OnionAddress(..)");
    }
}
