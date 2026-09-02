//! Microdescriptors (dir-spec/computing-microdescriptors.md).
//!
//! A microdescriptor supplies the two things the consensus leaves out: the
//! relay's ntor onion key, which every handshake needs, and its exit policy
//! summary. Its identity is the SHA-256 of its own text, running from the
//! `onion-key` line that opens it to the byte before the next one.

use std::io;

use super::netdoc;
use crate::ffi::hash::sha256;
use crate::util::invalid_data;

/// An exit policy summary: `p accept 80,443` or `p reject 25,119-135`.
#[derive(Clone)]
pub struct PortPolicy {
    is_accept: bool,
    ranges: Vec<(u16, u16)>,
}

impl PortPolicy {
    /// The default when a microdescriptor carries no `p` line: reject
    /// everything, which keeps such a relay out of the exit position.
    pub fn reject_all() -> Self {
        Self {
            is_accept: false,
            ranges: vec![(1, 65535)],
        }
    }

    pub fn parse(args: &str) -> io::Result<Self> {
        let (verb, list) = args
            .split_once(' ')
            .ok_or_else(|| invalid_data("malformed exit policy summary"))?;
        let is_accept = match verb {
            "accept" => true,
            "reject" => false,
            other => return Err(invalid_data(format!("unknown exit policy verb {other:?}"))),
        };
        let mut ranges = Vec::new();
        for entry in list.split(',') {
            let (low, high) = match entry.split_once('-') {
                Some((low, high)) => (low, high),
                None => (entry, entry),
            };
            let low: u16 = low
                .parse()
                .map_err(|_| invalid_data(format!("bad port {low:?}")))?;
            let high: u16 = high
                .parse()
                .map_err(|_| invalid_data(format!("bad port {high:?}")))?;
            if low > high {
                return Err(invalid_data("exit policy range is inverted"));
            }
            ranges.push((low, high));
        }
        Ok(Self { is_accept, ranges })
    }

    pub fn allows(&self, port: u16) -> bool {
        let listed = self
            .ranges
            .iter()
            .any(|(low, high)| (*low..=*high).contains(&port));
        listed == self.is_accept
    }

    /// True if the policy permits nothing at all, so the relay is no use as
    /// an exit.
    pub fn is_empty(&self) -> bool {
        !self.is_accept && self.ranges.contains(&(1, 65535))
    }
}

pub struct Microdesc {
    pub digest: [u8; 32],
    pub ntor_onion_key: [u8; 32],
    pub ed_identity: Option<[u8; 32]>,
    pub exit_policy: PortPolicy,
    /// Family members given as `$HEX` fingerprints. Nickname-only entries are
    /// dropped: resolving them would mean keeping the whole nickname table.
    pub family: Vec<[u8; 20]>,
}

impl Microdesc {
    /// Parse one microdescriptor, given its exact text.
    pub fn parse(text: &str) -> io::Result<Self> {
        if !text.starts_with("onion-key") {
            return Err(invalid_data(
                "microdescriptor does not start with onion-key",
            ));
        }
        let ntor = netdoc::item(text, "ntor-onion-key")
            .ok_or_else(|| invalid_data("microdescriptor has no ntor-onion-key"))?;
        let ntor_onion_key = netdoc::base64_fixed::<32>(ntor.trim())?;

        let ed_identity = netdoc::item(text, "id").and_then(|args| {
            let (kind, value) = args.split_once(' ')?;
            if kind != "ed25519" {
                return None;
            }
            netdoc::base64_fixed::<32>(value.trim()).ok()
        });

        let exit_policy = match netdoc::item(text, "p") {
            Some(args) => PortPolicy::parse(args)?,
            None => PortPolicy::reject_all(),
        };

        let mut family = Vec::new();
        if let Some(args) = netdoc::item(text, "family") {
            for entry in args.split_whitespace() {
                if let Some(hex) = entry.strip_prefix('$') {
                    // Entries may be "$FINGERPRINT=nickname" or "$FINGERPRINT~nickname".
                    let hex = hex.split(['=', '~']).next().unwrap_or(hex);
                    if let Ok(bytes) = crate::util::hex_decode(hex) {
                        if let Ok(id) = <[u8; 20]>::try_from(bytes) {
                            family.push(id);
                        }
                    }
                }
            }
        }

        Ok(Self {
            digest: sha256(text.as_bytes()),
            ntor_onion_key,
            ed_identity,
            exit_policy,
            family,
        })
    }

    pub fn shares_family_with(&self, identity: &[u8; 20]) -> bool {
        self.family.contains(identity)
    }
}

/// Split a `/tor/micro/d/...` response into individual microdescriptors and
/// parse each one, keeping the exact text each was parsed from so it can be
/// cached verbatim. Malformed entries are skipped rather than failing the
/// batch.
pub fn parse_batch(text: &str) -> Vec<(&str, Microdesc)> {
    let mut starts: Vec<usize> = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = netdoc::line_start_of(&text[offset..], "onion-key") {
        let absolute = offset + relative;
        starts.push(absolute);
        // Step past this line so the next search finds the following entry.
        offset = absolute
            + text[absolute..]
                .find('\n')
                .map(|i| i + 1)
                .unwrap_or(text.len() - absolute);
        if offset >= text.len() {
            break;
        }
    }

    let mut out = Vec::with_capacity(starts.len());
    for (index, start) in starts.iter().enumerate() {
        let end = starts.get(index + 1).copied().unwrap_or(text.len());
        let body = &text[*start..end];
        match Microdesc::parse(body) {
            Ok(md) => out.push((body, md)),
            Err(e) => crate::debug!("skipping microdescriptor: {e}"),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::base64_encode_unpadded;

    fn one(ntor: [u8; 32], policy: &str) -> String {
        format!(
            "onion-key\nntor-onion-key {}\nid ed25519 {}\n{policy}\n",
            base64_encode_unpadded(&ntor),
            base64_encode_unpadded(&[0x77u8; 32]),
        )
    }

    #[test]
    fn parses_keys_and_policy() {
        let text = one([0x42u8; 32], "p accept 80,443,8000-8100");
        let md = Microdesc::parse(&text).unwrap();
        assert_eq!(md.ntor_onion_key, [0x42u8; 32]);
        assert_eq!(md.ed_identity, Some([0x77u8; 32]));
        assert_eq!(md.digest, sha256(text.as_bytes()));
        assert!(md.exit_policy.allows(80));
        assert!(md.exit_policy.allows(8050));
        assert!(md.exit_policy.allows(8100));
        assert!(!md.exit_policy.allows(8101));
        assert!(!md.exit_policy.allows(22));
    }

    #[test]
    fn reject_policies_invert() {
        let md = Microdesc::parse(&one([1u8; 32], "p reject 25,119,135-139")).unwrap();
        assert!(!md.exit_policy.allows(25));
        assert!(!md.exit_policy.allows(137));
        assert!(md.exit_policy.allows(443));
        assert!(!md.exit_policy.is_empty());

        // No p line at all means the relay exits nowhere.
        let text =
            "onion-key\nntor-onion-key ".to_string() + &base64_encode_unpadded(&[2u8; 32]) + "\n";
        let md = Microdesc::parse(&text).unwrap();
        assert!(!md.exit_policy.allows(80));
        assert!(md.exit_policy.is_empty());
    }

    #[test]
    fn parses_family_fingerprints() {
        let text = format!(
            "onion-key\nntor-onion-key {}\nfamily $AABBCCDDEEFF00112233445566778899AABBCCDD=nick Nickname $00112233445566778899AABBCCDDEEFF00112233\np reject 1-65535\n",
            base64_encode_unpadded(&[3u8; 32])
        );
        let md = Microdesc::parse(&text).unwrap();
        assert_eq!(md.family.len(), 2, "nickname-only entries are dropped");
        assert_eq!(md.family[0][0], 0xaa);
        assert!(md.shares_family_with(&md.family[1]));
        assert!(!md.shares_family_with(&[0u8; 20]));
    }

    /// Each entry's digest must be over its own text only, so that the
    /// consensus `m` line can be matched against it.
    #[test]
    fn splits_a_batch_at_each_onion_key() {
        let a = one([0xa1u8; 32], "p accept 443");
        let b = one([0xb2u8; 32], "p reject 1-65535");
        let batch = format!("{a}{b}");
        let parsed = parse_batch(&batch);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].1.ntor_onion_key, [0xa1u8; 32]);
        assert_eq!(parsed[1].1.ntor_onion_key, [0xb2u8; 32]);
        assert_eq!(parsed[0].1.digest, sha256(a.as_bytes()));
        assert_eq!(parsed[1].1.digest, sha256(b.as_bytes()));
        // The text handed back must be exactly what was hashed.
        assert_eq!(parsed[0].0, a);
        assert_eq!(parsed[1].0, b);
    }

    #[test]
    fn rejects_malformed_entries() {
        assert!(Microdesc::parse("ntor-onion-key AAAA\n").is_err());
        assert!(Microdesc::parse("onion-key\n").is_err());
        assert!(PortPolicy::parse("accept 100-1").is_err());
        assert!(PortPolicy::parse("maybe 80").is_err());
        assert!(PortPolicy::parse("accept").is_err());
    }
}
