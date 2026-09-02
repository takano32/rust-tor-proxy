//! The microdescriptor consensus: parsing and signature verification
//! (dir-spec/consensus-formats.md).
//!
//! The document is around 2.5MB of text describing roughly eight thousand
//! relays. Nothing of it is kept: each `r`/`m`/`s`/`w` group is folded into a
//! fixed 64-byte [`RouterStatus`] and the text is dropped, which is what keeps
//! this usable on a 128MB machine.

use std::io;

use super::authority::{self, KeyCertificate, AUTHORITIES};
use super::netdoc;
use crate::ffi::hash::{sha1, sha256};
use crate::util::{hex_decode, invalid_data, parse_datetime};

pub const FLAG_AUTHORITY: u16 = 1 << 0;
pub const FLAG_BAD_EXIT: u16 = 1 << 1;
pub const FLAG_EXIT: u16 = 1 << 2;
pub const FLAG_FAST: u16 = 1 << 3;
pub const FLAG_GUARD: u16 = 1 << 4;
pub const FLAG_HSDIR: u16 = 1 << 5;
pub const FLAG_MIDDLE_ONLY: u16 = 1 << 6;
pub const FLAG_RUNNING: u16 = 1 << 7;
pub const FLAG_STABLE: u16 = 1 << 8;
pub const FLAG_V2DIR: u16 = 1 << 9;
pub const FLAG_VALID: u16 = 1 << 10;

fn flag_bit(name: &str) -> u16 {
    match name {
        "Authority" => FLAG_AUTHORITY,
        "BadExit" => FLAG_BAD_EXIT,
        "Exit" => FLAG_EXIT,
        "Fast" => FLAG_FAST,
        "Guard" => FLAG_GUARD,
        "HSDir" => FLAG_HSDIR,
        "MiddleOnly" => FLAG_MIDDLE_ONLY,
        "Running" => FLAG_RUNNING,
        "Stable" => FLAG_STABLE,
        "V2Dir" => FLAG_V2DIR,
        "Valid" => FLAG_VALID,
        _ => 0,
    }
}

/// One relay's entry, reduced to what path selection actually needs.
#[derive(Clone)]
pub struct RouterStatus {
    /// SHA-1 of the DER RSA identity key.
    pub identity: [u8; 20],
    /// SHA-256 of the relay's microdescriptor, from the `m` line.
    pub microdesc_digest: [u8; 32],
    pub ipv4: [u8; 4],
    pub or_port: u16,
    pub flags: u16,
    /// Consensus bandwidth weight, in kilobytes per second.
    pub bandwidth: u32,
}

impl RouterStatus {
    pub fn has(&self, flags: u16) -> bool {
        self.flags & flags == flags
    }

    /// The /16 an address belongs to, used to keep a path from doubling up on
    /// one operator's network.
    pub fn subnet16(&self) -> [u8; 2] {
        [self.ipv4[0], self.ipv4[1]]
    }
}

/// The consensus parameters this client reads (param-spec.md). Everything
/// else on the `params` line is dropped with the rest of the text.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Params {
    /// `hsdir-interval`: the length of a time period, in minutes.
    pub hsdir_interval: u64,
    /// How many places in the hash ring a descriptor is stored at.
    pub hsdir_n_replicas: u8,
    /// How many nodes after each of those places a client may fetch from.
    pub hsdir_spread_fetch: usize,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            hsdir_interval: 1440,
            hsdir_n_replicas: 2,
            hsdir_spread_fetch: 3,
        }
    }
}

impl Params {
    /// Parse a `params` line, keeping defaults for anything absent or out of
    /// the range the spec allows.
    fn parse(args: &str) -> Self {
        let mut out = Self::default();
        for field in args.split_whitespace() {
            let Some((key, value)) = field.split_once('=') else {
                continue;
            };
            match key {
                "hsdir-interval" => {
                    if let Some(v) = value.parse().ok().filter(|v| (30..=14_400).contains(v)) {
                        out.hsdir_interval = v;
                    }
                }
                "hsdir_n_replicas" => {
                    if let Some(v) = value.parse().ok().filter(|v| (1..=16).contains(v)) {
                        out.hsdir_n_replicas = v;
                    }
                }
                "hsdir_spread_fetch" => {
                    if let Some(v) = value.parse().ok().filter(|v| (1..=128).contains(v)) {
                        out.hsdir_spread_fetch = v;
                    }
                }
                _ => {}
            }
        }
        out
    }
}

pub struct Consensus {
    pub valid_after: u64,
    pub fresh_until: u64,
    pub valid_until: u64,
    pub routers: Vec<RouterStatus>,
    pub params: Params,
    /// The two shared random values, when the authorities published them
    /// (proposal 250). Absent only if the shared-randomness protocol failed.
    pub shared_rand_current: Option<[u8; 32]>,
    pub shared_rand_previous: Option<[u8; 32]>,
}

impl Consensus {
    pub fn is_live(&self, now: u64) -> bool {
        now < self.valid_until
    }

    pub fn count_with(&self, flags: u16) -> usize {
        self.routers.iter().filter(|r| r.has(flags)).count()
    }
}

/// Which authorities signed this consensus, and with which signing key.
struct Signature<'a> {
    algorithm: &'a str,
    identity: [u8; 20],
    signing_key_digest: [u8; 20],
    value: Vec<u8>,
}

/// Verify a microdescriptor consensus and parse it.
///
/// A consensus is accepted only when more than half of the embedded
/// authorities have a valid signature on it, and only while it is still
/// within its `valid-until`.
pub fn parse_and_verify(text: &str, certs: &[KeyCertificate], now: u64) -> io::Result<Consensus> {
    let header = text
        .lines()
        .next()
        .ok_or_else(|| invalid_data("empty consensus"))?;
    if header != "network-status-version 3 microdesc" {
        return Err(invalid_data(format!(
            "not a microdescriptor consensus: {header:?}"
        )));
    }

    let signed_len = signed_length(text)?;
    let signed = &text.as_bytes()[..signed_len];
    let digest_sha1 = sha1(signed);
    let digest_sha256 = sha256(signed);

    let mut signers: Vec<[u8; 20]> = Vec::new();
    for signature in signatures(&text[signed_len..]) {
        let digest: &[u8] = match signature.algorithm {
            "sha256" => &digest_sha256,
            "sha1" => &digest_sha1,
            // Unrecognized algorithms must be ignored, not rejected.
            _ => continue,
        };
        let Some(cert) = certs.iter().find(|c| {
            c.v3ident == signature.identity && c.signing_key_digest == signature.signing_key_digest
        }) else {
            continue;
        };
        if !AUTHORITIES.iter().any(|a| a.v3ident == signature.identity) {
            continue;
        }
        if cert.signing_key.verify_digest(digest, &signature.value)
            && !signers.contains(&signature.identity)
        {
            signers.push(signature.identity);
        }
    }

    let needed = authority::required_signatures();
    if signers.len() < needed {
        return Err(invalid_data(format!(
            "consensus has {} valid authority signatures, need {needed}",
            signers.len()
        )));
    }

    let valid_after = timestamp(text, "valid-after")?;
    let fresh_until = timestamp(text, "fresh-until")?;
    let valid_until = timestamp(text, "valid-until")?;
    if now >= valid_until {
        return Err(invalid_data(format!(
            "consensus expired at {} (valid-after {}, local clock says {})",
            crate::util::format_datetime(valid_until),
            crate::util::format_datetime(valid_after),
            crate::util::format_datetime(now)
        )));
    }

    let routers = parse_routers(&text[..signed_len])?;
    if routers.is_empty() {
        return Err(invalid_data("consensus lists no routers"));
    }
    Ok(Consensus {
        valid_after,
        fresh_until,
        valid_until,
        routers,
        params: netdoc::item(text, "params")
            .map(Params::parse)
            .unwrap_or_default(),
        shared_rand_current: shared_random(text, "shared-rand-current-value"),
        shared_rand_previous: shared_random(text, "shared-rand-previous-value"),
    })
}

/// `"shared-rand-current-value" SP NUM_REVEALS SP VALUE`, where the value is
/// 32 base64 bytes.
fn shared_random(text: &str, keyword: &str) -> Option<[u8; 32]> {
    let args = netdoc::item(text, keyword)?;
    let value = args.split_whitespace().nth(1)?;
    netdoc::base64_fixed::<32>(value).ok()
}

/// How much of the document the signatures cover: everything up to and
/// including the space after the first `directory-signature` keyword.
fn signed_length(text: &str) -> io::Result<usize> {
    let start = netdoc::line_start_of(text, "directory-signature ")
        .ok_or_else(|| invalid_data("consensus has no directory-signature"))?;
    Ok(start + "directory-signature ".len())
}

fn signatures(tail: &str) -> Vec<Signature<'_>> {
    let mut out = Vec::new();
    let mut rest = tail;
    // The first keyword was consumed by signed_length, so the first block
    // starts with its arguments; later blocks start at their own keyword.
    let mut first = true;
    loop {
        let (args_line, body) = if first {
            first = false;
            match rest.split_once('\n') {
                Some(pair) => pair,
                None => break,
            }
        } else {
            let Some(start) = netdoc::line_start_of(rest, "directory-signature ") else {
                break;
            };
            let after = &rest[start + "directory-signature ".len()..];
            match after.split_once('\n') {
                Some(pair) => pair,
                None => break,
            }
        };
        let end = match body.find("-----END SIGNATURE-----") {
            Some(i) => i + "-----END SIGNATURE-----".len(),
            None => break,
        };
        if let Some(signature) = parse_signature(args_line, &body[..end]) {
            out.push(signature);
        }
        rest = &body[end..];
    }
    out
}

fn parse_signature<'a>(args: &'a str, body: &str) -> Option<Signature<'a>> {
    let fields: Vec<&str> = args.split_whitespace().collect();
    // "sha1" is the default when no algorithm is named.
    let (algorithm, identity_hex, key_hex) = match fields.len() {
        2 => ("sha1", fields[0], fields[1]),
        3 => (fields[0], fields[1], fields[2]),
        _ => return None,
    };
    let identity: [u8; 20] = hex_decode(identity_hex).ok()?.try_into().ok()?;
    let signing_key_digest: [u8; 20] = hex_decode(key_hex).ok()?.try_into().ok()?;
    let value = netdoc::object(body, "SIGNATURE").ok()?;
    Some(Signature {
        algorithm,
        identity,
        signing_key_digest,
        value,
    })
}

/// The (authority identity, signing key) pairs this consensus is signed with,
/// restricted to authorities we trust. Used to ask a directory cache for
/// exactly the key certificates we are missing.
pub fn required_certificates(text: &str) -> Vec<([u8; 20], [u8; 20])> {
    let Ok(signed_len) = signed_length(text) else {
        return Vec::new();
    };
    signatures(&text[signed_len..])
        .into_iter()
        .filter(|s| AUTHORITIES.iter().any(|a| a.v3ident == s.identity))
        .map(|s| (s.identity, s.signing_key_digest))
        .collect()
}

fn timestamp(text: &str, keyword: &str) -> io::Result<u64> {
    let args = netdoc::item(text, keyword)
        .ok_or_else(|| invalid_data(format!("consensus has no {keyword}")))?;
    let (date, time) = args
        .split_once(' ')
        .ok_or_else(|| invalid_data(format!("bad {keyword}")))?;
    parse_datetime(date, time.split(' ').next().unwrap_or(time))
}

fn parse_routers(text: &str) -> io::Result<Vec<RouterStatus>> {
    let mut routers: Vec<RouterStatus> = Vec::new();
    let mut current: Option<RouterStatus> = None;

    for line in text.lines() {
        if let Some(args) = netdoc::item_args(line, "r") {
            if let Some(done) = current.take() {
                push_if_usable(&mut routers, done);
            }
            current = parse_r_line(args);
        } else if let Some(args) = netdoc::item_args(line, "m") {
            if let Some(router) = current.as_mut() {
                match netdoc::base64_fixed::<32>(args.split(' ').next().unwrap_or(args)) {
                    Ok(digest) => router.microdesc_digest = digest,
                    // Without a microdescriptor digest the relay is unusable;
                    // leaving the digest zeroed makes push_if_usable drop it.
                    Err(_) => router.microdesc_digest = [0u8; 32],
                }
            }
        } else if let Some(args) = netdoc::item_args(line, "s") {
            if let Some(router) = current.as_mut() {
                router.flags = args.split_whitespace().map(flag_bit).fold(0, |a, b| a | b);
            }
        } else if let Some(args) = netdoc::item_args(line, "w") {
            if let Some(router) = current.as_mut() {
                for field in args.split_whitespace() {
                    if let Some(value) = field.strip_prefix("Bandwidth=") {
                        router.bandwidth = value.parse().unwrap_or(0);
                    }
                }
            }
        } else if line.starts_with("directory-signature") || line.starts_with("directory-footer") {
            break;
        }
    }
    if let Some(done) = current.take() {
        push_if_usable(&mut routers, done);
    }
    Ok(routers)
}

fn push_if_usable(routers: &mut Vec<RouterStatus>, router: RouterStatus) {
    if router.microdesc_digest != [0u8; 32] && router.or_port != 0 {
        routers.push(router);
    }
}

/// `r nickname identity [descriptor-digest] date time IP ORPort DirPort`.
///
/// The microdescriptor flavour omits the descriptor digest, so the field
/// count is what distinguishes the two layouts.
fn parse_r_line(args: &str) -> Option<RouterStatus> {
    let fields: Vec<&str> = args.split_whitespace().collect();
    let (identity_b64, address_fields) = match fields.len() {
        7 => (fields[1], &fields[4..]),
        8 => (fields[1], &fields[5..]),
        _ => return None,
    };
    let identity: [u8; 20] = netdoc::base64_fixed::<20>(identity_b64).ok()?;
    let mut ipv4 = [0u8; 4];
    for (slot, part) in ipv4.iter_mut().zip(address_fields[0].split('.')) {
        *slot = part.parse().ok()?;
    }
    if address_fields[0].split('.').count() != 4 {
        return None;
    }
    let or_port: u16 = address_fields[1].parse().ok()?;
    Some(RouterStatus {
        identity,
        microdesc_digest: [0u8; 32],
        ipv4,
        or_port,
        flags: 0,
        bandwidth: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::base64_encode_unpadded;

    fn sample(signature_block: &str) -> String {
        format!(
            "network-status-version 3 microdesc\n\
             vote-status consensus\n\
             valid-after 2026-09-02 10:00:00\n\
             fresh-until 2026-09-02 11:00:00\n\
             valid-until 2026-09-02 13:00:00\n\
             r Alpha {id} 2026-09-02 09:00:00 1.2.3.4 9001 0\n\
             m {md}\n\
             s Fast Guard Running Stable V2Dir Valid\n\
             w Bandwidth=4500\n\
             r Beta {id2} 2026-09-02 09:00:00 5.6.7.8 443 0\n\
             m {md2}\n\
             s Exit Fast Running Valid\n\
             w Bandwidth=17000\n\
             directory-footer\n\
             {signature_block}",
            id = base64_encode_unpadded(&[0x11u8; 20]),
            md = base64_encode_unpadded(&[0x22u8; 32]),
            id2 = base64_encode_unpadded(&[0x33u8; 20]),
            md2 = base64_encode_unpadded(&[0x44u8; 32]),
        )
    }

    #[test]
    fn signed_region_stops_after_the_first_keyword_space() {
        let doc = sample(
            "directory-signature sha256 AABB CCDD\n-----BEGIN SIGNATURE-----\naGk=\n-----END SIGNATURE-----\n",
        );
        let len = signed_length(&doc).unwrap();
        assert!(doc[..len].ends_with("directory-signature "));
        assert!(!doc[..len].ends_with("directory-signature \n"));
        // Everything before the signature block is covered.
        assert!(doc[..len].contains("directory-footer"));
    }

    #[test]
    fn parses_router_entries() {
        let doc = sample("directory-signature x y\n");
        let routers = parse_routers(&doc).unwrap();
        assert_eq!(routers.len(), 2);
        assert_eq!(routers[0].identity, [0x11u8; 20]);
        assert_eq!(routers[0].microdesc_digest, [0x22u8; 32]);
        assert_eq!(routers[0].ipv4, [1, 2, 3, 4]);
        assert_eq!(routers[0].or_port, 9001);
        assert_eq!(routers[0].bandwidth, 4500);
        assert!(routers[0].has(FLAG_GUARD | FLAG_RUNNING | FLAG_STABLE | FLAG_VALID));
        assert!(!routers[0].has(FLAG_EXIT));
        assert!(routers[1].has(FLAG_EXIT));
        assert_eq!(routers[1].or_port, 443);
        assert_eq!(routers[1].subnet16(), [5, 6]);
    }

    /// The ns flavour carries an extra descriptor-digest field; both layouts
    /// must land on the same address and port.
    #[test]
    fn accepts_both_r_line_layouts() {
        let id = base64_encode_unpadded(&[9u8; 20]);
        let micro = parse_r_line(&format!("Nick {id} 2026-09-02 09:00:00 1.2.3.4 9001 0")).unwrap();
        let ns = parse_r_line(&format!(
            "Nick {id} AAAAAAAAAAAAAAAAAAAAAAAAAAA 2026-09-02 09:00:00 1.2.3.4 9001 0"
        ))
        .unwrap();
        assert_eq!(micro.ipv4, ns.ipv4);
        assert_eq!(micro.or_port, ns.or_port);
        assert_eq!(micro.identity, ns.identity);
        assert!(parse_r_line("too few").is_none());
    }

    #[test]
    fn rejects_documents_that_are_not_a_microdesc_consensus() {
        let now = parse_datetime("2026-09-02", "10:30:00").unwrap();
        assert!(parse_and_verify("network-status-version 3\n", &[], now).is_err());
        assert!(parse_and_verify("", &[], now).is_err());
        assert!(parse_and_verify("network-status-version 3 ns\n", &[], now).is_err());
    }

    /// With no key certificates nothing can be verified, so the signature
    /// count must fall short and the consensus must be refused.
    #[test]
    fn refuses_a_consensus_without_enough_signatures() {
        let doc = sample(
            "directory-signature sha256 AABB CCDD\n-----BEGIN SIGNATURE-----\naGk=\n-----END SIGNATURE-----\n",
        );
        let now = parse_datetime("2026-09-02", "10:30:00").unwrap();
        let err = match parse_and_verify(&doc, &[], now) {
            Err(e) => e,
            Ok(_) => panic!("an unsigned consensus must not be accepted"),
        };
        assert!(err.to_string().contains("signatures"), "{err}");
    }

    #[test]
    fn collects_every_signature_block() {
        let id_a = "AABBCCDDEEFF00112233445566778899AABBCCDD";
        let key_a = "1122334455667788990011223344556677889900";
        let id_b = "EEFF00112233445566778899AABBCCDDEEFF0011";
        let key_b = "9988776655443322110099887766554433221100";
        let doc = sample(&format!(
            "directory-signature sha256 {id_a} {key_a}\n-----BEGIN SIGNATURE-----\naGk=\n-----END SIGNATURE-----\n\
             directory-signature {id_b} {key_b}\n-----BEGIN SIGNATURE-----\naGk=\n-----END SIGNATURE-----\n"
        ));
        let len = signed_length(&doc).unwrap();
        let found = signatures(&doc[len..]);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].algorithm, "sha256");
        assert_eq!(found[0].identity[..2], [0xaa, 0xbb]);
        assert_eq!(found[0].signing_key_digest[..2], [0x11, 0x22]);
        assert_eq!(found[0].value, b"hi");
        // No algorithm named means sha1.
        assert_eq!(found[1].algorithm, "sha1");
        assert_eq!(found[1].identity[..2], [0xee, 0xff]);
    }
}
