//! Onion service descriptors: parsing, signature checking and the two layers
//! of decryption (rend-spec/hsdesc-outer.md, rend-spec/hsdesc-encrypt.md).
//!
//! The document a directory node serves is signed by a per-period key that the
//! blinded key certifies, and its body is encrypted twice. Both layers use the
//! same scheme with different inputs: the outer one keeps the directory node
//! from reading it, the inner one is where restricted discovery would live.
//! This client has no client authorisation, so it supplies no descriptor
//! cookie and the inner layer adds nothing -- but it is still there, and still
//! has to be peeled.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};

use super::int8;
use crate::ffi::aes::Aes256Ctr;
use crate::ffi::constant_time_eq;
use crate::ffi::hash::{sha3_256, shake256};
use crate::tor::certs::{
    Ed25519Cert, CERT_TYPE_HS_DESC_SIGN, CERT_TYPE_HS_INTRO_AUTH, CERT_TYPE_HS_INTRO_ENC,
};
use crate::tor::dir::netdoc;
use crate::tor::RelayInfo;
use crate::util::invalid_data;

/// What the outer signature covers, before the document itself.
const SIGNATURE_PREFIX: &[u8] = b"Tor onion service descriptor sig v3";

const SALT_LEN: usize = 16;
const MAC_LEN: usize = 32;
const SECRET_KEY_LEN: usize = 32;
const SECRET_IV_LEN: usize = 16;
const MAC_KEY_LEN: usize = 32;

/// rend-spec [NUM_INTRO_POINT]: a service may publish at most twenty.
const MAX_INTRO_POINTS: usize = 20;

/// HSDirs accept descriptors up to 50k; anything larger is not one.
pub const MAX_DESCRIPTOR_BYTES: usize = 50 * 1024;

/// One introduction point, with everything needed to reach it and to build an
/// INTRODUCE1 cell for it.
#[derive(Clone)]
pub struct IntroPoint {
    pub relay: RelayInfo,
    /// `KP_hs_ipt_sid`: names this introduction point to the service.
    pub auth_key: [u8; 32],
    /// `KP_hss_ntor`: the service's key for the hs-ntor handshake.
    pub enc_key: [u8; 32],
}

pub struct Descriptor {
    /// How long the service means this descriptor to be served, in minutes.
    pub lifetime_minutes: u64,
    pub revision_counter: u64,
    pub intro_points: Vec<IntroPoint>,
    /// What the inner layer's `flow-control` line said, when it had one.
    pub flow_control: Option<FlowControl>,
}

/// The service's `flow-control version-range sendme-inc` line (proposal 324
/// §9.1). A service only publishes it when it has congestion control enabled,
/// so its absence means the window scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowControl {
    /// The highest protocol version the service offers. 2 is the one that
    /// means proposal 324.
    pub max_version: u8,
    /// The service's view of the consensus `cc_sendme_inc`.
    pub sendme_inc: u8,
}

impl FlowControl {
    /// `"flow-control" SP version-range SP sendme-inc`, where the range is a
    /// dash-separated pair such as `1-2`.
    ///
    /// Unknown versions are ignored rather than refused, and so is anything
    /// further along the line, as the spec requires.
    fn parse(args: &str) -> Option<Self> {
        let mut fields = args.split_whitespace();
        let range = fields.next()?;
        let sendme_inc: u8 = fields.next()?.parse().ok()?;
        let max_version = range
            .split('-')
            .filter_map(|v| v.parse::<u8>().ok())
            .max()?;
        Some(Self {
            max_version,
            sendme_inc,
        })
    }
}

impl Descriptor {
    /// Verify and decrypt a descriptor fetched under `blinded_key`.
    ///
    /// `now` is used only for certificate expiry, which is the one thing here
    /// the consensus cannot date for us.
    pub fn parse(
        text: &str,
        blinded_key: &[u8; 32],
        subcredential: &[u8; 32],
        now: u64,
    ) -> io::Result<Self> {
        let version = netdoc::item(text, "hs-descriptor")
            .ok_or_else(|| invalid_data("not an onion service descriptor"))?;
        if version.trim() != "3" {
            return Err(invalid_data(format!(
                "unsupported descriptor version {version:?}"
            )));
        }
        let lifetime_minutes: u64 = netdoc::item(text, "descriptor-lifetime")
            .and_then(|v| v.trim().parse().ok())
            .ok_or_else(|| invalid_data("descriptor has no usable descriptor-lifetime"))?;
        let revision_counter: u64 = netdoc::item(text, "revision-counter")
            .and_then(|v| v.trim().parse().ok())
            .ok_or_else(|| invalid_data("descriptor has no usable revision-counter"))?;

        // The signing key is certified by the blinded key, which is the only
        // thing we knew about the service before asking for this document.
        let cert = Ed25519Cert::parse(&netdoc::item_object(
            text,
            "descriptor-signing-key-cert",
            "ED25519 CERT",
        )?)?;
        let signing_key = certified_key(&cert, CERT_TYPE_HS_DESC_SIGN, blinded_key, now)
            .map_err(|e| invalid_data(format!("descriptor-signing-key-cert: {e}")))?;

        check_signature(text, &signing_key)?;

        let superencrypted = netdoc::item_object(text, "superencrypted", "MESSAGE")?;
        let middle = decrypt_layer(
            &superencrypted,
            blinded_key,
            subcredential,
            revision_counter,
            b"hsdir-superencrypted-data",
        )?;

        // The middle layer only carries restricted-discovery material, which
        // is dummy data for a service that has none. The inner ciphertext is
        // all we want from it.
        let encrypted = netdoc::item_object(&middle, "encrypted", "MESSAGE")?;
        let inner = decrypt_layer(
            &encrypted,
            blinded_key,
            subcredential,
            revision_counter,
            b"hsdir-encrypted-data",
        )?;

        let intro_points = parse_inner(&inner, &signing_key, now)?;
        let flow_control = netdoc::item(&inner, "flow-control").and_then(FlowControl::parse);
        Ok(Self {
            lifetime_minutes,
            revision_counter,
            intro_points,
            flow_control,
        })
    }
}

/// Check one of rend-spec's certificates and return the key it certifies:
/// right type, signed by `expected_signer`, still valid.
fn certified_key(
    cert: &Ed25519Cert,
    cert_type: u8,
    expected_signer: &[u8; 32],
    now: u64,
) -> io::Result<[u8; 32]> {
    if cert.cert_type != cert_type {
        return Err(invalid_data(format!(
            "expected certificate type {cert_type:#04x}, found {:#04x}",
            cert.cert_type
        )));
    }
    // The signing key must be carried in the certificate *and* be the one we
    // expect: without the first check there is nothing to verify against, and
    // without the second any self-consistent certificate would pass.
    let signer = cert
        .signing_key
        .ok_or_else(|| invalid_data("certificate has no signed-with-ed25519-key extension"))?;
    if &signer != expected_signer {
        return Err(invalid_data("certificate is signed by an unexpected key"));
    }
    if !cert.check_signature(&signer) {
        return Err(invalid_data("certificate signature does not verify"));
    }
    if cert.is_expired(now) {
        return Err(invalid_data(format!(
            "certificate expired at unix time {}, local clock says {now}",
            cert.expires_at_unix()
        )));
    }
    Ok(cert.certified_key)
}

/// The outer signature covers the prefix string followed by the document up to
/// and including the newline before the `signature` line.
fn check_signature(text: &str, signing_key: &[u8; 32]) -> io::Result<()> {
    let signed_len = netdoc::line_start_of(text, "signature ")
        .ok_or_else(|| invalid_data("descriptor has no signature line"))?;
    let args = netdoc::item(text, "signature")
        .ok_or_else(|| invalid_data("descriptor has no signature line"))?;
    let signature = crate::util::base64_decode(args.trim())?;

    let mut message = Vec::with_capacity(SIGNATURE_PREFIX.len() + signed_len);
    message.extend_from_slice(SIGNATURE_PREFIX);
    message.extend_from_slice(&text.as_bytes()[..signed_len]);
    if !crate::ffi::ed25519::verify(signing_key, &message, &signature) {
        return Err(invalid_data("descriptor signature does not verify"));
    }
    Ok(())
}

/// Undo one encryption layer: `SALT(16) | ENCRYPTED | MAC(32)`.
fn decrypt_layer(
    blob: &[u8],
    secret_data: &[u8],
    subcredential: &[u8; 32],
    revision_counter: u64,
    string_constant: &[u8],
) -> io::Result<String> {
    if blob.len() <= SALT_LEN + MAC_LEN {
        return Err(invalid_data("encrypted descriptor layer is too short"));
    }
    let salt = &blob[..SALT_LEN];
    let ciphertext = &blob[SALT_LEN..blob.len() - MAC_LEN];
    let mac = &blob[blob.len() - MAC_LEN..];

    let mut secret_input = Vec::with_capacity(secret_data.len() + 32 + 8);
    secret_input.extend_from_slice(secret_data);
    secret_input.extend_from_slice(subcredential);
    secret_input.extend_from_slice(&int8(revision_counter));

    let mut kdf_input = secret_input;
    kdf_input.extend_from_slice(salt);
    kdf_input.extend_from_slice(string_constant);
    let keys = shake256(&kdf_input, SECRET_KEY_LEN + SECRET_IV_LEN + MAC_KEY_LEN);
    let secret_key: [u8; SECRET_KEY_LEN] = keys[..SECRET_KEY_LEN].try_into().unwrap();
    let secret_iv: [u8; SECRET_IV_LEN] = keys[SECRET_KEY_LEN..SECRET_KEY_LEN + SECRET_IV_LEN]
        .try_into()
        .unwrap();
    let mac_key = &keys[SECRET_KEY_LEN + SECRET_IV_LEN..];

    // D_MAC = H(INT_8(len(MAC_KEY)) | MAC_KEY | INT_8(len(SALT)) | SALT | ENCRYPTED)
    let mut mac_input = Vec::with_capacity(16 + mac_key.len() + salt.len() + ciphertext.len());
    mac_input.extend_from_slice(&int8(mac_key.len() as u64));
    mac_input.extend_from_slice(mac_key);
    mac_input.extend_from_slice(&int8(salt.len() as u64));
    mac_input.extend_from_slice(salt);
    mac_input.extend_from_slice(ciphertext);
    if !constant_time_eq(&sha3_256(&mac_input), mac) {
        return Err(invalid_data(
            "descriptor layer MAC does not match: wrong key or a tampered document",
        ));
    }

    let mut plaintext = ciphertext.to_vec();
    Aes256Ctr::with_counter(&secret_key, &secret_iv).apply(&mut plaintext);
    // The plaintext was padded with NULs to a multiple of 10k before
    // encryption; the document itself contains none.
    while plaintext.last() == Some(&0) {
        plaintext.pop();
    }
    String::from_utf8(plaintext).map_err(|_| invalid_data("decrypted descriptor is not UTF-8"))
}

/// Parse the innermost plaintext: the service's own settings and its list of
/// introduction points.
fn parse_inner(text: &str, signing_key: &[u8; 32], now: u64) -> io::Result<Vec<IntroPoint>> {
    let formats = netdoc::item(text, "create2-formats")
        .ok_or_else(|| invalid_data("descriptor has no create2-formats"))?;
    if !formats.split_whitespace().any(|f| f == "2") {
        return Err(invalid_data(
            "service does not offer the ntor handshake (create2-formats has no 2)",
        ));
    }
    if let Some(types) = netdoc::item(text, "intro-auth-required") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("service requires client authorization ({types}), which is not supported"),
        ));
    }

    let mut intro_points = Vec::new();
    for block in split_intro_points(text) {
        match parse_intro_point(block, signing_key, now) {
            Ok(point) => intro_points.push(point),
            // One unusable introduction point should not cost us the others.
            Err(e) => crate::debug!("skipping an introduction point: {e}"),
        }
        if intro_points.len() == MAX_INTRO_POINTS {
            break;
        }
    }
    if intro_points.is_empty() {
        return Err(invalid_data(
            "descriptor lists no usable introduction points",
        ));
    }
    Ok(intro_points)
}

/// Cut the inner document at each `introduction-point` line.
fn split_intro_points(text: &str) -> Vec<&str> {
    let mut starts = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = netdoc::line_start_of(&text[offset..], "introduction-point ") {
        let absolute = offset + relative;
        starts.push(absolute);
        match text[absolute..].find('\n') {
            Some(newline) => offset = absolute + newline + 1,
            None => break,
        }
        if offset >= text.len() {
            break;
        }
    }
    starts
        .iter()
        .enumerate()
        .map(|(index, start)| &text[*start..starts.get(index + 1).copied().unwrap_or(text.len())])
        .collect()
}

fn parse_intro_point(block: &str, signing_key: &[u8; 32], now: u64) -> io::Result<IntroPoint> {
    let specs = netdoc::item(block, "introduction-point")
        .ok_or_else(|| invalid_data("introduction point has no link specifiers"))?;
    let relay_addr = parse_link_specifiers(&crate::util::base64_decode(specs.trim())?)?;

    let ntor_onion_key = keyed_value(block, "onion-key", "ntor")
        .ok_or_else(|| invalid_data("introduction point has no ntor onion-key"))?;

    let auth_cert = Ed25519Cert::parse(&netdoc::item_object(block, "auth-key", "ED25519 CERT")?)?;
    let auth_key = certified_key(&auth_cert, CERT_TYPE_HS_INTRO_AUTH, signing_key, now)
        .map_err(|e| invalid_data(format!("auth-key: {e}")))?;

    let enc_key = keyed_value(block, "enc-key", "ntor")
        .ok_or_else(|| invalid_data("introduction point has no ntor enc-key"))?;

    // The cross-certificate proves nothing the descriptor's own signature has
    // not already proved, but a malformed one means a malformed descriptor.
    // TODO: check that its subject really is enc_key converted to Ed25519
    // (proposal 228 appendix A); C Tor does not, and the sign bit it zeroes
    // makes the subject unusable for verification anyway.
    let enc_cert =
        Ed25519Cert::parse(&netdoc::item_object(block, "enc-key-cert", "ED25519 CERT")?)?;
    certified_key(&enc_cert, CERT_TYPE_HS_INTRO_ENC, signing_key, now)
        .map_err(|e| invalid_data(format!("enc-key-cert: {e}")))?;

    let (addr, rsa_identity, ed_identity) = relay_addr;
    Ok(IntroPoint {
        relay: RelayInfo {
            addr: addr.ok_or_else(|| invalid_data("introduction point has no IPv4 address"))?,
            rsa_identity: rsa_identity
                .ok_or_else(|| invalid_data("introduction point has no legacy identity"))?,
            ed_identity,
            ntor_onion_key,
        },
        auth_key,
        enc_key,
    })
}

/// `keyword <kind> <base64>`, for `onion-key ntor ...` and `enc-key ntor ...`.
/// Lines naming a different kind are ignored, as the spec requires.
fn keyed_value(block: &str, keyword: &str, kind: &str) -> Option<[u8; 32]> {
    block.lines().find_map(|line| {
        let args = netdoc::item_args(line, keyword)?;
        let (found, value) = args.split_once(' ')?;
        if found != kind {
            return None;
        }
        netdoc::base64_fixed::<32>(value.trim()).ok()
    })
}

/// A link specifier list, as in EXTEND2: `NSPEC | {LSTYPE LSLEN LSPEC}*`.
///
/// IPv6 specifiers are skipped: this client has no IPv6 path to a relay, and
/// an unknown type must be ignored rather than rejected.
#[allow(clippy::type_complexity)]
fn parse_link_specifiers(
    data: &[u8],
) -> io::Result<(Option<SocketAddrV4>, Option<[u8; 20]>, Option<[u8; 32]>)> {
    let count = *data
        .first()
        .ok_or_else(|| invalid_data("empty link specifier list"))? as usize;
    let mut pos = 1usize;
    let (mut addr, mut rsa_identity, mut ed_identity) = (None, None, None);
    for _ in 0..count {
        if pos + 2 > data.len() {
            return Err(invalid_data("truncated link specifier header"));
        }
        let kind = data[pos];
        let len = data[pos + 1] as usize;
        let start = pos + 2;
        let end = start + len;
        if end > data.len() {
            return Err(invalid_data("link specifier runs past the end"));
        }
        let body = &data[start..end];
        match (kind, len) {
            (0x00, 6) => {
                addr = Some(SocketAddrV4::new(
                    Ipv4Addr::new(body[0], body[1], body[2], body[3]),
                    u16::from_be_bytes([body[4], body[5]]),
                ));
            }
            (0x02, 20) => rsa_identity = Some(body.try_into().unwrap()),
            (0x03, 32) => ed_identity = Some(body.try_into().unwrap()),
            _ => {}
        }
        pos = end;
    }
    Ok((addr, rsa_identity, ed_identity))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The service's flow-control line: the highest version it offers, and
    /// its view of the consensus SENDME increment.
    #[test]
    fn flow_control_line() {
        let parsed = FlowControl::parse("1-2 31").unwrap();
        assert_eq!(parsed.max_version, 2);
        assert_eq!(parsed.sendme_inc, 31);
        // Unknown versions are ignored rather than refused, and so is
        // anything further along the line.
        assert_eq!(FlowControl::parse("2-5 50 extra").unwrap().max_version, 5);
        assert_eq!(FlowControl::parse("1 100").unwrap().max_version, 1);
        // A malformed line is simply absent, not fatal.
        assert!(FlowControl::parse("").is_none());
        assert!(FlowControl::parse("1-2").is_none());
        assert!(FlowControl::parse("1-2 not-a-number").is_none());
        assert!(FlowControl::parse("x-y 31").is_none());
    }
    use crate::util::{base64_encode_unpadded, hex_decode};

    /// `unwrap_err` needs `Debug` on the success type, and neither a
    /// descriptor nor an introduction point should grow one: they hold keys.
    fn expect_err<T>(result: io::Result<T>) -> io::Error {
        match result {
            Err(e) => e,
            Ok(_) => panic!("expected this to be refused"),
        }
    }

    /// Encrypt a layer the way a service would, so the decryption path can be
    /// exercised without a live descriptor.
    fn encrypt_layer(
        plaintext: &[u8],
        secret_data: &[u8],
        subcredential: &[u8; 32],
        revision_counter: u64,
        string_constant: &[u8],
        salt: [u8; SALT_LEN],
    ) -> Vec<u8> {
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(secret_data);
        kdf_input.extend_from_slice(subcredential);
        kdf_input.extend_from_slice(&int8(revision_counter));
        kdf_input.extend_from_slice(&salt);
        kdf_input.extend_from_slice(string_constant);
        let keys = shake256(&kdf_input, SECRET_KEY_LEN + SECRET_IV_LEN + MAC_KEY_LEN);
        let key: [u8; 32] = keys[..32].try_into().unwrap();
        let iv: [u8; 16] = keys[32..48].try_into().unwrap();
        let mac_key = &keys[48..];

        let mut ciphertext = plaintext.to_vec();
        Aes256Ctr::with_counter(&key, &iv).apply(&mut ciphertext);

        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&int8(mac_key.len() as u64));
        mac_input.extend_from_slice(mac_key);
        mac_input.extend_from_slice(&int8(salt.len() as u64));
        mac_input.extend_from_slice(&salt);
        mac_input.extend_from_slice(&ciphertext);

        let mut out = salt.to_vec();
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&sha3_256(&mac_input));
        out
    }

    #[test]
    fn layer_round_trips_and_rejects_tampering() {
        let blinded = [0x11u8; 32];
        let subcredential = [0x22u8; 32];
        // Padded to a multiple of 10k, the way a service pads it.
        let mut plaintext = b"create2-formats 2\n".to_vec();
        plaintext.resize(10_240, 0);

        let blob = encrypt_layer(
            &plaintext,
            &blinded,
            &subcredential,
            7,
            b"hsdir-encrypted-data",
            [0x99u8; SALT_LEN],
        );
        let out = decrypt_layer(&blob, &blinded, &subcredential, 7, b"hsdir-encrypted-data")
            .expect("round trip");
        assert_eq!(out, "create2-formats 2\n", "NUL padding must be stripped");

        // Every input to the key derivation must actually be an input.
        assert!(decrypt_layer(
            &blob,
            &[0x12u8; 32],
            &subcredential,
            7,
            b"hsdir-encrypted-data"
        )
        .is_err());
        assert!(decrypt_layer(&blob, &blinded, &[0x23u8; 32], 7, b"hsdir-encrypted-data").is_err());
        assert!(
            decrypt_layer(&blob, &blinded, &subcredential, 8, b"hsdir-encrypted-data").is_err()
        );
        assert!(decrypt_layer(
            &blob,
            &blinded,
            &subcredential,
            7,
            b"hsdir-superencrypted-data"
        )
        .is_err());

        // A flipped ciphertext bit must fail the MAC, not decrypt to garbage.
        let mut tampered = blob.clone();
        tampered[SALT_LEN + 3] ^= 1;
        let err = decrypt_layer(
            &tampered,
            &blinded,
            &subcredential,
            7,
            b"hsdir-encrypted-data",
        )
        .unwrap_err();
        assert!(err.to_string().contains("MAC"), "{err}");
        assert!(decrypt_layer(&blob[..40], &blinded, &subcredential, 7, b"x").is_err());
    }

    #[test]
    fn link_specifiers_pick_out_the_three_we_use() {
        let mut data = vec![4u8];
        data.extend_from_slice(&[0x00, 6, 10, 1, 2, 3, 0x23, 0x29]); // 10.1.2.3:9001
        data.extend_from_slice(&[0x01, 18]); // IPv6, ignored
        data.extend_from_slice(&[0u8; 18]);
        data.push(0x02);
        data.push(20);
        data.extend_from_slice(&[0xaau8; 20]);
        data.push(0x03);
        data.push(32);
        data.extend_from_slice(&[0xbbu8; 32]);

        let (addr, rsa, ed) = parse_link_specifiers(&data).unwrap();
        assert_eq!(addr.unwrap().to_string(), "10.1.2.3:9001");
        assert_eq!(rsa.unwrap(), [0xaau8; 20]);
        assert_eq!(ed.unwrap(), [0xbbu8; 32]);

        assert!(parse_link_specifiers(&[]).is_err());
        assert!(parse_link_specifiers(&[1, 0x00, 6, 1, 2]).is_err());
        // An unknown type is skipped, leaving the rest readable.
        let unknown = [2u8, 0x7f, 1, 0xff, 0x02, 20]
            .into_iter()
            .chain([0xccu8; 20]);
        let (_, rsa, _) = parse_link_specifiers(&unknown.collect::<Vec<u8>>()).unwrap();
        assert_eq!(rsa.unwrap(), [0xccu8; 20]);
    }

    #[test]
    fn keyed_values_ignore_other_key_types() {
        let block = format!(
            "introduction-point AQ\nonion-key legacy AAAA\nonion-key ntor {}\nenc-key ntor {}\n",
            base64_encode_unpadded(&[0x31u8; 32]),
            base64_encode_unpadded(&[0x32u8; 32]),
        );
        assert_eq!(keyed_value(&block, "onion-key", "ntor"), Some([0x31u8; 32]));
        assert_eq!(keyed_value(&block, "enc-key", "ntor"), Some([0x32u8; 32]));
        assert_eq!(keyed_value(&block, "enc-key", "legacy"), None);
        assert_eq!(keyed_value(&block, "missing", "ntor"), None);
    }

    #[test]
    fn splits_the_inner_document_at_each_introduction_point() {
        let text = "create2-formats 2\n\
                    introduction-point AAA\nonion-key ntor x\n\
                    introduction-point BBB\nonion-key ntor y\n";
        let blocks = split_intro_points(text);
        assert_eq!(blocks.len(), 2);
        assert!(blocks[0].starts_with("introduction-point AAA"));
        assert!(blocks[0].ends_with("onion-key ntor x\n"));
        assert!(blocks[1].starts_with("introduction-point BBB"));
        assert!(split_intro_points("create2-formats 2\n").is_empty());
    }

    #[test]
    fn inner_document_requires_ntor_and_refuses_client_auth() {
        let key = [0u8; 32];
        let err = expect_err(parse_inner("create2-formats 1\n", &key, 0));
        assert!(err.to_string().contains("ntor"), "{err}");

        let err = expect_err(parse_inner(
            "create2-formats 2\nintro-auth-required ed25519\n",
            &key,
            0,
        ));
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("client authorization"), "{err}");

        assert!(parse_inner("nothing here\n", &key, 0).is_err());
        // Well-formed but empty: no introduction points to use.
        assert!(parse_inner("create2-formats 2\n", &key, 0).is_err());
    }

    #[test]
    fn certificates_must_be_the_right_type_and_signer() {
        // A certificate with a signature that cannot verify, to check the
        // ordering of the checks: type first, then signer, then signature.
        let mut raw = vec![1u8, CERT_TYPE_HS_DESC_SIGN];
        raw.extend_from_slice(&u32::MAX.to_be_bytes());
        raw.push(1);
        raw.extend_from_slice(&[0x41u8; 32]);
        raw.push(1);
        raw.extend_from_slice(&32u16.to_be_bytes());
        raw.push(4);
        raw.push(0);
        raw.extend_from_slice(&[0x42u8; 32]);
        raw.extend_from_slice(&[0u8; 64]);
        let cert = Ed25519Cert::parse(&raw).unwrap();

        let err = certified_key(&cert, CERT_TYPE_HS_INTRO_AUTH, &[0x42u8; 32], 0).unwrap_err();
        assert!(err.to_string().contains("certificate type"), "{err}");
        let err = certified_key(&cert, CERT_TYPE_HS_DESC_SIGN, &[0x43u8; 32], 0).unwrap_err();
        assert!(err.to_string().contains("unexpected key"), "{err}");
        let err = certified_key(&cert, CERT_TYPE_HS_DESC_SIGN, &[0x42u8; 32], 0).unwrap_err();
        assert!(err.to_string().contains("does not verify"), "{err}");
    }

    /// The signature covers the prefix plus everything up to the newline
    /// before the `signature` line -- not the keyword itself.
    #[test]
    fn signed_region_stops_before_the_signature_keyword() {
        let doc = "hs-descriptor 3\nrevision-counter 1\nsignature aGk\n";
        let signed_len = netdoc::line_start_of(doc, "signature ").unwrap();
        assert_eq!(&doc[..signed_len], "hs-descriptor 3\nrevision-counter 1\n");

        // A document with no signature line at all is refused rather than
        // treated as covering everything.
        let err = check_signature("hs-descriptor 3\n", &[0u8; 32]).unwrap_err();
        assert!(err.to_string().contains("signature"), "{err}");
    }

    #[test]
    fn rejects_documents_that_are_not_descriptors() {
        let subcred = [0u8; 32];
        assert!(Descriptor::parse("", &[0u8; 32], &subcred, 0).is_err());
        assert!(Descriptor::parse("hs-descriptor 2\n", &[0u8; 32], &subcred, 0).is_err());
        let err = expect_err(Descriptor::parse(
            "hs-descriptor 3\n",
            &[0u8; 32],
            &subcred,
            0,
        ));
        assert!(err.to_string().contains("descriptor-lifetime"), "{err}");
    }

    #[test]
    fn mac_input_lengths_are_eight_byte_big_endian() {
        // A regression guard for the easiest mistake here: rend-spec's INT_8
        // is eight bytes, while tor-spec's INT8 is one.
        assert_eq!(int8(32), hex_decode("0000000000000020").unwrap()[..]);
    }
}
