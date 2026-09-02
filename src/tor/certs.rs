//! CERTS cells and Tor's Ed25519 certificate format.
//!
//! Authenticating the responder (tor-spec/negotiating-channels.md) means:
//!
//!   * exactly one CertType 4 `IDENTITY_V_SIGNING` cert, self-signed, carrying
//!     the signing identity in a "signed-with-ed25519-key" extension. That
//!     extension key is `KP_relayid_ed`, the relay's identity; the certified
//!     key is `KP_relaysign_ed`;
//!   * exactly one CertType 5 `SIGNING_V_TLS_CERT` cert, signed by
//!     `KP_relaysign_ed`, whose subject is the SHA-256 of the DER TLS
//!     certificate the relay presented;
//!   * both signatures valid and neither certificate expired.
//!
//! Only then does the TLS connection actually belong to `KP_relayid_ed`.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ffi::{constant_time_eq, ed25519};
use crate::util::invalid_data;

pub const CERT_TYPE_IDENTITY_V_SIGNING: u8 = 4;
pub const CERT_TYPE_SIGNING_V_TLS: u8 = 5;

const EXT_TYPE_SIGNED_WITH_ED25519: u8 = 4;
const EXT_FLAG_AFFECTS_VALIDATION: u8 = 1;

/// A parsed "Tor Ed25519 certificate" (cert-spec.md).
pub struct Ed25519Cert {
    pub cert_type: u8,
    /// Expiry in **hours** since the Unix epoch, as the format specifies.
    pub expiration_hours: u32,
    pub cert_key_type: u8,
    pub certified_key: [u8; 32],
    /// The key from the "signed-with-ed25519-key" extension, if present.
    pub signing_key: Option<[u8; 32]>,
    /// Everything the signature covers: the cert without its 64-byte SIGNATURE.
    signed_portion: Vec<u8>,
    signature: [u8; 64],
}

impl Ed25519Cert {
    pub fn parse(data: &[u8]) -> io::Result<Self> {
        if data.len() < 40 {
            return Err(invalid_data("ed25519 certificate too short"));
        }
        if data[0] != 1 {
            return Err(invalid_data(format!(
                "unsupported certificate version {}",
                data[0]
            )));
        }
        let cert_type = data[1];
        let expiration_hours = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        let cert_key_type = data[6];
        let mut certified_key = [0u8; 32];
        certified_key.copy_from_slice(&data[7..39]);

        let n_extensions = data[39];
        let mut pos = 40usize;
        let mut signing_key = None;
        for _ in 0..n_extensions {
            if pos + 4 > data.len() {
                return Err(invalid_data("truncated certificate extension header"));
            }
            let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            let ext_type = data[pos + 2];
            let ext_flags = data[pos + 3];
            let body_start = pos + 4;
            let body_end = body_start
                .checked_add(ext_len)
                .ok_or_else(|| invalid_data("certificate extension length overflow"))?;
            if body_end > data.len() {
                return Err(invalid_data("certificate extension runs past end"));
            }
            match ext_type {
                EXT_TYPE_SIGNED_WITH_ED25519 => {
                    if ext_len != 32 {
                        return Err(invalid_data("signed-with-ed25519-key must be 32 bytes"));
                    }
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&data[body_start..body_end]);
                    signing_key = Some(key);
                }
                _ if ext_flags & EXT_FLAG_AFFECTS_VALIDATION != 0 => {
                    // The flag says we may not accept what we cannot check.
                    return Err(invalid_data(format!(
                        "unrecognized critical certificate extension {ext_type}"
                    )));
                }
                _ => {}
            }
            pos = body_end;
        }

        if pos + 64 != data.len() {
            return Err(invalid_data("certificate length does not match signature"));
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[pos..]);

        Ok(Self {
            cert_type,
            expiration_hours,
            cert_key_type,
            certified_key,
            signing_key,
            signed_portion: data[..pos].to_vec(),
            signature,
        })
    }

    pub fn check_signature(&self, key: &[u8; 32]) -> bool {
        ed25519::verify(key, &self.signed_portion, &self.signature)
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expiration_hours as u64 * 3600
    }

    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at_unix()
    }
}

/// The certificates carried by one CERTS cell, in order.
pub struct CertsCell {
    entries: Vec<(u8, Vec<u8>)>,
}

impl CertsCell {
    pub fn parse(body: &[u8]) -> io::Result<Self> {
        if body.is_empty() {
            return Err(invalid_data("empty CERTS cell"));
        }
        let count = body[0] as usize;
        let mut pos = 1usize;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            if pos + 3 > body.len() {
                return Err(invalid_data("truncated CERTS entry header"));
            }
            let cert_type = body[pos];
            let len = u16::from_be_bytes([body[pos + 1], body[pos + 2]]) as usize;
            let start = pos + 3;
            let end = start
                .checked_add(len)
                .ok_or_else(|| invalid_data("CERTS length overflow"))?;
            if end > body.len() {
                return Err(invalid_data("CERTS entry runs past end of cell"));
            }
            entries.push((cert_type, body[start..end].to_vec()));
            pos = end;
        }
        Ok(Self { entries })
    }

    /// The single certificate of this type, or an error if there is not
    /// exactly one -- the spec requires uniqueness.
    fn unique(&self, cert_type: u8) -> io::Result<&[u8]> {
        let mut found = None;
        for (t, body) in &self.entries {
            if *t == cert_type {
                if found.is_some() {
                    return Err(invalid_data(format!(
                        "CERTS cell has more than one type {cert_type} certificate"
                    )));
                }
                found = Some(body.as_slice());
            }
        }
        found.ok_or_else(|| invalid_data(format!("CERTS cell has no type {cert_type} certificate")))
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Validate a responder's CERTS cell against the TLS certificate we saw, and
/// return the relay's Ed25519 identity `KP_relayid_ed`.
pub fn validate_responder(
    certs: &CertsCell,
    tls_cert_sha256: &[u8; 32],
    now_unix: u64,
) -> io::Result<[u8; 32]> {
    let id_cert = Ed25519Cert::parse(certs.unique(CERT_TYPE_IDENTITY_V_SIGNING)?)?;
    if id_cert.cert_type != CERT_TYPE_IDENTITY_V_SIGNING {
        return Err(invalid_data("type 4 certificate has the wrong CERT_TYPE"));
    }
    let identity = id_cert
        .signing_key
        .ok_or_else(|| invalid_data("type 4 certificate has no signed-with-ed25519-key"))?;
    if !id_cert.check_signature(&identity) {
        return Err(invalid_data("type 4 certificate is not correctly self-signed"));
    }
    if id_cert.is_expired(now_unix) {
        return Err(expired("type 4 certificate", id_cert.expires_at_unix(), now_unix));
    }
    let signing_key = id_cert.certified_key;

    let tls_cert = Ed25519Cert::parse(certs.unique(CERT_TYPE_SIGNING_V_TLS)?)?;
    if tls_cert.cert_type != CERT_TYPE_SIGNING_V_TLS {
        return Err(invalid_data("type 5 certificate has the wrong CERT_TYPE"));
    }
    if !tls_cert.check_signature(&signing_key) {
        return Err(invalid_data(
            "type 5 certificate is not signed by the relay signing key",
        ));
    }
    if tls_cert.is_expired(now_unix) {
        return Err(expired(
            "type 5 certificate",
            tls_cert.expires_at_unix(),
            now_unix,
        ));
    }
    if !constant_time_eq(&tls_cert.certified_key, tls_cert_sha256) {
        return Err(invalid_data(
            "type 5 certificate does not certify the TLS certificate we saw",
        ));
    }

    Ok(identity)
}

fn expired(what: &str, expires_at: u64, now: u64) -> io::Error {
    // Clock skew is a common cause, so say what the two times were.
    invalid_data(format!(
        "{what} expired at unix time {expires_at}, local clock says {now}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a certificate of the shape cert-spec describes. `sign` decides
    /// whether the signature is genuine.
    fn make_cert(
        cert_type: u8,
        expiration_hours: u32,
        certified_key: &[u8; 32],
        signing_key_ext: Option<&[u8; 32]>,
        signature: &[u8; 64],
    ) -> Vec<u8> {
        let mut out = vec![1u8, cert_type];
        out.extend_from_slice(&expiration_hours.to_be_bytes());
        out.push(1); // CERT_KEY_TYPE: ed25519 key
        out.extend_from_slice(certified_key);
        match signing_key_ext {
            Some(key) => {
                out.push(1);
                out.extend_from_slice(&32u16.to_be_bytes());
                out.push(EXT_TYPE_SIGNED_WITH_ED25519);
                out.push(0);
                out.extend_from_slice(key);
            }
            None => out.push(0),
        }
        out.extend_from_slice(signature);
        out
    }

    #[test]
    fn parses_fields_and_extension() {
        let cert = make_cert(4, 500_000, &[7u8; 32], Some(&[9u8; 32]), &[3u8; 64]);
        let parsed = Ed25519Cert::parse(&cert).unwrap();
        assert_eq!(parsed.cert_type, 4);
        assert_eq!(parsed.expiration_hours, 500_000);
        assert_eq!(parsed.certified_key, [7u8; 32]);
        assert_eq!(parsed.signing_key, Some([9u8; 32]));
        // Expiry is in hours, not seconds.
        assert_eq!(parsed.expires_at_unix(), 500_000 * 3600);
        assert!(parsed.is_expired(500_000 * 3600));
        assert!(!parsed.is_expired(500_000 * 3600 - 1));
    }

    #[test]
    fn rejects_malformed_certificates() {
        assert!(Ed25519Cert::parse(&[1u8; 10]).is_err());
        let mut cert = make_cert(4, 1, &[0u8; 32], None, &[0u8; 64]);
        cert[0] = 2; // wrong version
        assert!(Ed25519Cert::parse(&cert).is_err());

        let mut cert = make_cert(4, 1, &[0u8; 32], Some(&[0u8; 32]), &[0u8; 64]);
        cert.push(0); // trailing byte: signature no longer ends the cert
        assert!(Ed25519Cert::parse(&cert).is_err());
    }

    #[test]
    fn rejects_unknown_critical_extension() {
        let mut cert = vec![1u8, 4];
        cert.extend_from_slice(&1u32.to_be_bytes());
        cert.push(1);
        cert.extend_from_slice(&[0u8; 32]);
        cert.push(1);
        cert.extend_from_slice(&1u16.to_be_bytes());
        cert.push(200); // unknown type
        cert.push(EXT_FLAG_AFFECTS_VALIDATION);
        cert.push(0);
        cert.extend_from_slice(&[0u8; 64]);
        assert!(Ed25519Cert::parse(&cert).is_err());
    }

    #[test]
    fn certs_cell_requires_exactly_one_of_each_type() {
        let one = make_cert(4, 1, &[0u8; 32], None, &[0u8; 64]);
        let mut body = vec![2u8];
        for _ in 0..2 {
            body.push(4);
            body.extend_from_slice(&(one.len() as u16).to_be_bytes());
            body.extend_from_slice(&one);
        }
        let cell = CertsCell::parse(&body).unwrap();
        assert!(cell.unique(4).is_err());
        assert!(cell.unique(5).is_err());
    }

    #[test]
    fn certs_cell_rejects_truncation() {
        assert!(CertsCell::parse(&[]).is_err());
        assert!(CertsCell::parse(&[1, 4, 0, 10, 1, 2]).is_err());
    }
}
