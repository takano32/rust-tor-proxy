//! The directory authorities, transcribed from C Tor's
//! `src/app/config/auth_dirs.inc`.
//!
//! Source: https://gitlab.torproject.org/tpo/core/tor/-/raw/main/src/app/config/auth_dirs.inc
//! Fetched 2026-09-02 at tor.git main commit
//! 42d33936663c207c774868403ce02220762d9e5b.
//!
//! The bridge authority (Serge) is left out: it does not vote on the
//! microdescriptor consensus, so it is not one of the signers we count.

pub struct Authority {
    pub nickname: &'static str,
    /// v3 identity: the SHA-1 fingerprint of the authority identity key that
    /// signs its key certificate.
    pub v3ident: [u8; 20],
    /// The relay RSA identity fingerprint. Kept to match the upstream file;
    /// an authority's identity is proved by its CERTS cell like any relay's.
    #[allow(dead_code)]
    pub rsa_identity: [u8; 20],
    pub ipv4: [u8; 4],
    /// Kept to match the upstream file; directory documents are fetched over
    /// BEGIN_DIR rather than the DirPort.
    #[allow(dead_code)]
    pub dir_port: u16,
    pub or_port: u16,
}

pub const AUTHORITIES: &[Authority] = &[
    Authority {
        nickname: "moria1",
        v3ident: [
            0xf5, 0x33, 0xc8, 0x1c, 0xef, 0x0b, 0xc0, 0x26, 0x78, 0x57, 0xc9, 0x9b, 0x2f, 0x47,
            0x1a, 0xdf, 0x24, 0x9f, 0xa2, 0x32,
        ],
        rsa_identity: [
            0x1a, 0x25, 0xc6, 0x35, 0x8d, 0xb9, 0x13, 0x42, 0xaa, 0x51, 0x72, 0x0a, 0x50, 0x38,
            0xb7, 0x27, 0x42, 0x73, 0x24, 0x98,
        ],
        ipv4: [128, 31, 0, 39],
        dir_port: 9231,
        or_port: 9201,
    },
    Authority {
        nickname: "tor26",
        v3ident: [
            0x2f, 0x3d, 0xf9, 0xca, 0x0e, 0x5d, 0x36, 0xf2, 0x68, 0x5a, 0x2d, 0xa6, 0x71, 0x84,
            0xeb, 0x8d, 0xcb, 0x8c, 0xba, 0x8c,
        ],
        rsa_identity: [
            0xfa, 0xa4, 0xbc, 0xa4, 0xa6, 0xac, 0x0f, 0xb4, 0xca, 0x2f, 0x8a, 0xd5, 0xa1, 0x1d,
            0x9e, 0x12, 0x2b, 0xa8, 0x94, 0xf6,
        ],
        ipv4: [217, 196, 147, 77],
        dir_port: 80,
        or_port: 443,
    },
    Authority {
        nickname: "dizum",
        v3ident: [
            0xe8, 0xa9, 0xc4, 0x5e, 0xde, 0x6d, 0x71, 0x12, 0x94, 0xfa, 0xdf, 0x8e, 0x79, 0x51,
            0xf4, 0xde, 0x6c, 0xa5, 0x6b, 0x58,
        ],
        rsa_identity: [
            0x7e, 0xa6, 0xea, 0xd6, 0xfd, 0x83, 0x08, 0x3c, 0x53, 0x8f, 0x44, 0x03, 0x8b, 0xbf,
            0xa0, 0x77, 0x58, 0x7d, 0xd7, 0x55,
        ],
        ipv4: [45, 66, 35, 11],
        dir_port: 80,
        or_port: 443,
    },
    Authority {
        nickname: "gabelmoo",
        v3ident: [
            0xed, 0x03, 0xbb, 0x61, 0x6e, 0xb2, 0xf6, 0x0b, 0xec, 0x80, 0x15, 0x11, 0x14, 0xbb,
            0x25, 0xce, 0xf5, 0x15, 0xb2, 0x26,
        ],
        rsa_identity: [
            0xf2, 0x04, 0x44, 0x13, 0xda, 0xc2, 0xe0, 0x2e, 0x3d, 0x6b, 0xcf, 0x47, 0x35, 0xa1,
            0x9b, 0xca, 0x1d, 0xe9, 0x72, 0x81,
        ],
        ipv4: [131, 188, 40, 189],
        dir_port: 80,
        or_port: 443,
    },
    Authority {
        nickname: "dannenberg",
        v3ident: [
            0x02, 0x32, 0xaf, 0x90, 0x1c, 0x31, 0xa0, 0x4e, 0xe9, 0x84, 0x85, 0x95, 0xaf, 0x9b,
            0xb7, 0x62, 0x0d, 0x4c, 0x5b, 0x2e,
        ],
        rsa_identity: [
            0x7b, 0xe6, 0x83, 0xe6, 0x5d, 0x48, 0x14, 0x13, 0x21, 0xc5, 0xed, 0x92, 0xf0, 0x75,
            0xc5, 0x53, 0x64, 0xac, 0x71, 0x23,
        ],
        ipv4: [193, 23, 244, 244],
        dir_port: 80,
        or_port: 443,
    },
    Authority {
        nickname: "maatuska",
        v3ident: [
            0x49, 0x01, 0x5f, 0x78, 0x74, 0x33, 0x10, 0x35, 0x80, 0xe3, 0xb6, 0x6a, 0x17, 0x07,
            0xa0, 0x0e, 0x60, 0xf2, 0xd1, 0x5b,
        ],
        rsa_identity: [
            0xbd, 0x6a, 0x82, 0x92, 0x55, 0xcb, 0x08, 0xe6, 0x6f, 0xbe, 0x7d, 0x37, 0x48, 0x36,
            0x35, 0x86, 0xe4, 0x6b, 0x38, 0x10,
        ],
        ipv4: [171, 25, 193, 9],
        dir_port: 443,
        or_port: 80,
    },
    Authority {
        nickname: "longclaw",
        v3ident: [
            0x23, 0xd1, 0x5d, 0x96, 0x5b, 0xc3, 0x51, 0x14, 0x46, 0x73, 0x63, 0xc1, 0x65, 0xc4,
            0xf7, 0x24, 0xb6, 0x4b, 0x4f, 0x66,
        ],
        rsa_identity: [
            0x74, 0xa9, 0x10, 0x64, 0x6b, 0xce, 0xef, 0xbc, 0xd2, 0xe8, 0x74, 0xfc, 0x1d, 0xc9,
            0x97, 0x43, 0x0f, 0x96, 0x81, 0x45,
        ],
        ipv4: [199, 58, 81, 140],
        dir_port: 80,
        or_port: 443,
    },
    Authority {
        nickname: "bastet",
        v3ident: [
            0x27, 0x10, 0x2b, 0xc1, 0x23, 0xe7, 0xaf, 0x1d, 0x47, 0x41, 0xae, 0x04, 0x7e, 0x16,
            0x0c, 0x91, 0xad, 0xc7, 0x6b, 0x21,
        ],
        rsa_identity: [
            0x24, 0xe2, 0xf1, 0x39, 0x12, 0x1d, 0x43, 0x94, 0xc5, 0x4b, 0x5b, 0xcc, 0x36, 0x8b,
            0x3b, 0x41, 0x18, 0x57, 0xc4, 0x13,
        ],
        ipv4: [204, 13, 164, 118],
        dir_port: 80,
        or_port: 443,
    },
    Authority {
        nickname: "faravahar",
        v3ident: [
            0x70, 0x84, 0x9b, 0x86, 0x8d, 0x60, 0x6b, 0xae, 0xcf, 0xb6, 0x12, 0x8c, 0x5e, 0x3d,
            0x78, 0x20, 0x29, 0xaa, 0x39, 0x4f,
        ],
        rsa_identity: [
            0xe3, 0xe4, 0x2d, 0x35, 0xf8, 0x01, 0xc9, 0xd5, 0xab, 0x23, 0x58, 0x4e, 0x00, 0x25,
            0xd5, 0x6f, 0xe2, 0xb3, 0x33, 0x96,
        ],
        ipv4: [216, 218, 219, 41],
        dir_port: 80,
        or_port: 443,
    },
];

/// A consensus is accepted only with signatures from more than half of them.
pub fn required_signatures() -> usize {
    AUTHORITIES.len() / 2 + 1
}

// ---------------------------------------------------------------------------
// Authority key certificates (dir-spec/creating-key-certificates.md)
// ---------------------------------------------------------------------------

use std::io;

use super::netdoc;
use crate::ffi::hash::sha1;
use crate::ffi::rsa::RsaPublicKey;
use crate::util::{hex_decode, invalid_data, parse_datetime};

/// One authority's medium-term signing key, certified by its long-term
/// identity key. Consensus signatures are made with the signing key, so this
/// is the bridge from the identities embedded above to a usable verifier.
pub struct KeyCertificate {
    /// SHA-1 of the DER identity key: matches an `Authority::v3ident`.
    pub v3ident: [u8; 20],
    /// SHA-1 of the DER signing key: matches a `directory-signature` line.
    pub signing_key_digest: [u8; 20],
    pub signing_key: RsaPublicKey,
}

impl KeyCertificate {
    /// Parse and fully verify one certificate.
    fn parse(text: &str, now: u64) -> io::Result<Self> {
        let version = netdoc::item(text, "dir-key-certificate-version")
            .ok_or_else(|| invalid_data("key certificate has no version"))?;
        if version != "3" {
            return Err(invalid_data(format!(
                "unsupported key certificate version {version}"
            )));
        }

        let fingerprint = netdoc::item(text, "fingerprint")
            .ok_or_else(|| invalid_data("key certificate has no fingerprint"))?;
        let v3ident: [u8; 20] = hex_decode(fingerprint)?
            .try_into()
            .map_err(|_| invalid_data("key certificate fingerprint is not 20 bytes"))?;

        let expires_args = netdoc::item(text, "dir-key-expires")
            .ok_or_else(|| invalid_data("key certificate has no dir-key-expires"))?;
        let (date, time) = expires_args
            .split_once(' ')
            .ok_or_else(|| invalid_data("bad dir-key-expires"))?;
        let expires = parse_datetime(date, time.split(' ').next().unwrap_or(time))?;
        if now >= expires {
            return Err(invalid_data(format!(
                "key certificate expired at {} (local clock says {})",
                crate::util::format_datetime(expires),
                crate::util::format_datetime(now)
            )));
        }

        // Both keys appear as RSA PUBLIC KEY objects, identity first.
        let identity_start = netdoc::line_start_of(text, "dir-identity-key")
            .ok_or_else(|| invalid_data("key certificate has no dir-identity-key"))?;
        let identity_key = RsaPublicKey::from_pkcs1_der(&netdoc::object(
            &text[identity_start..],
            "RSA PUBLIC KEY",
        )?)?;
        if identity_key.fingerprint() != v3ident {
            return Err(invalid_data(
                "key certificate fingerprint does not match its identity key",
            ));
        }

        let signing_start = netdoc::line_start_of(text, "dir-signing-key")
            .ok_or_else(|| invalid_data("key certificate has no dir-signing-key"))?;
        let signing_key = RsaPublicKey::from_pkcs1_der(&netdoc::object(
            &text[signing_start..],
            "RSA PUBLIC KEY",
        )?)?;
        let signing_key_digest = signing_key.fingerprint();

        // The signature covers everything through the newline that ends the
        // "dir-key-certification" keyword line (it takes no arguments).
        let signed_end = netdoc::line_end_after(text, "dir-key-certification")
            .ok_or_else(|| invalid_data("key certificate has no dir-key-certification"))?;
        let signature = netdoc::object(&text[signed_end..], "SIGNATURE")?;
        if !identity_key.verify_digest(&sha1(&text.as_bytes()[..signed_end]), &signature) {
            return Err(invalid_data(
                "key certificate is not signed by its own identity key",
            ));
        }

        Ok(Self {
            v3ident,
            signing_key_digest,
            signing_key,
        })
    }
}

/// Parse every certificate in a `/tor/keys/...` response, keeping the ones
/// that verify and that belong to an authority we trust.
pub fn parse_key_certificates(text: &str, now: u64) -> Vec<KeyCertificate> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = netdoc::line_start_of(rest, "dir-key-certificate-version") {
        let body = &rest[start..];
        // A certificate ends after its signature object.
        let end = match body.find("-----END SIGNATURE-----") {
            Some(i) => i + "-----END SIGNATURE-----".len(),
            None => break,
        };
        match KeyCertificate::parse(&body[..end], now) {
            Ok(cert) => {
                if AUTHORITIES.iter().any(|a| a.v3ident == cert.v3ident) {
                    out.push(cert);
                } else {
                    crate::debug!("ignoring key certificate from an unknown authority");
                }
            }
            Err(e) => crate::warn!("skipping key certificate: {e}"),
        }
        rest = &body[end..];
    }
    out
}
