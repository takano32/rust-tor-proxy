//! RSA public keys and Tor's flavour of PKCS#1 v1.5 signature checking.
//!
//! Tor's directory signatures are RSA with PKCS#1 v1.5 padding but *without* a
//! DigestInfo prefix — dir-spec says "the signature does not include the
//! algorithmIdentifier". `EVP_PKEY_verify` therefore always rejects them, so
//! the padded block is recovered with `EVP_PKEY_verify_recover` and compared
//! against a digest we compute ourselves.

use std::ffi::{c_long, c_void};
use std::io;

use super::hash;
use super::x25519::CtxGuard;
use super::*;
use crate::util;

pub struct RsaPublicKey {
    pkey: *mut c_void,
    /// The PKCS#1 DER this key was parsed from; its SHA-1 is Tor's identity
    /// fingerprint for the relay or directory authority that owns it.
    der: Vec<u8>,
}

// The key is owned exclusively by this value.
unsafe impl Send for RsaPublicKey {}
unsafe impl Sync for RsaPublicKey {}

impl RsaPublicKey {
    /// Parse a PKCS#1 `RSAPublicKey` DER blob.
    pub fn from_pkcs1_der(der: &[u8]) -> io::Result<Self> {
        let mut ptr = der.as_ptr();
        let pkey = unsafe {
            d2i_PublicKey(
                EVP_PKEY_RSA,
                std::ptr::null_mut(),
                &mut ptr,
                der.len() as c_long,
            )
        };
        if pkey.is_null() {
            return Err(openssl_err("d2i_PublicKey(RSA)"));
        }
        Ok(Self {
            pkey,
            der: der.to_vec(),
        })
    }

    /// Parse a `-----BEGIN RSA PUBLIC KEY-----` block.
    pub fn from_pem(pem: &str) -> io::Result<Self> {
        let body = util::pem_body(pem, "RSA PUBLIC KEY")?;
        Self::from_pkcs1_der(&util::base64_decode(body)?)
    }

    /// SHA-1 of the DER encoding: the 20-byte Tor identity fingerprint.
    pub fn fingerprint(&self) -> [u8; 20] {
        hash::sha1(&self.der)
    }

    /// Recover the padded payload of a PKCS#1 v1.5 signature.
    pub fn verify_recover(&self, sig: &[u8]) -> io::Result<Vec<u8>> {
        let ctx = unsafe { EVP_PKEY_CTX_new(self.pkey, std::ptr::null_mut()) };
        if ctx.is_null() {
            return Err(openssl_err("EVP_PKEY_CTX_new"));
        }
        let guard = CtxGuard(ctx);
        if unsafe { EVP_PKEY_verify_recover_init(guard.0) } != 1 {
            return Err(openssl_err("EVP_PKEY_verify_recover_init"));
        }
        if unsafe { EVP_PKEY_CTX_set_rsa_padding(guard.0, RSA_PKCS1_PADDING) } != 1 {
            return Err(openssl_err("EVP_PKEY_CTX_set_rsa_padding"));
        }
        let size = unsafe { EVP_PKEY_get_size(self.pkey) };
        if size <= 0 {
            return Err(openssl_err("EVP_PKEY_get_size"));
        }
        let mut out = vec![0u8; size as usize];
        let mut out_len = out.len();
        if unsafe {
            EVP_PKEY_verify_recover(
                guard.0,
                out.as_mut_ptr(),
                &mut out_len,
                sig.as_ptr(),
                sig.len(),
            )
        } != 1
        {
            return Err(openssl_err("EVP_PKEY_verify_recover"));
        }
        out.truncate(out_len);
        Ok(out)
    }

    /// Check a Tor-style signature: recover the block and compare it with the
    /// digest, in constant time.
    pub fn verify_digest(&self, digest: &[u8], sig: &[u8]) -> bool {
        match self.verify_recover(sig) {
            Ok(recovered) => constant_time_eq(&recovered, digest),
            Err(_) => false,
        }
    }
}

impl Drop for RsaPublicKey {
    fn drop(&mut self) {
        unsafe { EVP_PKEY_free(self.pkey) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_decode;

    /// Signature produced with `openssl pkeyutl -sign -pkeyopt
    /// rsa_padding_mode:pkcs1` over a bare SHA-1 digest, i.e. PKCS#1 v1.5
    /// padding with no DigestInfo -- exactly what Tor's directory documents
    /// carry.
    const PUBLIC_KEY_PEM: &str = "\
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBANU7t7T6E0d2DTXGvriY33dzslxeKkVgWUsIMLeLSZVgTk2EimlImBft
oHltVbhZfTwL/JUXV2YL1QF/Pazknmy+aGHYI/Bidt88Vtk+JPbfoTaOD1rsAy18
7bHANgQ4UZhA8l+O1eWxLNleUqJM6MbYipHFwvzk6RimdljqDU73AgMBAAE=
-----END RSA PUBLIC KEY-----";

    const SIGNATURE_HEX: &str = concat!(
        "4a4920e4569d809c1efabae8491394190306f87d13d9ece76eb8293e5d270ee6",
        "e0fbfe831c5b5cb1138b603afdc769a7df4d2d99cd51078bdf70d806ac23e36e",
        "9fa968ef1f2c257f9afddb6c708e2e503d3ec354582bdd9912cdd938ce98ff7a",
        "da65633eba292893e0d57d74e633ea66085dcc9dee5ec46a3ec6e8ce5049b074"
    );

    #[test]
    fn verifies_tor_style_signature() {
        let key = RsaPublicKey::from_pem(PUBLIC_KEY_PEM).unwrap();
        let sig = hex_decode(SIGNATURE_HEX).unwrap();
        let digest = hash::sha1(b"tor directory signature test");

        assert_eq!(key.verify_recover(&sig).unwrap(), digest.to_vec());
        assert!(key.verify_digest(&digest, &sig));
        assert!(!key.verify_digest(&hash::sha1(b"something else"), &sig));

        let mut bad = sig.clone();
        bad[10] ^= 1;
        assert!(!key.verify_digest(&digest, &bad));
    }

    #[test]
    fn fingerprint_is_sha1_of_der() {
        let key = RsaPublicKey::from_pem(PUBLIC_KEY_PEM).unwrap();
        let der = crate::util::base64_decode(
            crate::util::pem_body(PUBLIC_KEY_PEM, "RSA PUBLIC KEY").unwrap(),
        )
        .unwrap();
        assert_eq!(key.fingerprint().to_vec(), hash::sha1(&der).to_vec());
    }
}
