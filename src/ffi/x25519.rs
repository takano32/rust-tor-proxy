//! X25519 key generation and Diffie-Hellman, for the ntor handshake.

use std::ffi::c_void;
use std::io;

use super::*;

/// An X25519 key pair. The private half never leaves OpenSSL.
pub struct EphemeralSecret {
    pkey: *mut c_void,
}

// The key is owned exclusively by this value.
unsafe impl Send for EphemeralSecret {}

impl EphemeralSecret {
    pub fn generate() -> io::Result<Self> {
        let ctx = unsafe { EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, std::ptr::null_mut()) };
        if ctx.is_null() {
            return Err(openssl_err("EVP_PKEY_CTX_new_id(X25519)"));
        }
        let guard = CtxGuard(ctx);
        if unsafe { EVP_PKEY_keygen_init(guard.0) } != 1 {
            return Err(openssl_err("EVP_PKEY_keygen_init"));
        }
        let mut pkey: *mut c_void = std::ptr::null_mut();
        if unsafe { EVP_PKEY_keygen(guard.0, &mut pkey) } != 1 || pkey.is_null() {
            return Err(openssl_err("EVP_PKEY_keygen"));
        }
        Ok(Self { pkey })
    }

    pub fn public_key(&self) -> io::Result<[u8; 32]> {
        let mut out = [0u8; 32];
        let mut len = out.len();
        if unsafe { EVP_PKEY_get_raw_public_key(self.pkey, out.as_mut_ptr(), &mut len) } != 1
            || len != 32
        {
            return Err(openssl_err("EVP_PKEY_get_raw_public_key"));
        }
        Ok(out)
    }

    /// `EXP(peer, self)`. OpenSSL rejects an all-zero result, which is the
    /// low-order-point check Tor's handshake relies on.
    pub fn diffie_hellman(&self, peer: &[u8; 32]) -> io::Result<[u8; 32]> {
        let peer_key = unsafe {
            EVP_PKEY_new_raw_public_key(
                EVP_PKEY_X25519,
                std::ptr::null_mut(),
                peer.as_ptr(),
                peer.len(),
            )
        };
        if peer_key.is_null() {
            return Err(openssl_err("EVP_PKEY_new_raw_public_key(X25519)"));
        }
        let peer_guard = PkeyGuard(peer_key);

        let ctx = unsafe { EVP_PKEY_CTX_new(self.pkey, std::ptr::null_mut()) };
        if ctx.is_null() {
            return Err(openssl_err("EVP_PKEY_CTX_new"));
        }
        let ctx_guard = CtxGuard(ctx);
        if unsafe { EVP_PKEY_derive_init(ctx_guard.0) } != 1 {
            return Err(openssl_err("EVP_PKEY_derive_init"));
        }
        if unsafe { EVP_PKEY_derive_set_peer(ctx_guard.0, peer_guard.0) } != 1 {
            return Err(openssl_err("EVP_PKEY_derive_set_peer"));
        }
        let mut out = [0u8; 32];
        let mut len = out.len();
        if unsafe { EVP_PKEY_derive(ctx_guard.0, out.as_mut_ptr(), &mut len) } != 1 || len != 32 {
            return Err(openssl_err("EVP_PKEY_derive"));
        }
        Ok(out)
    }
}

#[cfg(test)]
impl EphemeralSecret {
    /// Rebuild a key pair from a known private scalar, for test vectors only.
    pub(crate) fn from_raw_private(secret: &[u8; 32]) -> io::Result<Self> {
        let pkey = unsafe {
            EVP_PKEY_new_raw_private_key(
                EVP_PKEY_X25519,
                std::ptr::null_mut(),
                secret.as_ptr(),
                secret.len(),
            )
        };
        if pkey.is_null() {
            return Err(openssl_err("EVP_PKEY_new_raw_private_key(X25519)"));
        }
        Ok(Self { pkey })
    }
}

impl Drop for EphemeralSecret {
    fn drop(&mut self) {
        unsafe { EVP_PKEY_free(self.pkey) };
    }
}

pub(crate) struct CtxGuard(pub *mut c_void);

impl Drop for CtxGuard {
    fn drop(&mut self) {
        unsafe { EVP_PKEY_CTX_free(self.0) };
    }
}

pub(crate) struct PkeyGuard(pub *mut c_void);

impl Drop for PkeyGuard {
    fn drop(&mut self) {
        unsafe { EVP_PKEY_free(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_decode;

    fn key32(hex: &str) -> [u8; 32] {
        hex_decode(hex).unwrap().try_into().unwrap()
    }

    /// RFC 7748 section 6.1.
    #[test]
    fn rfc7748_x25519() {
        let alice = EphemeralSecret::from_raw_private(&key32(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ))
        .unwrap();
        let bob = EphemeralSecret::from_raw_private(&key32(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ))
        .unwrap();

        let alice_pub = key32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_pub = key32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        assert_eq!(alice.public_key().unwrap(), alice_pub);
        assert_eq!(bob.public_key().unwrap(), bob_pub);

        let shared = key32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(alice.diffie_hellman(&bob_pub).unwrap(), shared);
        assert_eq!(bob.diffie_hellman(&alice_pub).unwrap(), shared);
    }

    /// A low-order public key yields an all-zero secret; OpenSSL must refuse it
    /// rather than hand back a shared secret the peer can predict.
    #[test]
    fn rejects_low_order_point() {
        let secret = EphemeralSecret::generate().unwrap();
        assert!(secret.diffie_hellman(&[0u8; 32]).is_err());
    }

    #[test]
    fn generated_keys_agree() {
        let a = EphemeralSecret::generate().unwrap();
        let b = EphemeralSecret::generate().unwrap();
        assert_eq!(
            a.diffie_hellman(&b.public_key().unwrap()).unwrap(),
            b.diffie_hellman(&a.public_key().unwrap()).unwrap()
        );
    }
}
