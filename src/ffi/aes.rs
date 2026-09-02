//! AES-128-CTR as a continuous keystream.
//!
//! Tor's relay-cell encryption is a stream cipher whose keystream runs across
//! cells, so one context is kept per direction per hop and fed every cell in
//! order. OpenSSL's EVP layer buffers the partial block between calls, which is
//! exactly the required behaviour. Decryption is the same operation.

use std::ffi::{c_int, c_void};

use super::*;

pub struct Aes128Ctr {
    ctx: *mut c_void,
}

// The context is owned exclusively by this value.
unsafe impl Send for Aes128Ctr {}

impl Aes128Ctr {
    /// Key stream starting at counter zero, which is what Tor's KDF implies.
    pub fn new(key: &[u8; 16]) -> Self {
        Self::with_counter(key, &[0u8; 16])
    }

    pub fn with_counter(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        let ctx = unsafe { EVP_CIPHER_CTX_new() };
        assert!(!ctx.is_null(), "EVP_CIPHER_CTX_new failed");
        let rc = unsafe {
            EVP_EncryptInit_ex(
                ctx,
                EVP_aes_128_ctr(),
                std::ptr::null_mut(),
                key.as_ptr(),
                iv.as_ptr(),
            )
        };
        assert_eq!(rc, 1, "EVP_EncryptInit_ex failed: {}", openssl_errors());
        Self { ctx }
    }

    /// XOR `buf` with the next `buf.len()` bytes of keystream, in place.
    pub fn apply(&mut self, buf: &mut [u8]) {
        if buf.is_empty() {
            return;
        }
        let mut out_len: c_int = 0;
        let ptr = buf.as_mut_ptr();
        let rc = unsafe { EVP_EncryptUpdate(self.ctx, ptr, &mut out_len, ptr, buf.len() as c_int) };
        assert_eq!(rc, 1, "EVP_EncryptUpdate failed: {}", openssl_errors());
        assert_eq!(out_len as usize, buf.len());
    }
}

impl Drop for Aes128Ctr {
    fn drop(&mut self) {
        unsafe { EVP_CIPHER_CTX_free(self.ctx) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_decode;

    /// NIST SP 800-38A F.5.1, CTR-AES128.Encrypt.
    #[test]
    fn nist_sp800_38a_ctr_aes128() {
        let key: [u8; 16] = hex_decode("2b7e151628aed2a6abf7158809cf4f3c")
            .unwrap()
            .try_into()
            .unwrap();
        let iv: [u8; 16] = hex_decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
            .unwrap()
            .try_into()
            .unwrap();
        let plain = hex_decode(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710"
        ))
        .unwrap();
        let expected = hex_decode(concat!(
            "874d6191b620e3261bef6864990db6ce",
            "9806f66b7970fdff8617187bb9fffdff",
            "5ae4df3edbd5d35e5b4f09020db03eab",
            "1e031dda2fbe03d1792170a0f3009cee"
        ))
        .unwrap();

        let mut buf = plain.clone();
        let mut ctr = Aes128Ctr::with_counter(&key, &iv);
        ctr.apply(&mut buf);
        assert_eq!(buf, expected);

        // Decryption is the same operation, and the keystream must continue
        // across calls that do not land on a block boundary.
        let mut ctr = Aes128Ctr::with_counter(&key, &iv);
        let mut buf = expected.clone();
        let (head, tail) = buf.split_at_mut(7);
        ctr.apply(head);
        ctr.apply(tail);
        assert_eq!(buf, plain);
    }
}
