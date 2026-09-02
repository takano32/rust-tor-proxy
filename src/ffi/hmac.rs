//! HMAC-SHA256 (one-shot), the only MAC the ntor handshake needs.

use std::ffi::{c_int, c_uint, c_void};

use super::*;

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut out_len: c_uint = 0;
    // HMAC() rejects a null key pointer even with key_len 0, so point at self.
    let key_ptr = if key.is_empty() {
        out.as_ptr() as *const c_void
    } else {
        key.as_ptr() as *const c_void
    };
    let rc = unsafe {
        HMAC(
            EVP_sha256(),
            key_ptr,
            key.len() as c_int,
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
            &mut out_len,
        )
    };
    assert!(!rc.is_null(), "HMAC failed: {}", openssl_errors());
    assert_eq!(out_len, 32);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_decode;

    /// RFC 4231 test cases 1 and 2.
    #[test]
    fn rfc4231_vectors() {
        assert_eq!(
            hmac_sha256(&[0x0b; 20], b"Hi There").to_vec(),
            hex_decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7").unwrap()
        );
        assert_eq!(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?").to_vec(),
            hex_decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843").unwrap()
        );
    }
}
