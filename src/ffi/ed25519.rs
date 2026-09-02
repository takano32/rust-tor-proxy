//! Ed25519 signature verification (Tor certificates and consensus documents).

use super::x25519::PkeyGuard;
use super::*;

/// True when `sig` is a valid Ed25519 signature over `msg` by `public_key`.
pub fn verify(public_key: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    if sig.len() != 64 {
        return false;
    }
    let pkey = unsafe {
        EVP_PKEY_new_raw_public_key(
            EVP_PKEY_ED25519,
            std::ptr::null_mut(),
            public_key.as_ptr(),
            public_key.len(),
        )
    };
    if pkey.is_null() {
        // A malformed key is a verification failure, not a crash.
        let _ = openssl_errors();
        return false;
    }
    let key_guard = PkeyGuard(pkey);

    let ctx = unsafe { EVP_MD_CTX_new() };
    if ctx.is_null() {
        return false;
    }
    let result = (|| {
        // Ed25519 is a one-shot algorithm: no digest, and EVP_DigestVerify.
        if unsafe {
            EVP_DigestVerifyInit(
                ctx,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null_mut(),
                key_guard.0,
            )
        } != 1
        {
            return false;
        }
        unsafe { EVP_DigestVerify(ctx, sig.as_ptr(), sig.len(), msg.as_ptr(), msg.len()) == 1 }
    })();
    unsafe { EVP_MD_CTX_free(ctx) };
    if !result {
        let _ = openssl_errors();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_decode;

    /// RFC 8032 section 7.1, TEST 2.
    #[test]
    fn rfc8032_test2() {
        let public: [u8; 32] =
            hex_decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
                .unwrap()
                .try_into()
                .unwrap();
        let sig = hex_decode(concat!(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ))
        .unwrap();
        assert!(verify(&public, &[0x72], &sig));

        // A flipped bit anywhere must fail.
        let mut bad = sig.clone();
        bad[0] ^= 1;
        assert!(!verify(&public, &[0x72], &bad));
        assert!(!verify(&public, &[0x73], &sig));
        assert!(!verify(&[0u8; 32], &[0x72], &sig));
        assert!(!verify(&public, &[0x72], &sig[..63]));
    }
}
