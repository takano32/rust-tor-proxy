//! SHA-1, SHA-256 and SHA3-256, one-shot and incremental, plus SHAKE-256.

use std::ffi::{c_uint, c_void};

use super::*;

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut out = [0u8; 20];
    digest_into(unsafe { EVP_sha1() }, data, &mut out);
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    digest_into(unsafe { EVP_sha256() }, data, &mut out);
    out
}

/// SHA3-256, which is `H()` throughout the onion service protocol.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    digest_into(unsafe { EVP_sha3_256() }, data, &mut out);
    out
}

fn digest_into(md: *const c_void, data: &[u8], out: &mut [u8]) {
    let mut len: c_uint = 0;
    let rc = unsafe {
        EVP_Digest(
            data.as_ptr() as *const c_void,
            data.len(),
            out.as_mut_ptr(),
            &mut len,
            md,
            std::ptr::null_mut(),
        )
    };
    // EVP_Digest with a built-in MD only fails on allocation failure.
    assert_eq!(rc, 1, "EVP_Digest failed: {}", openssl_errors());
    assert_eq!(len as usize, out.len());
}

/// SHAKE-256 as an extendable output function: `KDF(x, n)` in rend-spec.
///
/// `EVP_DigestFinalXOF` may be called only once per context, so the whole
/// output is taken in a single call and the length has to be known up front.
pub fn shake256(data: &[u8], out_len: usize) -> Vec<u8> {
    let ctx = unsafe { EVP_MD_CTX_new() };
    assert!(!ctx.is_null(), "EVP_MD_CTX_new failed");
    let mut out = vec![0u8; out_len];
    let rc = unsafe {
        let ok = EVP_DigestInit_ex(ctx, EVP_shake256(), std::ptr::null_mut())
            & EVP_DigestUpdate(ctx, data.as_ptr() as *const c_void, data.len())
            & EVP_DigestFinalXOF(ctx, out.as_mut_ptr(), out_len);
        EVP_MD_CTX_free(ctx);
        ok
    };
    assert_eq!(rc, 1, "SHAKE-256 failed: {}", openssl_errors());
    out
}

/// A running digest whose intermediate value can be read without ending it.
///
/// Tor's relay-cell integrity check needs exactly that: every cell's digest is
/// the running hash of every relay cell sent so far on that hop. `peek_into`
/// finalises a *copy* of the context, so the original keeps accumulating.
///
/// The algorithm is chosen per hop: SHA-1 for ordinary relays, SHA3-256 for
/// the virtual hop of a rendezvous circuit.
pub struct Digest {
    ctx: *mut c_void,
    output_len: usize,
}

// The context is owned exclusively by this value.
unsafe impl Send for Digest {}

impl Digest {
    pub fn sha1() -> Self {
        Self::new(unsafe { EVP_sha1() }, 20)
    }

    pub fn sha3_256() -> Self {
        Self::new(unsafe { EVP_sha3_256() }, 32)
    }

    fn new(md: *const c_void, output_len: usize) -> Self {
        let ctx = unsafe { EVP_MD_CTX_new() };
        assert!(!ctx.is_null(), "EVP_MD_CTX_new failed");
        let rc = unsafe { EVP_DigestInit_ex(ctx, md, std::ptr::null_mut()) };
        assert_eq!(rc, 1, "EVP_DigestInit_ex failed: {}", openssl_errors());
        Self { ctx, output_len }
    }

    pub fn update(&mut self, data: &[u8]) {
        let rc = unsafe { EVP_DigestUpdate(self.ctx, data.as_ptr() as *const c_void, data.len()) };
        assert_eq!(rc, 1, "EVP_DigestUpdate failed: {}", openssl_errors());
    }

    /// Fill `out` with the leading bytes of the digest value as of right now;
    /// the running state is unchanged.
    pub fn peek_into(&self, out: &mut [u8]) {
        assert!(
            out.len() <= self.output_len,
            "asked for {} bytes of a {}-byte digest",
            out.len(),
            self.output_len
        );
        let copy = self.clone();
        let mut full = [0u8; 64];
        let mut len: c_uint = 0;
        let rc = unsafe { EVP_DigestFinal_ex(copy.ctx, full.as_mut_ptr(), &mut len) };
        assert_eq!(rc, 1, "EVP_DigestFinal_ex failed: {}", openssl_errors());
        assert_eq!(len as usize, self.output_len);
        out.copy_from_slice(&full[..out.len()]);
    }

    /// First `N` bytes of the running digest, the form Tor's relay header and
    /// its authenticated SENDMEs want.
    pub fn peek_prefix<const N: usize>(&self) -> [u8; N] {
        let mut out = [0u8; N];
        self.peek_into(&mut out);
        out
    }
}

impl Clone for Digest {
    fn clone(&self) -> Self {
        let ctx = unsafe { EVP_MD_CTX_new() };
        assert!(!ctx.is_null(), "EVP_MD_CTX_new failed");
        let rc = unsafe { EVP_MD_CTX_copy_ex(ctx, self.ctx) };
        assert_eq!(rc, 1, "EVP_MD_CTX_copy_ex failed: {}", openssl_errors());
        Self {
            ctx,
            output_len: self.output_len,
        }
    }
}

impl Drop for Digest {
    fn drop(&mut self) {
        unsafe { EVP_MD_CTX_free(self.ctx) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_decode;

    #[test]
    fn known_digests() {
        assert_eq!(
            sha256(b"abc").to_vec(),
            hex_decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap()
        );
        assert_eq!(
            sha1(b"abc").to_vec(),
            hex_decode("a9993e364706816aba3e25717850c26c9cd0d89d").unwrap()
        );
        assert_eq!(
            sha256(b"").to_vec(),
            hex_decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap()
        );
    }

    /// SHA3-256, not Keccak-256: the two differ only in the padding byte, so a
    /// known vector is the only thing that tells them apart.
    #[test]
    fn known_sha3_digests() {
        assert_eq!(
            sha3_256(b"abc").to_vec(),
            hex_decode("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532").unwrap()
        );
        assert_eq!(
            sha3_256(b"").to_vec(),
            hex_decode("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a").unwrap()
        );
    }

    #[test]
    fn known_shake256_output() {
        assert_eq!(
            shake256(b"abc", 32),
            hex_decode("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739").unwrap()
        );
        // A longer request must extend the same stream, not restart it.
        let long = shake256(b"abc", 64);
        assert_eq!(&long[..32], &shake256(b"abc", 32)[..]);
        assert_eq!(shake256(b"", 0), Vec::<u8>::new());
    }

    /// `peek_into` must not disturb the running state, and a clone must be
    /// able to diverge from it: both are what the relay-cell digest check
    /// relies on.
    #[test]
    fn running_digest_peek_and_clone() {
        let mut d = Digest::sha1();
        d.update(b"a");
        d.update(b"b");
        assert_eq!(d.peek_prefix::<20>(), sha1(b"ab"));

        let mut branch = d.clone();
        branch.update(b"X");
        d.update(b"c");
        assert_eq!(branch.peek_prefix::<20>(), sha1(b"abX"));
        assert_eq!(d.peek_prefix::<20>(), sha1(b"abc"));
        assert_eq!(d.peek_prefix::<4>(), sha1(b"abc")[..4]);
    }

    /// The same machinery has to work for the SHA3-256 hop of a rendezvous
    /// circuit, where 20 bytes is a prefix of a 32-byte digest.
    #[test]
    fn running_sha3_digest() {
        let mut d = Digest::sha3_256();
        d.update(b"ab");
        assert_eq!(d.peek_prefix::<32>(), sha3_256(b"ab"));
        assert_eq!(d.peek_prefix::<20>(), sha3_256(b"ab")[..20]);
        let mut branch = d.clone();
        branch.update(b"c");
        assert_eq!(branch.peek_prefix::<32>(), sha3_256(b"abc"));
        assert_eq!(d.peek_prefix::<32>(), sha3_256(b"ab"));
    }

    #[test]
    #[should_panic(expected = "asked for 32 bytes of a 20-byte digest")]
    fn peeking_past_the_end_of_a_sha1_digest_is_a_bug() {
        Digest::sha1().peek_prefix::<32>();
    }
}
