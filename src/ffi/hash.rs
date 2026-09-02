//! SHA-1 and SHA-256, one-shot and incremental.

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

/// Which hash a [`Digest`] computes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Algorithm {
    Sha1,
    Sha256,
}

impl Algorithm {
    pub fn output_len(self) -> usize {
        match self {
            Algorithm::Sha1 => 20,
            Algorithm::Sha256 => 32,
        }
    }

    fn md(self) -> *const c_void {
        unsafe {
            match self {
                Algorithm::Sha1 => EVP_sha1(),
                Algorithm::Sha256 => EVP_sha256(),
            }
        }
    }
}

/// A running digest whose intermediate value can be read without ending it.
///
/// Tor's relay-cell integrity check needs exactly that: every cell's digest is
/// the running hash of every relay cell sent so far on the circuit. `peek`
/// finalises a *copy* of the context, so the original keeps accumulating.
pub struct Digest {
    ctx: *mut c_void,
    alg: Algorithm,
}

// The context is owned exclusively by this value.
unsafe impl Send for Digest {}

impl Digest {
    pub fn new(alg: Algorithm) -> Self {
        let ctx = unsafe { EVP_MD_CTX_new() };
        assert!(!ctx.is_null(), "EVP_MD_CTX_new failed");
        let rc = unsafe { EVP_DigestInit_ex(ctx, alg.md(), std::ptr::null_mut()) };
        assert_eq!(rc, 1, "EVP_DigestInit_ex failed: {}", openssl_errors());
        Self { ctx, alg }
    }

    pub fn sha1() -> Self {
        Self::new(Algorithm::Sha1)
    }

    pub fn update(&mut self, data: &[u8]) {
        let rc =
            unsafe { EVP_DigestUpdate(self.ctx, data.as_ptr() as *const c_void, data.len()) };
        assert_eq!(rc, 1, "EVP_DigestUpdate failed: {}", openssl_errors());
    }

    /// The digest value as of right now; the running state is unchanged.
    pub fn peek(&self) -> Vec<u8> {
        let copy = self.clone();
        let mut out = vec![0u8; self.alg.output_len()];
        let mut len: c_uint = 0;
        let rc = unsafe { EVP_DigestFinal_ex(copy.ctx, out.as_mut_ptr(), &mut len) };
        assert_eq!(rc, 1, "EVP_DigestFinal_ex failed: {}", openssl_errors());
        out.truncate(len as usize);
        out
    }

    /// First `N` bytes of [`Digest::peek`], the form Tor's relay header wants.
    pub fn peek_prefix<const N: usize>(&self) -> [u8; N] {
        let full = self.peek();
        let mut out = [0u8; N];
        out.copy_from_slice(&full[..N]);
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
            alg: self.alg,
        }
    }
}

impl Drop for Digest {
    fn drop(&mut self) {
        unsafe { EVP_MD_CTX_free(self.ctx) };
    }
}

/// SHA-256 over several pieces without concatenating them first.
pub fn sha256_of_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut d = Digest::new(Algorithm::Sha256);
    for p in parts {
        d.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&d.peek());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_decode;

    #[test]
    fn known_digests() {
        assert_eq!(
            sha256(b"abc").to_vec(),
            hex_decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap()
        );
        assert_eq!(
            sha1(b"abc").to_vec(),
            hex_decode("a9993e364706816aba3e25717850c26c9cd0d89d").unwrap()
        );
        assert_eq!(
            sha256(b"").to_vec(),
            hex_decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap()
        );
    }

    /// `peek` must not disturb the running state, and a clone must be able to
    /// diverge from it: both are what the relay-cell digest check relies on.
    #[test]
    fn running_digest_peek_and_clone() {
        let mut d = Digest::sha1();
        d.update(b"a");
        d.update(b"b");
        assert_eq!(d.peek(), sha1(b"ab").to_vec());

        let mut branch = d.clone();
        branch.update(b"X");
        d.update(b"c");
        assert_eq!(branch.peek(), sha1(b"abX").to_vec());
        assert_eq!(d.peek(), sha1(b"abc").to_vec());
        assert_eq!(d.peek_prefix::<4>(), sha1(b"abc")[..4]);
    }
}
