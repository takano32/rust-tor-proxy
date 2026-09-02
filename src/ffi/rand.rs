//! Cryptographically strong random bytes.

use std::ffi::c_int;
use std::io;

use super::*;

pub fn fill(buf: &mut [u8]) -> io::Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    let rc = unsafe { RAND_bytes(buf.as_mut_ptr(), buf.len() as c_int) };
    if rc == 1 {
        Ok(())
    } else {
        Err(openssl_err("RAND_bytes"))
    }
}

pub fn bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

pub fn u32_value() -> io::Result<u32> {
    Ok(u32::from_be_bytes(bytes::<4>()?))
}

/// Uniform value in `0..n` (rejection sampling; `n` must be non-zero).
pub fn below(n: u64) -> io::Result<u64> {
    assert!(n > 0);
    let limit = u64::MAX - (u64::MAX % n);
    loop {
        let v = u64::from_be_bytes(bytes::<8>()?);
        if v < limit {
            return Ok(v % n);
        }
    }
}
