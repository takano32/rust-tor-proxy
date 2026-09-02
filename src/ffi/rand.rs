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

/// Fisher-Yates, for putting a small list in a random order: which
/// introduction point to try first, which directory node to ask.
pub fn shuffle<T>(items: &mut [T]) -> io::Result<()> {
    for i in (1..items.len()).rev() {
        items.swap(i, below(i as u64 + 1)? as usize);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shuffle_keeps_every_element() {
        let mut items: Vec<u8> = (0..32).collect();
        shuffle(&mut items).unwrap();
        let mut sorted = items.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..32).collect::<Vec<u8>>());
        // Short lists must not panic.
        shuffle(&mut Vec::<u8>::new()).unwrap();
        shuffle(&mut [7u8]).unwrap();
    }

    /// Every position has to be reachable, or the "random order" would only
    /// ever try the same node first.
    #[test]
    fn shuffle_moves_things_around() {
        let mut seen_elsewhere = false;
        for _ in 0..50 {
            let mut items: Vec<u8> = (0..6).collect();
            shuffle(&mut items).unwrap();
            if items[0] != 0 {
                seen_elsewhere = true;
                break;
            }
        }
        assert!(seen_elsewhere, "shuffle never moved the first element");
    }
}
