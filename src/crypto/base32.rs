//! RFC 4648 base32, lowercase and unpadded: the encoding of `.onion`
//! addresses.

use std::io;

use crate::util::invalid_data;

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn value(c: u8) -> Option<u8> {
    match c {
        b'a'..=b'z' => Some(c - b'a'),
        b'A'..=b'Z' => Some(c - b'A'),
        b'2'..=b'7' => Some(c - b'2' + 26),
        _ => None,
    }
}

/// Decode base32 without padding. Case is ignored, since a user may well type
/// or paste an address in capitals.
pub fn decode(input: &str) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    let mut acc: u16 = 0;
    let mut bits: u32 = 0;
    for &c in input.as_bytes() {
        if c == b'=' {
            break;
        }
        let v = value(c).ok_or_else(|| invalid_data("invalid base32 character"))?;
        acc = (acc << 5) | v as u16;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // Whatever is left over has to be zero padding, not a partial byte.
    if bits >= 5 || (acc & ((1u16 << bits) - 1)) != 0 {
        return Err(invalid_data("truncated base32 group"));
    }
    Ok(out)
}

pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut acc: u16 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        acc = (acc << 8) | byte as u16;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 section 10, lowercased.
    #[test]
    fn rfc4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "my"),
            ("fo", "mzxq"),
            ("foo", "mzxw6"),
            ("foob", "mzxw6yq"),
            ("fooba", "mzxw6ytb"),
            ("foobar", "mzxw6ytboi"),
        ] {
            assert_eq!(encode(plain.as_bytes()), encoded);
            assert_eq!(decode(encoded).unwrap(), plain.as_bytes());
        }
    }

    /// An onion address is 56 characters for exactly 35 bytes, with no
    /// leftover bits.
    #[test]
    fn onion_address_length() {
        let data: Vec<u8> = (0..35).map(|i| (i * 7 + 1) as u8).collect();
        let encoded = encode(&data);
        assert_eq!(encoded.len(), 56);
        assert_eq!(decode(&encoded).unwrap(), data);
    }

    #[test]
    fn round_trips_every_length() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 13 + 5) as u8).collect();
            assert_eq!(decode(&encode(&data)).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn accepts_uppercase_and_padding() {
        assert_eq!(decode("MZXW6YTBOI").unwrap(), b"foobar");
        assert_eq!(decode("mzxw6yq=").unwrap(), b"foob");
    }

    #[test]
    fn rejects_bad_input() {
        assert!(decode("mzxw6yt1").is_err(), "1 is not in the alphabet");
        assert!(decode("m").is_err(), "a lone character is a partial byte");
        // "mb" would decode to one byte plus two non-zero leftover bits.
        assert!(decode("mb").is_err());
    }
}
