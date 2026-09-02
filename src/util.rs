//! Small encoding helpers. Tor directory documents are full of base64 without
//! padding and of uppercase hex fingerprints.

use std::io;

const B64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode base64, tolerating missing padding and embedded whitespace.
pub fn base64_decode(input: &str) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4 + 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in input.as_bytes() {
        match c {
            b'=' => break,
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => {}
        }
        let v = b64_value(c)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid base64 character"))?;
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // Leftover bits must be zero padding, never a partial byte of data.
    if bits >= 6 || (acc & ((1u32 << bits) - 1)) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated base64 group",
        ));
    }
    Ok(out)
}

/// Encode base64 without padding, the form Tor uses in directory URLs.
pub fn base64_encode_unpadded(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        let chars = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
        let keep = chunk.len() + 1;
        for &c in chars.iter().take(keep) {
            out.push(B64_ALPHABET[c as usize] as char);
        }
    }
    out
}

pub fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(data.len() * 2);
    for &b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn hex_decode(s: &str) -> io::Result<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "odd-length hex string",
        ));
    }
    let nibble = |c: u8| -> io::Result<u8> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid hex character",
            )),
        }
    };
    bytes
        .chunks(2)
        .map(|p| Ok((nibble(p[0])? << 4) | nibble(p[1])?))
        .collect()
}

/// Pull the body out of a PEM block with the given label.
pub fn pem_body<'a>(text: &'a str, label: &str) -> io::Result<&'a str> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text
        .find(&begin)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("missing {begin}")))?
        + begin.len();
    let rest = &text[start..];
    let stop = rest
        .find(&end)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("missing {end}")))?;
    Ok(&rest[..stop])
}

pub fn invalid_data<E: Into<Box<dyn std::error::Error + Send + Sync>>>(msg: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trip() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let encoded = base64_encode_unpadded(&data);
            assert_eq!(base64_decode(&encoded).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn base64_accepts_padding_and_whitespace() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVs\nbG8").unwrap(), b"hello");
        assert_eq!(base64_decode("").unwrap(), b"");
        assert!(base64_decode("a").is_err());
        assert!(base64_decode("****").is_err());
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xa5, 0xff]), "000FA5FF");
        assert_eq!(hex_decode("000fA5ff").unwrap(), vec![0x00, 0x0f, 0xa5, 0xff]);
        assert!(hex_decode("abc").is_err());
        assert!(hex_decode("zz").is_err());
    }
}
