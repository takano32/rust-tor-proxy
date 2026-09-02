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

/// Days from 1970-01-01 to the given proleptic Gregorian date.
///
/// Howard Hinnant's `days_from_civil`; the calendar shifts to start in March
/// so that the leap day lands at the end of the year and the month-length
/// pattern becomes a simple linear formula.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Parse a directory document timestamp: `YYYY-MM-DD HH:MM:SS`, always UTC.
pub fn parse_datetime(date: &str, time: &str) -> io::Result<u64> {
    let bad = || invalid_data(format!("bad timestamp {date:?} {time:?}"));
    let mut d = date.split('-');
    let year: i64 = d.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let month: i64 = d.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let day: i64 = d.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    if d.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(bad());
    }
    let mut t = time.split(':');
    let hour: i64 = t.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let minute: i64 = t.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let second: i64 = t.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    if t.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return Err(bad());
    }
    let seconds =
        days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    u64::try_from(seconds).map_err(|_| bad())
}

/// Format a unix timestamp the way directory documents do, for log messages.
pub fn format_datetime(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    // Invert days_from_civil.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
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
    fn datetime_round_trip() {
        assert_eq!(parse_datetime("1970-01-01", "00:00:00").unwrap(), 0);
        assert_eq!(parse_datetime("2000-03-01", "00:00:00").unwrap(), 951_868_800);
        assert_eq!(parse_datetime("2026-09-02", "12:34:56").unwrap(), 1_788_352_496);
        // A leap day must land where the Gregorian calendar puts it.
        assert_eq!(
            parse_datetime("2024-02-29", "00:00:00").unwrap() + 86_400,
            parse_datetime("2024-03-01", "00:00:00").unwrap()
        );
        for stamp in [
            (0, "1970-01-01 00:00:00"),
            (1_788_352_496, "2026-09-02 12:34:56"),
            (951_868_800, "2000-03-01 00:00:00"),
        ] {
            assert_eq!(format_datetime(stamp.0), stamp.1);
        }
        assert!(parse_datetime("2026-13-01", "00:00:00").is_err());
        assert!(parse_datetime("2026-09-02", "24:00:00").is_err());
        assert!(parse_datetime("nope", "00:00:00").is_err());
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xa5, 0xff]), "000FA5FF");
        assert_eq!(hex_decode("000fA5ff").unwrap(), vec![0x00, 0x0f, 0xa5, 0xff]);
        assert!(hex_decode("abc").is_err());
        assert!(hex_decode("zz").is_err());
    }
}
