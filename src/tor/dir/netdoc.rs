//! Minimal helpers for Tor's directory document format (dir-spec/netdoc.md).
//!
//! A document is a sequence of "items": a keyword, optional space-separated
//! arguments, and optionally a PEM-wrapped "object" on the following lines.
//! Only what the consensus, key certificates and microdescriptors need is
//! implemented here.

use std::io;

use crate::util::{base64_decode, invalid_data};

/// Arguments of the first item with this keyword, if any.
pub fn item<'a>(text: &'a str, keyword: &str) -> Option<&'a str> {
    text.lines().find_map(|line| item_args(line, keyword))
}

/// If `line` is an item with `keyword`, its arguments.
pub fn item_args<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(keyword)?;
    match rest.chars().next() {
        None => Some(""),
        Some(' ') => Some(rest[1..].trim_end()),
        Some(_) => None,
    }
}

/// The DER bytes of the first PEM object with this label.
pub fn object(text: &str, label: &str) -> io::Result<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text
        .find(&begin)
        .ok_or_else(|| invalid_data(format!("missing {begin}")))?
        + begin.len();
    let rest = &text[start..];
    let stop = rest
        .find(&end)
        .ok_or_else(|| invalid_data(format!("missing {end}")))?;
    base64_decode(&rest[..stop])
}

/// Byte offset just past the newline that ends the first line starting with
/// `keyword` at the beginning of a line.
pub fn line_end_after(text: &str, keyword: &str) -> Option<usize> {
    let start = line_start_of(text, keyword)?;
    let newline = text[start..].find('\n')?;
    Some(start + newline + 1)
}

/// Byte offset of the first line that begins with `keyword`.
pub fn line_start_of(text: &str, keyword: &str) -> Option<usize> {
    if text.starts_with(keyword) {
        return Some(0);
    }
    let pattern = format!("\n{keyword}");
    text.find(&pattern).map(|i| i + 1)
}

/// A parsed base64 argument of a fixed size.
pub fn base64_fixed<const N: usize>(value: &str) -> io::Result<[u8; N]> {
    let bytes = base64_decode(value)?;
    bytes
        .try_into()
        .map_err(|_| invalid_data(format!("expected {N} bytes of base64")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = "\
network-status-version 3 microdesc
valid-after 2026-09-02 10:00:00
flag-with-no-args
r Unnamed AAAA 2026-09-02 10:00:00 1.2.3.4 443 0
";

    #[test]
    fn reads_item_arguments() {
        assert_eq!(item(DOC, "network-status-version"), Some("3 microdesc"));
        assert_eq!(item(DOC, "valid-after"), Some("2026-09-02 10:00:00"));
        assert_eq!(item(DOC, "flag-with-no-args"), Some(""));
        assert_eq!(item(DOC, "missing"), None);
        // A prefix match must not be mistaken for the keyword.
        assert_eq!(item(DOC, "valid"), None);
        assert_eq!(item(DOC, "network-status"), None);
    }

    #[test]
    fn finds_line_boundaries() {
        assert_eq!(line_start_of(DOC, "network-status-version"), Some(0));
        let start = line_start_of(DOC, "valid-after").unwrap();
        assert!(DOC[start..].starts_with("valid-after"));
        assert_eq!(
            &DOC[..line_end_after(DOC, "valid-after").unwrap()],
            "network-status-version 3 microdesc\nvalid-after 2026-09-02 10:00:00\n"
        );
        assert_eq!(line_start_of(DOC, "nothing"), None);
    }

    #[test]
    fn extracts_objects() {
        let doc = "dir-signing-key\n-----BEGIN RSA PUBLIC KEY-----\naGVsbG8=\n-----END RSA PUBLIC KEY-----\n";
        assert_eq!(object(doc, "RSA PUBLIC KEY").unwrap(), b"hello");
        assert!(object(doc, "SIGNATURE").is_err());
    }
}
