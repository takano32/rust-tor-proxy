//! HTTP over a BEGIN_DIR stream.
//!
//! Directory documents are fetched by opening a RELAY_BEGIN_DIR stream to a
//! relay's own directory cache and speaking plain HTTP/1.0 over it.
//!
//! Responses are compressed when zlib could be loaded. dir-spec says clients
//! SHOULD advertise `Accept-Encoding` rather than asking for the legacy `.z`
//! URL, and that anonymous requests -- the ones made over a multi-hop circuit,
//! such as an onion service lookup -- should advertise nothing but `deflate`,
//! so that the header itself does not distinguish us. Advertising only
//! `deflate` everywhere satisfies both, and every directory server is required
//! to support it.

use std::io::{self, Read, Write};

use crate::ffi::zlib;
use crate::tor::circuit::Circuit;
use crate::util::invalid_data;

/// Refuse absurd responses rather than growing a buffer without bound. Applied
/// to the compressed bytes as they arrive and again to the inflated result, so
/// a compression bomb cannot get past it.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// How many BEGIN_DIR streams [`get_parallel`] runs at once on one circuit.
///
/// Each stream has its own flow-control window but they share the circuit's,
/// so beyond a handful the circuit window becomes the limit and the extra
/// threads only add cells in flight.
pub const MAX_PARALLEL_REQUESTS: usize = 4;

/// `GET path` from the directory cache at the far end of `circuit`.
pub fn get(circuit: &Circuit, path: &str) -> io::Result<Vec<u8>> {
    get_with(circuit, path, &[])
}

/// `GET path` with extra request headers, as `(name, value)` pairs.
///
/// The one caller that needs them asks for a consensus diff, which is a header
/// rather than a different URL.
pub fn get_with(circuit: &Circuit, path: &str, headers: &[(&str, String)]) -> io::Result<Vec<u8>> {
    let mut stream = circuit.begin_dir_stream()?;
    stream.write_all(request(path, &circuit.peer().ip().to_string(), headers).as_bytes())?;
    stream.flush()?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if raw.len() + n > MAX_RESPONSE_BYTES {
                    stream.close();
                    return Err(invalid_data("directory response is implausibly large"));
                }
                raw.extend_from_slice(&chunk[..n]);
            }
            Err(e) => {
                stream.close();
                return Err(e);
            }
        }
    }
    stream.close();
    parse_response(raw)
}

/// Fetch several paths over one circuit at the same time, each on its own
/// BEGIN_DIR stream. The result is in the same order as `paths`.
///
/// A circuit already multiplexes streams, so this costs nothing but threads,
/// and it turns the HSDir ring's thirty-odd microdescriptor batches from a
/// chain of round trips into a handful.
pub fn get_parallel(circuit: &Circuit, paths: &[String]) -> Vec<io::Result<Vec<u8>>> {
    let mut results: Vec<io::Result<Vec<u8>>> = Vec::with_capacity(paths.len());
    for group in paths.chunks(MAX_PARALLEL_REQUESTS) {
        let mut group_results: Vec<io::Result<Vec<u8>>> = Vec::with_capacity(group.len());
        std::thread::scope(|scope| {
            let handles: Vec<_> = group
                .iter()
                .map(|path| scope.spawn(move || get(circuit, path)))
                .collect();
            for handle in handles {
                group_results.push(match handle.join() {
                    Ok(result) => result,
                    // A panic in a fetch thread is a bug, but it must not take
                    // the whole directory operation down with it.
                    Err(_) => Err(io::Error::other("directory fetch thread panicked")),
                });
            }
        });
        results.append(&mut group_results);
    }
    results
}

fn request(path: &str, host: &str, headers: &[(&str, String)]) -> String {
    // Only deflate: see the module comment on why the list is kept to one.
    let encoding = if zlib::available() {
        "deflate"
    } else {
        "identity"
    };
    let mut out = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nAccept-Encoding: {encoding}\r\n");
    for (name, value) in headers {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out
}

/// Split an HTTP/1.0 response, decompress the body if it is encoded, and fail
/// on a non-200.
fn parse_response(mut raw: Vec<u8>) -> io::Result<Vec<u8>> {
    let header_end = find_header_end(&raw)
        .ok_or_else(|| invalid_data("directory response has no header terminator"))?;
    let header = String::from_utf8_lossy(&raw[..header_end]).into_owned();
    let mut lines = header.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| invalid_data("empty directory response"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| invalid_data(format!("bad HTTP status line {status_line:?}")))?;
    if status != 200 {
        // Neither of these is a malformed answer. 404 is the ordinary "not on
        // this directory node" for an onion service descriptor, and the caller
        // moves on to the next one. 304 answers a diff request with "you
        // already have the current consensus", which is a result, not a
        // failure -- and refetching the document after it would be pure waste.
        let kind = match status {
            404 => io::ErrorKind::NotFound,
            304 => io::ErrorKind::AlreadyExists,
            _ => io::ErrorKind::InvalidData,
        };
        return Err(io::Error::new(
            kind,
            format!("directory server answered HTTP {status}"),
        ));
    }
    let encoding = header_value(&header, "content-encoding").unwrap_or_else(|| "identity".into());

    // Drop the header in place so the (possibly multi-megabyte) body is not
    // copied into a second allocation.
    raw.drain(..header_end + 4);
    decode_body(raw, &encoding)
}

fn decode_body(body: Vec<u8>, encoding: &str) -> io::Result<Vec<u8>> {
    match encoding {
        "identity" | "" => Ok(body),
        // gzip is not advertised, but the two framings differ only in their
        // header and inflate_all detects either, so accepting it costs nothing.
        "deflate" | "gzip" => zlib::inflate_all(&body, MAX_RESPONSE_BYTES),
        other => Err(invalid_data(format!(
            "directory server used {other:?} compression, which was not offered"
        ))),
    }
}

/// The value of a header, matched case-insensitively as HTTP requires.
fn header_value(header: &str, name: &str) -> Option<String> {
    header.split("\r\n").skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(name) {
            Some(value.trim().to_ascii_lowercase())
        } else {
            None
        }
    })
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_headers_from_body() {
        let raw = b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec();
        assert_eq!(parse_response(raw).unwrap(), b"hello");
    }

    /// A 304 answers "you already have it", and has to be told apart from a
    /// real failure so that the caller does not refetch the whole consensus.
    #[test]
    fn not_modified_has_its_own_kind() {
        let raw = b"HTTP/1.0 304 Not modified\r\n\r\n".to_vec();
        let err = parse_response(raw).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(err.to_string().contains("304"), "{err}");
    }

    #[test]
    fn reports_error_statuses() {
        let raw = b"HTTP/1.0 404 Not found\r\n\r\n".to_vec();
        let err = parse_response(raw).unwrap_err();
        assert!(err.to_string().contains("404"), "{err}");
        assert_eq!(
            err.kind(),
            io::ErrorKind::NotFound,
            "404 must be its own kind"
        );
        let raw = b"HTTP/1.0 503 Busy\r\n\r\n".to_vec();
        assert_eq!(
            parse_response(raw).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(parse_response(b"garbage".to_vec()).is_err());
        assert!(parse_response(b"nonsense\r\n\r\nbody".to_vec()).is_err());
    }

    #[test]
    fn empty_body_is_allowed() {
        let raw = b"HTTP/1.0 200 OK\r\nX: y\r\n\r\n".to_vec();
        assert_eq!(parse_response(raw).unwrap(), Vec::<u8>::new());
    }

    /// Header names are case-insensitive, and a server that says nothing about
    /// the encoding is sending the document as it is.
    #[test]
    fn reads_the_content_encoding_header_in_any_case() {
        let header = "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nCONTENT-ENCODING: Deflate\r\n";
        assert_eq!(
            header_value(header, "content-encoding").as_deref(),
            Some("deflate")
        );
        assert_eq!(header_value(header, "content-length"), None);
        // The status line is never mistaken for a header.
        assert_eq!(header_value("HTTP/1.0 200 OK\r\n", "http/1.0"), None);
    }

    #[test]
    fn refuses_an_encoding_that_was_never_offered() {
        assert!(decode_body(vec![1, 2, 3], "x-zstd").is_err());
        assert_eq!(decode_body(vec![1, 2, 3], "identity").unwrap(), [1, 2, 3]);
    }

    /// The request must be a well-formed HTTP/1.0 request line plus headers,
    /// with whatever extras the caller passed in.
    #[test]
    fn request_carries_host_and_extra_headers() {
        let text = request(
            "/tor/status-vote/current/consensus-microdesc",
            "1.2.3.4",
            &[("X-Or-Diff-From-Consensus", "ABCD".to_string())],
        );
        assert!(text.starts_with(
            "GET /tor/status-vote/current/consensus-microdesc HTTP/1.0\r\nHost: 1.2.3.4\r\n"
        ));
        assert!(text.contains("X-Or-Diff-From-Consensus: ABCD\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
        // Exactly one encoding is offered, and never a wildcard.
        assert_eq!(text.matches("Accept-Encoding:").count(), 1);
        assert!(!text.contains('*'));
    }

    /// A body the server really did compress must come back out again.
    #[test]
    fn inflates_a_deflated_body() {
        if !zlib::available() {
            return;
        }
        // "hello hello hello hello" deflated, produced with python3 zlib.
        const DEFLATED: &[u8] = &[
            0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40, 0x27, 0x01, 0x68, 0x03,
            0x08, 0xb1,
        ];
        let mut raw = b"HTTP/1.0 200 OK\r\nContent-Encoding: deflate\r\n\r\n".to_vec();
        raw.extend_from_slice(DEFLATED);
        assert_eq!(parse_response(raw).unwrap(), b"hello hello hello hello");
    }
}
