//! HTTP over a BEGIN_DIR stream.
//!
//! Directory documents are fetched by opening a RELAY_BEGIN_DIR stream to a
//! relay's own directory cache and speaking plain HTTP/1.0 over it. No
//! compression is requested: adding zlib would mean another FFI surface, and
//! the only large document is the consensus.

use std::io::{Read, Write};
use std::io::{self};

use crate::tor::circuit::Circuit;
use crate::util::invalid_data;

/// Refuse absurd responses rather than growing a buffer without bound.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// `GET path` from the directory cache at the far end of `circuit`.
pub fn get(circuit: &Circuit, path: &str) -> io::Result<Vec<u8>> {
    let mut stream = circuit.begin_dir_stream()?;
    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: {}\r\nAccept-Encoding: identity\r\n\r\n",
        circuit.peer().ip()
    );
    stream.write_all(request.as_bytes())?;
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

/// Split an HTTP/1.0 response and return its body, or fail on a non-200.
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
        return Err(invalid_data(format!(
            "directory server answered HTTP {status}"
        )));
    }
    // Drop the header in place so the (possibly multi-megabyte) body is not
    // copied into a second allocation.
    raw.drain(..header_end + 4);
    Ok(raw)
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

    #[test]
    fn reports_error_statuses() {
        let raw = b"HTTP/1.0 404 Not found\r\n\r\n".to_vec();
        let err = parse_response(raw).unwrap_err();
        assert!(err.to_string().contains("404"), "{err}");
        assert!(parse_response(b"garbage".to_vec()).is_err());
        assert!(parse_response(b"nonsense\r\n\r\nbody".to_vec()).is_err());
    }

    #[test]
    fn empty_body_is_allowed() {
        let raw = b"HTTP/1.0 200 OK\r\nX: y\r\n\r\n".to_vec();
        assert_eq!(parse_response(raw).unwrap(), Vec::<u8>::new());
    }
}
