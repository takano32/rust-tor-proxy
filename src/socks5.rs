//! The proxy front end: SOCKS5, SOCKS4a and HTTP CONNECT on one port.
//!
//! Which of the three a connection is speaking is decided by its first byte --
//! `0x05`, `0x04`, or a letter -- so no configuration is needed to point
//! `proxychains` (SOCKS4 by default) or `https_proxy=http://...` at the same
//! listener as `curl --socks5-hostname`.
//!
//! Host names are passed to the exit relay untouched: resolving them locally
//! would leak the destination to the local resolver, which is why clients
//! should always use `--socks5-hostname` / `socks5h://`. SOCKS4a and CONNECT
//! both carry a name rather than an address, so they leak nothing either.
//!
//! A `.onion` host name never reaches an exit at all: it is a v3 onion
//! address, and goes to a rendezvous circuit instead.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use crate::relay;
use crate::tor::circuit::{self, StreamEnd};
use crate::tor::client::TorClient;
use crate::tor::hs::address::{self, OnionAddress};
use crate::util::invalid_data;

const VERSION: u8 = 0x05;
const SOCKS4_VERSION: u8 = 0x04;
const METHOD_NO_AUTH: u8 = 0x00;
/// Username and password (RFC 1929). Accepted and thrown away: the
/// credentials are not used for anything, and refusing them would turn away
/// clients that only offer this method.
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NONE_ACCEPTABLE: u8 = 0xff;

/// SOCKS4 reply codes.
const SOCKS4_GRANTED: u8 = 90;
const SOCKS4_REJECTED: u8 = 91;

/// A CONNECT request's headers may not run past this, so that a client which
/// never sends the blank line cannot make us buffer without bound.
const MAX_HTTP_HEADER_BYTES: usize = 8 * 1024;

const CMD_CONNECT: u8 = 0x01;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REP_SUCCEEDED: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_NOT_ALLOWED: u8 = 0x02;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_TTL_EXPIRED: u8 = 0x06;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// How long the client has to finish the SOCKS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Which protocol a client is speaking, so the answer can be phrased in it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Protocol {
    Socks5,
    Socks4,
    Http,
}

/// What the client asked for.
struct Request {
    host: String,
    port: u16,
    protocol: Protocol,
}

pub fn handle(mut client: TcpStream, tor: &Arc<TorClient>) {
    let peer = client
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into());

    if let Err(e) = client.set_read_timeout(Some(HANDSHAKE_TIMEOUT)) {
        crate::debug!("{peer}: could not set a handshake timeout: {e}");
        return;
    }
    // The tunnelled traffic is already carried in 498-byte relay cells, so
    // there is nothing for Nagle to coalesce and only latency to add.
    if let Err(e) = client.set_nodelay(true) {
        crate::debug!("{peer}: could not disable Nagle: {e}");
    }
    let request = match negotiate(&mut client) {
        Ok(request) => request,
        Err(e) => {
            crate::debug!("{peer}: SOCKS handshake failed: {e}");
            return;
        }
    };
    // An onion address names the destination in full, so it is only ever
    // logged at debug: an info line would put every service a user visits in
    // the log.
    if address::is_onion(&request.host) {
        crate::info!("{peer} -> an onion service, port {}", request.port);
        crate::debug!("{peer} -> {}:{}", request.host, request.port);
    } else {
        crate::info!("{peer} -> {}:{}", request.host, request.port);
    }

    let stream = match connect(tor, &request) {
        Ok(stream) => stream,
        Err(e) => {
            if address::is_onion(&request.host) {
                crate::warn!("{peer}: onion service on port {} failed: {e}", request.port);
            } else {
                crate::warn!("{peer}: {}:{} failed: {e}", request.host, request.port);
            }
            let _ = send_reply(&mut client, request.protocol, reply_code(&e));
            return;
        }
    };
    if let Err(e) = send_reply(&mut client, request.protocol, REP_SUCCEEDED) {
        crate::debug!("{peer}: could not send the SOCKS reply: {e}");
        stream.close();
        return;
    }
    // The handshake timeout must not apply to the tunnelled connection.
    let _ = client.set_read_timeout(None);

    let reader = stream.try_clone();
    if let Err(e) = relay::bidirectional(client, reader, stream.try_clone()) {
        // With optimistic data the SOCKS reply has already gone out by the
        // time a refusal arrives, so the client sees a closed connection
        // rather than a status code. Say why here, or the reason is lost.
        if circuit::is_stream_end(&e) {
            crate::info!("{peer}: the far end closed the stream: {e}");
        } else {
            crate::debug!("{peer}: relay ended: {e}");
        }
    }
    stream.close();
}

/// Where a request wants to go.
enum Destination {
    /// A host name or address for an exit relay to resolve and connect to.
    Exit,
    /// A v3 onion service, reached through a rendezvous circuit.
    Onion(OnionAddress),
}

/// Decide which of the two a host name names.
///
/// A `.onion` that does not parse -- a version 2 address, or a mistyped one --
/// is reported as an unreachable host rather than a general failure: no exit
/// could resolve it either, so the client should not retry.
fn classify(host: &str) -> io::Result<Destination> {
    if !address::is_onion(host) {
        return Ok(Destination::Exit);
    }
    match OnionAddress::parse(host) {
        Ok(onion) => Ok(Destination::Onion(onion)),
        Err(e) => Err(io::Error::new(io::ErrorKind::NotFound, e)),
    }
}

fn connect(tor: &Arc<TorClient>, request: &Request) -> io::Result<crate::tor::circuit::TorStream> {
    match classify(&request.host)? {
        Destination::Exit => tor.connect(&request.host, request.port),
        Destination::Onion(onion) => tor.connect_onion(&onion, request.port),
    }
}

/// Work out which protocol the client is speaking from its first byte, and
/// run that protocol's handshake.
fn negotiate(client: &mut TcpStream) -> io::Result<Request> {
    let mut first = [0u8; 1];
    client.read_exact(&mut first)?;
    match first[0] {
        VERSION => negotiate_socks5(client),
        SOCKS4_VERSION => negotiate_socks4(client),
        // An HTTP method always starts with an uppercase letter.
        b'A'..=b'Z' => negotiate_http(client, first[0]),
        other => Err(invalid_data(format!(
            "connection starts with {other:#04x}, which is no protocol we speak"
        ))),
    }
}

/// SOCKS5 (RFC 1928): the method greeting, then the CONNECT request.
fn negotiate_socks5(client: &mut TcpStream) -> io::Result<Request> {
    let mut count = [0u8; 1];
    client.read_exact(&mut count)?;
    let mut methods = vec![0u8; count[0] as usize];
    client.read_exact(&mut methods)?;

    if methods.contains(&METHOD_NO_AUTH) {
        client.write_all(&[VERSION, METHOD_NO_AUTH])?;
    } else if methods.contains(&METHOD_USER_PASS) {
        // Some clients offer nothing else. Take the credentials, ignore them,
        // and carry on: this proxy has no notion of users, and refusing would
        // only turn those clients away.
        client.write_all(&[VERSION, METHOD_USER_PASS])?;
        read_username_password(client)?;
        client.write_all(&[0x01, 0x00])?;
    } else {
        client.write_all(&[VERSION, METHOD_NONE_ACCEPTABLE])?;
        return Err(invalid_data("client offered no acceptable auth method"));
    }

    let mut header = [0u8; 4];
    client.read_exact(&mut header)?;
    if header[0] != VERSION {
        return Err(invalid_data("bad SOCKS version in request"));
    }
    if header[1] != CMD_CONNECT {
        send_reply(client, Protocol::Socks5, REP_COMMAND_NOT_SUPPORTED)?;
        return Err(invalid_data(format!("unsupported command {}", header[1])));
    }

    let host = match header[3] {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            client.read_exact(&mut addr)?;
            std::net::Ipv4Addr::from(addr).to_string()
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len)?;
            let mut name = vec![0u8; len[0] as usize];
            client.read_exact(&mut name)?;
            String::from_utf8(name).map_err(|_| invalid_data("host name is not UTF-8"))?
        }
        ATYP_IPV6 => {
            // Reading the address keeps the stream in sync for the reply.
            let mut addr = [0u8; 16];
            client.read_exact(&mut addr)?;
            let mut port = [0u8; 2];
            client.read_exact(&mut port)?;
            send_reply(client, Protocol::Socks5, REP_ADDRESS_TYPE_NOT_SUPPORTED)?;
            return Err(invalid_data("IPv6 destinations are not supported"));
        }
        other => {
            send_reply(client, Protocol::Socks5, REP_ADDRESS_TYPE_NOT_SUPPORTED)?;
            return Err(invalid_data(format!("unknown address type {other}")));
        }
    };

    let mut port = [0u8; 2];
    client.read_exact(&mut port)?;
    let port = u16::from_be_bytes(port);
    if port == 0 || host.is_empty() {
        send_reply(client, Protocol::Socks5, REP_GENERAL_FAILURE)?;
        return Err(invalid_data("empty host or port"));
    }
    Ok(Request {
        host,
        port,
        protocol: Protocol::Socks5,
    })
}

/// RFC 1929: `VER=1 | ULEN | UNAME | PLEN | PASSWD`, read and discarded.
fn read_username_password(client: &mut TcpStream) -> io::Result<()> {
    let mut version = [0u8; 1];
    client.read_exact(&mut version)?;
    if version[0] != 0x01 {
        return Err(invalid_data(format!(
            "unsupported username/password version {}",
            version[0]
        )));
    }
    for _ in 0..2 {
        let mut len = [0u8; 1];
        client.read_exact(&mut len)?;
        let mut field = vec![0u8; len[0] as usize];
        client.read_exact(&mut field)?;
    }
    Ok(())
}

/// SOCKS4 and SOCKS4a: `CD | DSTPORT(2) | DSTIP(4) | USERID NUL [ HOST NUL ]`.
///
/// A DSTIP of `0.0.0.x` with a non-zero last byte is the 4a marker: the real
/// destination is a host name after the user id, which is what lets a SOCKS4
/// client reach a name -- and a `.onion` -- without resolving it first.
fn negotiate_socks4(client: &mut TcpStream) -> io::Result<Request> {
    let mut header = [0u8; 7];
    client.read_exact(&mut header)?;
    let command = header[0];
    let port = u16::from_be_bytes([header[1], header[2]]);
    let addr = [header[3], header[4], header[5], header[6]];

    if command != CMD_CONNECT {
        send_reply(client, Protocol::Socks4, REP_COMMAND_NOT_SUPPORTED)?;
        return Err(invalid_data(format!(
            "unsupported SOCKS4 command {command}"
        )));
    }
    // The user id is not used for anything; it is read to stay in step.
    let _user = read_until_nul(client, 256)?;

    let is_4a = addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] != 0;
    let host = if is_4a {
        let name = read_until_nul(client, 256)?;
        String::from_utf8(name).map_err(|_| invalid_data("SOCKS4a host name is not UTF-8"))?
    } else {
        std::net::Ipv4Addr::from(addr).to_string()
    };

    if port == 0 || host.is_empty() {
        send_reply(client, Protocol::Socks4, REP_GENERAL_FAILURE)?;
        return Err(invalid_data("empty host or port"));
    }
    Ok(Request {
        host,
        port,
        protocol: Protocol::Socks4,
    })
}

/// Read a NUL-terminated field one byte at a time.
///
/// Byte at a time because the socket is handed straight to the tunnel
/// afterwards: a buffered reader would swallow whatever the client sent next.
fn read_until_nul(client: &mut TcpStream, limit: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        client.read_exact(&mut byte)?;
        if byte[0] == 0 {
            return Ok(out);
        }
        if out.len() >= limit {
            return Err(invalid_data("SOCKS4 field is too long"));
        }
        out.push(byte[0]);
    }
}

/// `CONNECT host:port HTTP/1.x`, so that `https_proxy=http://127.0.0.1:9050`
/// works without a SOCKS-aware client.
fn negotiate_http(client: &mut TcpStream, first: u8) -> io::Result<Request> {
    let head = read_http_head(client, first)?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut fields = request_line.split_whitespace();
    let method = fields.next().unwrap_or_default();
    let target = fields.next().unwrap_or_default();

    if !method.eq_ignore_ascii_case("CONNECT") {
        // A plain proxied request (an absolute-URI GET) would send the whole
        // exchange in clear through the exit, so say what to use instead
        // rather than doing it.
        let body = "This is a Tor proxy. Use CONNECT, or point a SOCKS client \
                    at this port (socks5h://).\n";
        let response = format!(
            "HTTP/1.1 501 Not Implemented\r\nContent-Type: text/plain\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        client.write_all(response.as_bytes())?;
        return Err(invalid_data(format!(
            "HTTP method {method:?} is not supported; only CONNECT is"
        )));
    }

    let (host, port) = match target.rsplit_once(':') {
        Some((host, port)) => (
            host.trim_matches(['[', ']']).to_string(),
            port.parse::<u16>()
                .map_err(|_| invalid_data(format!("bad CONNECT port in {target:?}")))?,
        ),
        // CONNECT is defined to carry a port, but defaulting costs nothing.
        None => (target.to_string(), 443),
    };
    if port == 0 || host.is_empty() {
        send_reply(client, Protocol::Http, REP_GENERAL_FAILURE)?;
        return Err(invalid_data("empty host or port"));
    }
    Ok(Request {
        host,
        port,
        protocol: Protocol::Http,
    })
}

/// Read the request line and headers, up to and including the blank line.
fn read_http_head(client: &mut TcpStream, first: u8) -> io::Result<String> {
    let mut head = vec![first];
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HTTP_HEADER_BYTES {
            return Err(invalid_data("HTTP request headers are too long"));
        }
        client.read_exact(&mut byte)?;
        head.push(byte[0]);
        // Tolerate bare LF line endings from hand-typed requests.
        if head.ends_with(b"\n\n") {
            break;
        }
    }
    String::from_utf8(head).map_err(|_| invalid_data("HTTP request is not UTF-8"))
}

/// Answer the request in whichever protocol asked it.
///
/// SOCKS replies always name 0.0.0.0:0 as the bound address: the client does
/// not need it, and the exit's real address is not ours to hand out.
fn send_reply(client: &mut TcpStream, protocol: Protocol, code: u8) -> io::Result<()> {
    match protocol {
        Protocol::Socks5 => client.write_all(&[VERSION, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]),
        Protocol::Socks4 => {
            // SOCKS4 has only "granted" and "rejected", and the version byte
            // in a reply is zero rather than 4.
            let status = if code == REP_SUCCEEDED {
                SOCKS4_GRANTED
            } else {
                SOCKS4_REJECTED
            };
            client.write_all(&[0x00, status, 0, 0, 0, 0, 0, 0])
        }
        Protocol::Http => {
            let status = match code {
                REP_SUCCEEDED => "200 Connection established",
                REP_NOT_ALLOWED => "403 Forbidden",
                REP_HOST_UNREACHABLE => "404 Not Found",
                REP_CONNECTION_REFUSED => "502 Bad Gateway",
                REP_TTL_EXPIRED => "504 Gateway Timeout",
                _ => "502 Bad Gateway",
            };
            let closing = if code == REP_SUCCEEDED {
                ""
            } else {
                "Connection: close\r\n"
            };
            client.write_all(format!("HTTP/1.1 {status}\r\n{closing}\r\n").as_bytes())
        }
    }
}

/// Map a failure to open the Tor stream onto a SOCKS reply code.
fn reply_code(error: &io::Error) -> u8 {
    if let Some(end) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<StreamEnd>())
    {
        return match end.0 {
            circuit::END_REASON_EXITPOLICY => REP_NOT_ALLOWED,
            circuit::END_REASON_RESOLVEFAILED | circuit::END_REASON_NOROUTE => REP_HOST_UNREACHABLE,
            circuit::END_REASON_CONNECTREFUSED => REP_CONNECTION_REFUSED,
            circuit::END_REASON_TIMEOUT => REP_TTL_EXPIRED,
            _ => REP_GENERAL_FAILURE,
        };
    }
    match error.kind() {
        io::ErrorKind::ConnectionRefused => REP_CONNECTION_REFUSED,
        io::ErrorKind::TimedOut => REP_TTL_EXPIRED,
        io::ErrorKind::NotFound => REP_HOST_UNREACHABLE,
        io::ErrorKind::PermissionDenied => REP_NOT_ALLOWED,
        _ => REP_GENERAL_FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    /// Drive `negotiate` over a real socket pair and return what it made of
    /// the request, plus everything the server wrote back.
    fn negotiate_with(request: &[u8]) -> (io::Result<Request>, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let bytes = request.to_vec();
        let client = std::thread::spawn(move || {
            let mut sock = TcpStream::connect(addr).unwrap();
            sock.write_all(&bytes).unwrap();
            sock.shutdown(std::net::Shutdown::Write).unwrap();
            let mut seen = Vec::new();
            let _ = sock.read_to_end(&mut seen);
            seen
        });
        let (mut server, _) = listener.accept().unwrap();
        let result = negotiate(&mut server);
        // Close in two steps. A socket dropped while unread bytes are still
        // in its receive buffer -- which is exactly what a rejected request
        // leaves behind -- makes the kernel send RST rather than FIN, and the
        // RST can throw away the reply the client has not read yet.
        server.shutdown(std::net::Shutdown::Write).unwrap();
        let _ = server.read_to_end(&mut Vec::new());
        drop(server);
        (result, client.join().unwrap())
    }

    #[test]
    fn accepts_a_hostname_connect() {
        let mut request = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, ATYP_DOMAIN, 11];
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&443u16.to_be_bytes());
        let (parsed, written) = negotiate_with(&request);
        let parsed = parsed.expect("should parse");
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(written, vec![0x05, 0x00]);
    }

    #[test]
    fn accepts_an_ipv4_connect() {
        let mut request = vec![
            0x05, 0x01, 0x00, 0x05, 0x01, 0x00, ATYP_IPV4, 93, 184, 216, 34,
        ];
        request.extend_from_slice(&80u16.to_be_bytes());
        let (parsed, _) = negotiate_with(&request);
        let parsed = parsed.expect("should parse");
        assert_eq!(parsed.host, "93.184.216.34");
        assert_eq!(parsed.port, 80);
    }

    #[test]
    fn rejects_ipv6_with_the_right_code() {
        let mut request = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, ATYP_IPV6];
        request.extend_from_slice(&[0u8; 16]);
        request.extend_from_slice(&443u16.to_be_bytes());
        let (parsed, written) = negotiate_with(&request);
        assert!(parsed.is_err());
        assert_eq!(written[..2], [0x05, 0x00], "auth is negotiated first");
        assert_eq!(written[2..4], [0x05, REP_ADDRESS_TYPE_NOT_SUPPORTED]);
    }

    #[test]
    fn rejects_bind_and_associate() {
        let request = vec![
            0x05, 0x01, 0x00, 0x05, 0x02, 0x00, ATYP_IPV4, 1, 2, 3, 4, 0, 80,
        ];
        let (parsed, written) = negotiate_with(&request);
        assert!(parsed.is_err());
        assert_eq!(written[2..4], [0x05, REP_COMMAND_NOT_SUPPORTED]);
    }

    #[test]
    fn refuses_clients_without_no_auth() {
        // Offers only GSSAPI (0x01).
        let request = vec![0x05, 0x01, 0x01];
        let (parsed, written) = negotiate_with(&request);
        assert!(parsed.is_err());
        assert_eq!(written, vec![0x05, METHOD_NONE_ACCEPTABLE]);
    }

    /// proxychains' default configuration is `socks4 127.0.0.1 9050`, and
    /// its 4a form is what carries a host name -- a `.onion` included --
    /// without the client resolving it first.
    #[test]
    fn accepts_socks4a_with_a_hostname() {
        let mut request = vec![0x04, 0x01];
        request.extend_from_slice(&443u16.to_be_bytes());
        request.extend_from_slice(&[0, 0, 0, 7]); // 0.0.0.x marks 4a
        request.extend_from_slice(b"someuser\0");
        request.extend_from_slice(b"example.com\0");
        let (parsed, written) = negotiate_with(&request);
        let parsed = parsed.expect("should parse");
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.protocol, Protocol::Socks4);
        // Nothing is written until the destination has been reached.
        assert!(written.is_empty(), "{written:?}");
    }

    /// Plain SOCKS4 names an address rather than a host, which the exit is
    /// perfectly able to connect to.
    #[test]
    fn accepts_plain_socks4_with_an_address() {
        let mut request = vec![0x04, 0x01];
        request.extend_from_slice(&80u16.to_be_bytes());
        request.extend_from_slice(&[93, 184, 216, 34]);
        request.extend_from_slice(b"\0");
        let (parsed, _) = negotiate_with(&request);
        let parsed = parsed.expect("should parse");
        assert_eq!(parsed.host, "93.184.216.34");
        assert_eq!(parsed.port, 80);
    }

    #[test]
    fn rejects_a_socks4_bind() {
        let mut request = vec![0x04, 0x02];
        request.extend_from_slice(&80u16.to_be_bytes());
        request.extend_from_slice(&[1, 2, 3, 4]);
        request.extend_from_slice(b"\0");
        let (parsed, written) = negotiate_with(&request);
        assert!(parsed.is_err());
        assert_eq!(written, vec![0x00, SOCKS4_REJECTED, 0, 0, 0, 0, 0, 0]);
    }

    /// `https_proxy=http://127.0.0.1:9050` sends a CONNECT, and expects a
    /// 200 before it starts its TLS handshake.
    #[test]
    fn accepts_an_http_connect() {
        let request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let (parsed, written) = negotiate_with(request);
        let parsed = parsed.expect("should parse");
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.protocol, Protocol::Http);
        assert!(written.is_empty(), "no reply until the stream is open");
    }

    /// A proxied plain-HTTP request would go through the exit in clear, so it
    /// is refused with an explanation rather than served.
    #[test]
    fn refuses_a_plain_proxied_request() {
        let request = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (parsed, written) = negotiate_with(request);
        assert!(parsed.is_err());
        let text = String::from_utf8_lossy(&written);
        assert!(text.starts_with("HTTP/1.1 501 "), "{text}");
        assert!(text.contains("socks5h://"), "{text}");
    }

    /// A client that offers only username/password is accepted and its
    /// credentials thrown away, rather than being turned back.
    #[test]
    fn accepts_a_client_that_only_offers_username_and_password() {
        let mut request = vec![0x05, 0x01, METHOD_USER_PASS];
        // RFC 1929: version, "bob", "hunter2".
        request.extend_from_slice(&[0x01, 3]);
        request.extend_from_slice(b"bob");
        request.push(7);
        request.extend_from_slice(b"hunter2");
        request.extend_from_slice(&[0x05, 0x01, 0x00, ATYP_DOMAIN, 11]);
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&443u16.to_be_bytes());
        let (parsed, written) = negotiate_with(&request);
        let parsed = parsed.expect("should parse");
        assert_eq!(parsed.host, "example.com");
        assert_eq!(
            written,
            vec![0x05, METHOD_USER_PASS, 0x01, 0x00],
            "the method is chosen, then the credentials are accepted"
        );
    }

    /// A first byte that belongs to none of the three protocols is dropped
    /// rather than guessed at.
    #[test]
    fn refuses_an_unknown_protocol() {
        for first in [0x00u8, 0x03, 0x06, 0x80, b'a'] {
            let (parsed, _) = negotiate_with(&[first, 0x01, 0x00, 0x50]);
            assert!(parsed.is_err(), "first byte {first:#04x}");
        }
    }

    /// Every entry point has to be able to phrase both answers.
    #[test]
    fn each_protocol_answers_in_its_own_words() {
        assert_eq!(
            reply_bytes(Protocol::Socks5, REP_SUCCEEDED),
            vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            reply_bytes(Protocol::Socks4, REP_SUCCEEDED),
            vec![0x00, SOCKS4_GRANTED, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            reply_bytes(Protocol::Socks4, REP_HOST_UNREACHABLE),
            vec![0x00, SOCKS4_REJECTED, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            String::from_utf8(reply_bytes(Protocol::Http, REP_SUCCEEDED)).unwrap(),
            "HTTP/1.1 200 Connection established\r\n\r\n"
        );
        let refused =
            String::from_utf8(reply_bytes(Protocol::Http, REP_CONNECTION_REFUSED)).unwrap();
        assert!(refused.starts_with("HTTP/1.1 502 "), "{refused}");
        assert!(refused.contains("Connection: close"), "{refused}");
    }

    /// Run `send_reply` over a socket pair and return what came out.
    fn reply_bytes(protocol: Protocol, code: u8) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut sock = TcpStream::connect(addr).unwrap();
            let mut seen = Vec::new();
            let _ = sock.read_to_end(&mut seen);
            seen
        });
        let (mut server, _) = listener.accept().unwrap();
        send_reply(&mut server, protocol, code).unwrap();
        drop(server);
        client.join().unwrap()
    }

    /// A `.onion` host is routed to the rendezvous path, and one that cannot
    /// be a v3 address is refused as unreachable -- which is what SOCKS code
    /// 04 means, and what the client should see rather than a retryable
    /// general failure.
    #[test]
    fn onion_hosts_are_routed_and_bad_ones_are_unreachable() {
        let valid = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
        assert!(matches!(classify(valid).unwrap(), Destination::Onion(_)));
        assert!(matches!(
            classify(&valid.to_uppercase()).unwrap(),
            Destination::Onion(_)
        ));
        assert!(matches!(
            classify("example.com").unwrap(),
            Destination::Exit
        ));
        assert!(matches!(
            classify("93.184.216.34").unwrap(),
            Destination::Exit
        ));

        for bad in ["expyuzz4wqqyqhjn.onion", "nope.onion", "aaaa.onion"] {
            let err = match classify(bad) {
                Err(e) => e,
                Ok(_) => panic!("{bad} must not parse as a v3 address"),
            };
            assert_eq!(err.kind(), io::ErrorKind::NotFound, "{bad}");
            assert_eq!(reply_code(&err), REP_HOST_UNREACHABLE, "{bad}");
        }
    }

    #[test]
    fn maps_end_reasons_to_socks_codes() {
        let cases = [
            (circuit::END_REASON_EXITPOLICY, REP_NOT_ALLOWED),
            (circuit::END_REASON_RESOLVEFAILED, REP_HOST_UNREACHABLE),
            (circuit::END_REASON_NOROUTE, REP_HOST_UNREACHABLE),
            (circuit::END_REASON_CONNECTREFUSED, REP_CONNECTION_REFUSED),
            (circuit::END_REASON_TIMEOUT, REP_TTL_EXPIRED),
            (circuit::END_REASON_MISC, REP_GENERAL_FAILURE),
        ];
        for (reason, expected) in cases {
            let error: io::Error = StreamEnd(reason).into();
            assert_eq!(reply_code(&error), expected, "reason {reason}");
        }
        assert_eq!(
            reply_code(&io::Error::other("something else")),
            REP_GENERAL_FAILURE
        );
    }

    #[test]
    fn reply_frame_is_well_formed() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut sock = TcpStream::connect(addr).unwrap();
            let mut seen = Vec::new();
            let _ = sock.read_to_end(&mut seen);
            seen
        });
        let (mut server, _) = listener.accept().unwrap();
        send_reply(&mut server, Protocol::Socks5, REP_SUCCEEDED).unwrap();
        drop(server);
        assert_eq!(
            client.join().unwrap(),
            vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
    }
}
