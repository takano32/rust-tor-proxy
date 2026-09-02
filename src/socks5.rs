//! A SOCKS5 server (RFC 1928), with no authentication.
//!
//! Host names are passed to the exit relay untouched: resolving them locally
//! would leak the destination to the local resolver, which is why clients
//! should always use `--socks5-hostname` / `socks5h://`.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use crate::relay;
use crate::tor::circuit::{self, StreamEnd};
use crate::tor::client::TorClient;
use crate::util::invalid_data;

const VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NONE_ACCEPTABLE: u8 = 0xff;

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

/// What the client asked for.
struct Request {
    host: String,
    port: u16,
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
    let request = match negotiate(&mut client) {
        Ok(request) => request,
        Err(e) => {
            crate::debug!("{peer}: SOCKS handshake failed: {e}");
            return;
        }
    };
    crate::info!("{peer} -> {}:{}", request.host, request.port);

    let stream = match tor.connect(&request.host, request.port) {
        Ok(stream) => stream,
        Err(e) => {
            crate::warn!("{peer}: {}:{} failed: {e}", request.host, request.port);
            let _ = send_reply(&mut client, reply_code(&e));
            return;
        }
    };
    if let Err(e) = send_reply(&mut client, REP_SUCCEEDED) {
        crate::debug!("{peer}: could not send the SOCKS reply: {e}");
        stream.close();
        return;
    }
    // The handshake timeout must not apply to the tunnelled connection.
    let _ = client.set_read_timeout(None);

    let reader = stream.try_clone();
    if let Err(e) = relay::bidirectional(client, reader, stream.try_clone()) {
        crate::debug!("{peer}: relay ended: {e}");
    }
    stream.close();
}

/// Run the greeting and the CONNECT request.
fn negotiate(client: &mut TcpStream) -> io::Result<Request> {
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting)?;
    if greeting[0] != VERSION {
        return Err(invalid_data(format!(
            "unsupported SOCKS version {}",
            greeting[0]
        )));
    }
    let mut methods = vec![0u8; greeting[1] as usize];
    client.read_exact(&mut methods)?;
    if !methods.contains(&METHOD_NO_AUTH) {
        client.write_all(&[VERSION, METHOD_NONE_ACCEPTABLE])?;
        return Err(invalid_data("client offered no acceptable auth method"));
    }
    client.write_all(&[VERSION, METHOD_NO_AUTH])?;

    let mut header = [0u8; 4];
    client.read_exact(&mut header)?;
    if header[0] != VERSION {
        return Err(invalid_data("bad SOCKS version in request"));
    }
    if header[1] != CMD_CONNECT {
        send_reply(client, REP_COMMAND_NOT_SUPPORTED)?;
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
            send_reply(client, REP_ADDRESS_TYPE_NOT_SUPPORTED)?;
            return Err(invalid_data("IPv6 destinations are not supported"));
        }
        other => {
            send_reply(client, REP_ADDRESS_TYPE_NOT_SUPPORTED)?;
            return Err(invalid_data(format!("unknown address type {other}")));
        }
    };

    let mut port = [0u8; 2];
    client.read_exact(&mut port)?;
    let port = u16::from_be_bytes(port);
    if port == 0 || host.is_empty() {
        send_reply(client, REP_GENERAL_FAILURE)?;
        return Err(invalid_data("empty host or port"));
    }
    Ok(Request { host, port })
}

/// Replies always name 0.0.0.0:0 as the bound address: the client does not
/// need it, and the exit's real address is not ours to hand out.
fn send_reply(client: &mut TcpStream, code: u8) -> io::Result<()> {
    let reply = [VERSION, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    client.write_all(&reply)
}

/// Map a failure to open the Tor stream onto a SOCKS reply code.
fn reply_code(error: &io::Error) -> u8 {
    if let Some(end) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<StreamEnd>())
    {
        return match end.0 {
            circuit::END_REASON_EXITPOLICY => REP_NOT_ALLOWED,
            circuit::END_REASON_RESOLVEFAILED | circuit::END_REASON_NOROUTE => {
                REP_HOST_UNREACHABLE
            }
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
        let mut request = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, ATYP_IPV4, 93, 184, 216, 34];
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
        let request = vec![0x05, 0x01, 0x00, 0x05, 0x02, 0x00, ATYP_IPV4, 1, 2, 3, 4, 0, 80];
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

    #[test]
    fn refuses_socks4() {
        let request = vec![0x04, 0x01, 0x00, 0x50];
        let (parsed, _) = negotiate_with(&request);
        assert!(parsed.is_err());
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
        send_reply(&mut server, REP_SUCCEEDED).unwrap();
        drop(server);
        assert_eq!(
            client.join().unwrap(),
            vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
    }
}
