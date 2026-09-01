use std::{
    io::{self, BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    thread,
};

use crate::{config::Config, http, relay, socks5};

const MAX_HEADER_BYTES: usize = 32 * 1024;

pub fn run(config: Config) -> io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", config.listen_port))?;
    eprintln!(
        "Tor HTTP proxy listening on 0.0.0.0:{}; SOCKS5 upstream: {}",
        config.listen_port, config.tor_socks_addr
    );
    for connection in listener.incoming() {
        match connection {
            Ok(client) => {
                let tor_socks_addr = config.tor_socks_addr.clone();
                thread::spawn(move || log_connection_error(handle_client(client, &tor_socks_addr)));
            }
            Err(error) => eprintln!("accept failed: {error}"),
        }
    }
    Ok(())
}

fn log_connection_error(result: io::Result<()>) {
    if let Err(error) = result {
        eprintln!("connection failed: {error}");
    }
}

fn handle_client(mut client: TcpStream, tor_socks_addr: &str) -> io::Result<()> {
    let mut reader = BufReader::new(client.try_clone()?);
    let header = read_header(&mut reader)?;
    let request = http::request_line(&header)?;
    let (host, port) = http::destination(request, &header)?;
    let mut upstream = socks5::connect(tor_socks_addr, &host, port)?;
    if request.method.eq_ignore_ascii_case("CONNECT") {
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    } else {
        upstream.write_all(&http::rewrite_absolute_target(&header, request.target)?)?;
    }
    if !reader.buffer().is_empty() {
        upstream.write_all(reader.buffer())?;
    }
    relay::bidirectional(client, upstream)
}

fn read_header(reader: &mut BufReader<TcpStream>) -> io::Result<Vec<u8>> {
    let mut header = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client closed before headers",
            ));
        }
        let remaining = MAX_HEADER_BYTES.saturating_sub(header.len());
        if remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request headers too large",
            ));
        }
        let take = available.len().min(remaining);
        let end = available[..take]
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .map(|index| index + 4);
        let consumed = end.unwrap_or(take);
        header.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);
        if end.is_some() {
            return Ok(header);
        }
    }
}
