use std::{error::Error, io};

use arti_client::{TorClient, TorClientConfig};
use async_std::{
    io::{prelude::*, BufReader},
    net::{TcpListener, TcpStream},
    task,
};
use futures_util::io::AsyncBufReadExt;

use crate::{config::Config, http, relay};

const MAX_HEADER_BYTES: usize = 32 * 1024;

pub async fn run(config: Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    eprintln!("Bootstrapping the embedded Tor client...");
    let tor_client = TorClient::create_bootstrapped(TorClientConfig::default()).await?;
    let listener = TcpListener::bind(("0.0.0.0", config.listen_port)).await?;
    eprintln!("Tor HTTP proxy listening on 0.0.0.0:{}", config.listen_port);

    loop {
        let (client, _) = listener.accept().await?;
        let tor_client = tor_client.clone();
        task::spawn(async move {
            if let Err(error) = handle_client(client, tor_client).await {
                eprintln!("connection failed: {error}");
            }
        });
    }
}

async fn handle_client(
    client: TcpStream,
    tor_client: std::sync::Arc<TorClient<tor_rtcompat::PreferredRuntime>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut reader = BufReader::new(client);
    let header = read_header(&mut reader).await?;
    let request = http::request_line(&header)?;
    let (host, port) = http::destination(request, &header)?;
    let mut upstream = tor_client
        .isolated_client()
        .connect((host.as_str(), port))
        .await?;
    let client = reader.get_mut();
    if request.method.eq_ignore_ascii_case("CONNECT") {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    } else {
        upstream
            .write_all(&http::rewrite_absolute_target(&header, request.target)?)
            .await?;
    }
    if !reader.buffer().is_empty() {
        upstream.write_all(reader.buffer()).await?;
    }
    upstream.flush().await?;
    relay::bidirectional(reader.into_inner(), upstream).await?;
    Ok(())
}

async fn read_header(reader: &mut BufReader<TcpStream>) -> io::Result<Vec<u8>> {
    let mut header = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
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
        reader.consume_unpin(consumed);
        if end.is_some() {
            return Ok(header);
        }
    }
}
