use arti_client::DataStream;
use async_std::{io, net::TcpStream, task};
use futures_util::io::{AsyncReadExt, AsyncWriteExt};

pub async fn bidirectional(client: TcpStream, upstream: DataStream) -> io::Result<()> {
    let (mut client_read, mut client_write) = client.split();
    let (mut tor_read, mut tor_write) = upstream.split();
    let client_to_tor = task::spawn(async move {
        let result = io::copy(&mut client_read, &mut tor_write).await;
        let _ = tor_write.close().await;
        result
    });
    let result = io::copy(&mut tor_read, &mut client_write).await;
    let _ = client_write.close().await;
    client_to_tor.await?;
    result.map(|_| ())
}
