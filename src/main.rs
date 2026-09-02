//! A dependency-free Tor client with a SOCKS5 front end.

#[macro_use]
mod log;

mod config;
mod ffi;
mod relay;
mod socks5;
mod tor;
mod util;

use std::net::TcpListener;
use std::sync::Arc;

fn main() -> std::io::Result<()> {
    log::init();
    let config = config::Config::from_env()?;

    // Bind before bootstrapping, so a port conflict is reported immediately
    // rather than after a minute of directory work.
    let listener = TcpListener::bind(("0.0.0.0", config.listen_port))?;
    info!("bootstrapping the Tor client (state in {})", config.state_dir.display());

    let client = Arc::new(tor::client::TorClient::bootstrap(config.state_dir)?);
    info!("ready: {}", client.consensus_summary());
    info!("SOCKS5 listening on 0.0.0.0:{}", config.listen_port);

    for incoming in listener.incoming() {
        match incoming {
            Ok(socket) => {
                let client = Arc::clone(&client);
                if let Err(e) = std::thread::Builder::new()
                    .name("socks5".into())
                    .spawn(move || socks5::handle(socket, &client))
                {
                    warn!("could not spawn a connection thread: {e}");
                }
            }
            Err(e) => warn!("accept failed: {e}"),
        }
    }
    Ok(())
}
