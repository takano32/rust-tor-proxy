//! A dependency-free Tor client with a SOCKS5 front end.

#[macro_use]
mod log;

mod config;
mod crypto;
mod ffi;
mod relay;
mod socks5;
mod tor;
mod util;

use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::Arc;

fn main() -> ExitCode {
    log::init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Returning io::Error from main would print its Debug form, which
            // buries the message in Custom { kind: Other, error: "..." }.
            error!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> std::io::Result<()> {
    // Before any thread exists, so that every thread started later shares the
    // arenas this allows.
    ffi::malloc::limit_arenas();

    let config = config::Config::from_env()?;

    // OpenSSL is resolved at run time, so surface a missing library here
    // rather than from whichever thread happens to need crypto first.
    ffi::ensure_loaded()?;
    if let Some((ssl, crypto)) = ffi::library_paths() {
        debug!("OpenSSL loaded from {ssl} and {crypto}");
    }
    // Compression is optional: without libz the directory is fetched
    // uncompressed, which works but costs several megabytes at start-up.
    match ffi::zlib::version() {
        Some(version) => debug!("zlib {version} loaded; directory documents will be compressed"),
        None => warn!("no libz found; directory documents will be fetched uncompressed"),
    }

    // Bind before bootstrapping, so a port conflict is reported immediately
    // rather than after a minute of directory work.
    let listener = TcpListener::bind(("0.0.0.0", config.listen_port))?;
    info!(
        "bootstrapping the Tor client (state in {})",
        config.state_dir.display()
    );

    let client = Arc::new(tor::client::TorClient::bootstrap(config.state_dir)?);
    info!("ready: {}", client.consensus_summary());
    info!(
        "listening on 0.0.0.0:{} for SOCKS5, SOCKS4a and HTTP CONNECT",
        config.listen_port
    );

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
