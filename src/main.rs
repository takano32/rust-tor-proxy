//! A dependency-free Tor client with a SOCKS5 front end.

#[macro_use]
mod log;

mod config;
mod crypto;
mod ffi;
mod relay;
mod socks5;
mod status;
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
    status::mark_start();
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
    // rather than after a minute of directory work, and accept at once, so
    // that the status page can say what the bootstrap is doing. Proxy
    // requests that arrive meanwhile wait for it.
    let listener = TcpListener::bind(("0.0.0.0", config.listen_port))?;
    let front = Arc::new(socks5::Front::new(config.listen_port));
    info!(
        "listening on 0.0.0.0:{} (status page at /status); bootstrapping the \
         Tor client (state in {})",
        config.listen_port,
        config.state_dir.display()
    );

    let ready = Arc::clone(&front);
    let state_dir = config.state_dir;
    let listen_port = config.listen_port;
    std::thread::Builder::new()
        .name("bootstrap".into())
        .spawn(move || match tor::client::TorClient::bootstrap(state_dir) {
            Ok(client) => {
                info!("ready: {}", client.consensus_summary());
                info!("serving SOCKS5, SOCKS4a and HTTP CONNECT on 0.0.0.0:{listen_port}");
                ready.set_ready(client);
            }
            Err(e) => {
                // Nothing can be served without a client, and a supervisor
                // restarting the process is the best retry there is.
                error!("bootstrap failed: {e}");
                std::process::exit(1);
            }
        })?;

    for incoming in listener.incoming() {
        match incoming {
            Ok(socket) => {
                let front = Arc::clone(&front);
                if let Err(e) = std::thread::Builder::new()
                    .name("socks5".into())
                    .spawn(move || socks5::handle(socket, &front))
                {
                    warn!("could not spawn a connection thread: {e}");
                }
            }
            Err(e) => warn!("accept failed: {e}"),
        }
    }
    Ok(())
}
