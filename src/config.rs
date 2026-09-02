use std::{env, io, path::PathBuf};

/// The port Tor clients expect a SOCKS proxy on, and what this binds to when
/// `SERVER_PORT` says nothing.
const DEFAULT_PORT: u16 = 9050;

pub struct Config {
    /// TCP port the proxy listens on, from `SERVER_PORT`.
    pub listen_port: u16,
    /// Directory for the consensus / microdescriptor / guard cache.
    pub state_dir: PathBuf,
}

impl Config {
    pub fn from_env() -> io::Result<Self> {
        // Unset means the port every Tor client already looks for, so that
        // the program needs no configuration at all to be useful.
        let listen_port = match env::var("SERVER_PORT") {
            Err(_) => DEFAULT_PORT,
            Ok(value) => value.parse::<u16>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SERVER_PORT must be a port number",
                )
            })?,
        };
        if listen_port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SERVER_PORT must be between 1 and 65535",
            ));
        }
        let state_dir = env::var_os("TOR_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("state"));
        Ok(Self {
            listen_port,
            state_dir,
        })
    }
}
