use std::{env, io, path::PathBuf};

pub struct Config {
    /// TCP port the SOCKS5 listener binds to. Required, from `SERVER_PORT`.
    pub listen_port: u16,
    /// Directory for the consensus / microdescriptor / guard cache.
    pub state_dir: PathBuf,
}

impl Config {
    pub fn from_env() -> io::Result<Self> {
        let listen_port = env::var("SERVER_PORT")
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "SERVER_PORT is required"))?
            .parse::<u16>()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SERVER_PORT must be a port number",
                )
            })?;
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
