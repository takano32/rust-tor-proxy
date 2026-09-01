use std::{env, io};

pub const DEFAULT_TOR_SOCKS_ADDR: &str = "127.0.0.1:9050";

pub struct Config {
    pub listen_port: u16,
    pub tor_socks_addr: String,
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
        Ok(Self {
            listen_port,
            tor_socks_addr: env::var("TOR_SOCKS_ADDR")
                .unwrap_or_else(|_| DEFAULT_TOR_SOCKS_ADDR.into()),
        })
    }
}
