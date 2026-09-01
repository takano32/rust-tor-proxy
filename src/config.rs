use std::{env, io};

pub struct Config {
    pub listen_port: u16,
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
        Ok(Self { listen_port })
    }
}
