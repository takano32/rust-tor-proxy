use std::{
    io::{self, Read, Write},
    net::TcpStream,
};

pub fn connect(proxy_addr: &str, host: &str, port: u16) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr)?;
    stream.write_all(&[5, 1, 0])?;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting)?;
    if greeting != [5, 0] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Tor SOCKS5 rejected no-authentication",
        ));
    }
    let host = host.as_bytes();
    if host.is_empty() || host.len() > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid destination hostname",
        ));
    }
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request)?;
    read_connect_reply(&mut stream)?;
    Ok(stream)
}

fn read_connect_reply(stream: &mut TcpStream) -> io::Result<()> {
    let mut reply = [0; 4];
    stream.read_exact(&mut reply)?;
    if reply[0] != 5 || reply[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("Tor SOCKS5 CONNECT failed with code {}", reply[1]),
        ));
    }
    let address_len = match reply[3] {
        1 => 4,
        3 => {
            let mut length = [0];
            stream.read_exact(&mut length)?;
            length[0] as usize
        }
        4 => 16,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SOCKS5 reply",
            ))
        }
    };
    let mut address_and_port = vec![0; address_len + 2];
    stream.read_exact(&mut address_and_port)
}
