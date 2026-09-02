use std::{
    io::{self, Read, Write},
    net::{Shutdown, TcpStream},
    thread,
};

/// Copy bytes both ways between a SOCKS5 client and a Tor stream until either
/// side reaches EOF.
pub fn bidirectional<R, W>(
    mut client: TcpStream,
    mut tor_read: R,
    mut tor_write: W,
) -> io::Result<()>
where
    R: Read,
    W: Write + Send + 'static,
{
    let mut client_read = client.try_clone()?;
    let client_to_tor = thread::spawn(move || {
        let result = io::copy(&mut client_read, &mut tor_write);
        let _ = tor_write.flush();
        result
    });
    let result = io::copy(&mut tor_read, &mut client);
    let _ = client.shutdown(Shutdown::Both);
    let _ = client_to_tor.join();
    result.map(|_| ())
}
