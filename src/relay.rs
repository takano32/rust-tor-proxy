use std::{
    io,
    net::{Shutdown, TcpStream},
    thread,
};

pub fn bidirectional(mut client: TcpStream, mut upstream: TcpStream) -> io::Result<()> {
    let mut client_read = client.try_clone()?;
    let mut upstream_write = upstream.try_clone()?;
    let client_to_upstream = thread::spawn(move || {
        let result = io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
        result
    });
    let result = io::copy(&mut upstream, &mut client);
    let _ = client.shutdown(Shutdown::Write);
    let _ = client_to_upstream.join();
    result.map(|_| ())
}
