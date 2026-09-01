use std::io;

#[derive(Clone, Copy)]
pub struct Request<'a> {
    pub method: &'a str,
    pub target: &'a str,
}

pub fn request_line(header: &[u8]) -> io::Result<Request<'_>> {
    let text = std::str::from_utf8(header)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request is not valid UTF-8"))?;
    let line = text
        .split("\r\n")
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request line"))?;
    let mut fields = line.split_whitespace();
    let method = fields
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP method"))?;
    let target = fields
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request target"))?;
    if fields.next().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing HTTP version",
        ));
    }
    Ok(Request { method, target })
}

pub fn destination(request: Request<'_>, header: &[u8]) -> io::Result<(String, u16)> {
    if request.method.eq_ignore_ascii_case("CONNECT") {
        return split_host_port(request.target, 443);
    }
    if let Some(authority) = request.target.strip_prefix("http://") {
        return split_host_port(authority.split('/').next().unwrap_or(authority), 80);
    }
    if let Some(authority) = request.target.strip_prefix("https://") {
        return split_host_port(authority.split('/').next().unwrap_or(authority), 443);
    }
    let text = std::str::from_utf8(header)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid headers"))?;
    let host = text
        .split("\r\n")
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("host").then_some(value.trim())
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing Host header"))?;
    split_host_port(host, 80)
}

pub fn rewrite_absolute_target(header: &[u8], target: &str) -> io::Result<Vec<u8>> {
    if !target.starts_with("http://") && !target.starts_with("https://") {
        return Ok(header.to_vec());
    }
    let text = std::str::from_utf8(header)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid request"))?;
    let (first, rest) = text
        .split_once("\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid request line"))?;
    let mut fields = first.split_whitespace();
    let method = fields.next().unwrap_or_default();
    let absolute = fields.next().unwrap_or_default();
    let version = fields.next().unwrap_or_default();
    let path = absolute
        .find("://")
        .and_then(|start| {
            absolute[start + 3..]
                .find('/')
                .map(|pos| &absolute[start + 3 + pos..])
        })
        .unwrap_or("/");
    Ok(format!("{method} {path} {version}\r\n{rest}").into_bytes())
}

fn split_host_port(value: &str, default_port: u16) -> io::Result<(String, u16)> {
    let value = value.trim();
    if value.is_empty() || value.contains(['/', ' ', '\\']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid destination",
        ));
    }
    if let Some(bracketed) = value.strip_prefix('[') {
        let end = bracketed
            .find(']')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid IPv6 address"))?;
        let suffix = &bracketed[end + 1..];
        let port = suffix
            .strip_prefix(':')
            .map(str::parse)
            .transpose()
            .map_err(invalid_port)?
            .unwrap_or(default_port);
        return Ok((bracketed[..end].to_owned(), port));
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            Ok((host.to_owned(), port.parse().map_err(invalid_port)?))
        }
        _ => Ok((value.to_owned(), default_port)),
    }
}

fn invalid_port(_: std::num::ParseIntError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid port")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finds_http_destination_and_rewrites_target() {
        let header = b"GET http://example.com:8080/a HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        let request = request_line(header).unwrap();
        assert_eq!(
            destination(request, header).unwrap(),
            ("example.com".into(), 8080)
        );
        assert_eq!(
            rewrite_absolute_target(header, request.target).unwrap(),
            b"GET /a HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"
        );
    }
}
