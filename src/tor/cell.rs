//! Cell framing (tor-spec/cell-packet-format.md).
//!
//! A fixed-length cell is `CircID | Command | Body[509]`; a variable-length
//! cell is `CircID | Command | Length | Body`. VERSIONS (7) and every command
//! from 128 up are variable-length. The width of CircID depends on the link
//! protocol: 2 bytes while VERSIONS is being exchanged, 4 bytes from link
//! version 4 on.

use std::io::{self, Read};

use crate::util::invalid_data;

pub const CELL_BODY_LEN: usize = 509;

/// CircID width before any version has been negotiated.
pub const CIRC_ID_LEN_V2: usize = 2;
/// CircID width for link protocol 4 and later.
pub const CIRC_ID_LEN_V4: usize = 4;

pub const CMD_PADDING: u8 = 0;
pub const CMD_RELAY: u8 = 3;
pub const CMD_DESTROY: u8 = 4;
pub const CMD_VERSIONS: u8 = 7;
pub const CMD_NETINFO: u8 = 8;
pub const CMD_RELAY_EARLY: u8 = 9;
pub const CMD_CREATE2: u8 = 10;
pub const CMD_CREATED2: u8 = 11;
pub const CMD_VPADDING: u8 = 128;
pub const CMD_CERTS: u8 = 129;
pub const CMD_AUTH_CHALLENGE: u8 = 130;

pub fn is_variable_length(command: u8) -> bool {
    command == CMD_VERSIONS || command >= 128
}

pub fn command_name(command: u8) -> &'static str {
    match command {
        CMD_PADDING => "PADDING",
        1 => "CREATE",
        2 => "CREATED",
        CMD_RELAY => "RELAY",
        CMD_DESTROY => "DESTROY",
        5 => "CREATE_FAST",
        6 => "CREATED_FAST",
        CMD_VERSIONS => "VERSIONS",
        CMD_NETINFO => "NETINFO",
        CMD_RELAY_EARLY => "RELAY_EARLY",
        CMD_CREATE2 => "CREATE2",
        CMD_CREATED2 => "CREATED2",
        12 => "PADDING_NEGOTIATE",
        CMD_VPADDING => "VPADDING",
        CMD_CERTS => "CERTS",
        CMD_AUTH_CHALLENGE => "AUTH_CHALLENGE",
        131 => "AUTHENTICATE",
        _ => "UNKNOWN",
    }
}

#[derive(Clone)]
pub struct Cell {
    pub circ_id: u32,
    pub command: u8,
    /// Exactly [`CELL_BODY_LEN`] bytes for a fixed-length cell; the declared
    /// length for a variable-length one.
    pub body: Vec<u8>,
}

impl Cell {
    pub fn new(circ_id: u32, command: u8, mut body: Vec<u8>) -> io::Result<Self> {
        if is_variable_length(command) {
            if body.len() > u16::MAX as usize {
                return Err(invalid_data("variable-length cell body too long"));
            }
        } else {
            if body.len() > CELL_BODY_LEN {
                return Err(invalid_data("fixed-length cell body too long"));
            }
            body.resize(CELL_BODY_LEN, 0);
        }
        Ok(Self {
            circ_id,
            command,
            body,
        })
    }

    pub fn encode(&self, circ_id_len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(circ_id_len + 3 + self.body.len());
        match circ_id_len {
            CIRC_ID_LEN_V2 => out.extend_from_slice(&(self.circ_id as u16).to_be_bytes()),
            _ => out.extend_from_slice(&self.circ_id.to_be_bytes()),
        }
        out.push(self.command);
        if is_variable_length(self.command) {
            out.extend_from_slice(&(self.body.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(&self.body);
        out
    }

    /// Parse one cell from the front of `buf`.
    ///
    /// Returns `Ok(None)` when more bytes are needed; the caller keeps the
    /// buffer and tries again after reading more.
    pub fn try_parse(buf: &[u8], circ_id_len: usize) -> io::Result<Option<(Cell, usize)>> {
        let header = circ_id_len + 1;
        if buf.len() < header {
            return Ok(None);
        }
        let circ_id = match circ_id_len {
            CIRC_ID_LEN_V2 => u16::from_be_bytes([buf[0], buf[1]]) as u32,
            CIRC_ID_LEN_V4 => u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            other => return Err(invalid_data(format!("bad CircID width {other}"))),
        };
        let command = buf[circ_id_len];

        let (body_start, body_len) = if is_variable_length(command) {
            if buf.len() < header + 2 {
                return Ok(None);
            }
            let len = u16::from_be_bytes([buf[header], buf[header + 1]]) as usize;
            (header + 2, len)
        } else {
            (header, CELL_BODY_LEN)
        };
        let total = body_start + body_len;
        if buf.len() < total {
            return Ok(None);
        }
        Ok(Some((
            Cell {
                circ_id,
                command,
                body: buf[body_start..total].to_vec(),
            },
            total,
        )))
    }

    /// Blocking read of exactly one cell, used during the link handshake
    /// before the non-blocking I/O loop takes over.
    pub fn read_from<R: Read>(reader: &mut R, circ_id_len: usize) -> io::Result<Cell> {
        let mut header = vec![0u8; circ_id_len + 1];
        reader.read_exact(&mut header)?;
        let mut buf = header;
        if is_variable_length(buf[circ_id_len]) {
            let mut len_bytes = [0u8; 2];
            reader.read_exact(&mut len_bytes)?;
            let len = u16::from_be_bytes(len_bytes) as usize;
            buf.extend_from_slice(&len_bytes);
            let start = buf.len();
            buf.resize(start + len, 0);
            reader.read_exact(&mut buf[start..])?;
        } else {
            let start = buf.len();
            buf.resize(start + CELL_BODY_LEN, 0);
            reader.read_exact(&mut buf[start..])?;
        }
        match Cell::try_parse(&buf, circ_id_len)? {
            Some((cell, _)) => Ok(cell),
            None => Err(invalid_data("short cell")),
        }
    }
}

/// Read a big-endian u16 at `offset`, or fail.
pub fn be_u16(buf: &[u8], offset: usize) -> io::Result<u16> {
    if offset + 2 > buf.len() {
        return Err(invalid_data("truncated u16"));
    }
    Ok(u16::from_be_bytes([buf[offset], buf[offset + 1]]))
}

/// Read a big-endian u32 at `offset`, or fail.
pub fn be_u32(buf: &[u8], offset: usize) -> io::Result<u32> {
    if offset + 4 > buf.len() {
        return Err(invalid_data("truncated u32"));
    }
    Ok(u32::from_be_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_length_round_trip() {
        let cell = Cell::new(0x8000_0001, CMD_RELAY, vec![1, 2, 3]).unwrap();
        assert_eq!(cell.body.len(), CELL_BODY_LEN);
        let bytes = cell.encode(CIRC_ID_LEN_V4);
        assert_eq!(bytes.len(), 4 + 1 + CELL_BODY_LEN);
        let (parsed, used) = Cell::try_parse(&bytes, CIRC_ID_LEN_V4).unwrap().unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(parsed.circ_id, 0x8000_0001);
        assert_eq!(parsed.command, CMD_RELAY);
        assert_eq!(&parsed.body[..3], &[1, 2, 3]);
    }

    #[test]
    fn versions_uses_two_byte_circ_id() {
        let cell = Cell::new(0, CMD_VERSIONS, vec![0, 3, 0, 4]).unwrap();
        let bytes = cell.encode(CIRC_ID_LEN_V2);
        assert_eq!(bytes, vec![0, 0, 7, 0, 4, 0, 3, 0, 4]);
        let (parsed, used) = Cell::try_parse(&bytes, CIRC_ID_LEN_V2).unwrap().unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(parsed.body, vec![0, 3, 0, 4]);
    }

    #[test]
    fn partial_input_asks_for_more() {
        let bytes = Cell::new(7, CMD_CERTS, vec![9; 40])
            .unwrap()
            .encode(CIRC_ID_LEN_V4);
        for cut in 0..bytes.len() {
            assert!(Cell::try_parse(&bytes[..cut], CIRC_ID_LEN_V4)
                .unwrap()
                .is_none());
        }
        assert!(Cell::try_parse(&bytes, CIRC_ID_LEN_V4).unwrap().is_some());
    }

    #[test]
    fn oversized_bodies_are_rejected() {
        assert!(Cell::new(1, CMD_RELAY, vec![0; CELL_BODY_LEN + 1]).is_err());
        assert!(Cell::new(0, CMD_VERSIONS, vec![0; 70000]).is_err());
    }
}
