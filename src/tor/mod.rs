pub mod cell;
pub mod certs;
pub mod channel;
pub mod circuit;
pub mod client;
pub mod dir;
pub mod hs;
pub mod maintain;
pub mod ntor;
pub mod ntor_v3;
pub mod path;
pub mod pool;

use std::net::SocketAddrV4;

/// Everything needed to open a channel to a relay and run ntor with it.
#[derive(Clone)]
pub struct RelayInfo {
    pub addr: SocketAddrV4,
    /// SHA-1 of the DER RSA identity key: the ntor NODEID.
    pub rsa_identity: [u8; 20],
    /// KP_relayid_ed, when the directory told us about it.
    pub ed_identity: Option<[u8; 32]>,
    /// KP_onion_ntor, the relay's curve25519 onion key.
    pub ntor_onion_key: [u8; 32],
}

impl RelayInfo {
    /// The relay as a link specifier list: `NSPEC | {LSTYPE LSLEN LSPEC}*`,
    /// in the order tor-spec asks for (IPv4, legacy identity, Ed25519
    /// identity). EXTEND2 carries one of these, and so does the plaintext of
    /// an INTRODUCE1 message.
    pub fn link_specifiers(&self) -> Vec<u8> {
        let mut specs: Vec<(u8, Vec<u8>)> = Vec::with_capacity(3);
        let mut ipv4 = Vec::with_capacity(6);
        ipv4.extend_from_slice(&self.addr.ip().octets());
        ipv4.extend_from_slice(&self.addr.port().to_be_bytes());
        specs.push((0x00, ipv4));
        specs.push((0x02, self.rsa_identity.to_vec()));
        if let Some(ed) = self.ed_identity {
            specs.push((0x03, ed.to_vec()));
        }

        let mut out = Vec::with_capacity(1 + 8 + 22 + 34);
        out.push(specs.len() as u8);
        for (kind, value) in specs {
            out.push(kind);
            out.push(value.len() as u8);
            out.extend_from_slice(&value);
        }
        out
    }
}
