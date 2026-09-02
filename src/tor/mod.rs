pub mod cell;
pub mod certs;
pub mod channel;
pub mod circuit;
pub mod dir;
pub mod ntor;

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
