//! The two pieces of cryptography that are not OpenSSL's: base32 for `.onion`
//! addresses, and just enough Ed25519 point arithmetic to blind a public key.

pub mod base32;
pub mod ed25519_point;
