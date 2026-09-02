//! Meeting an onion service: ESTABLISH_RENDEZVOUS, INTRODUCE1 and
//! RENDEZVOUS2 (rend-spec/rendezvous-protocol.md,
//! rend-spec/introduction-protocol.md).
//!
//! Neither side connects to the other. The client builds a circuit to a
//! rendezvous point of its own choosing and leaves a cookie there, then sends
//! the service -- through one of the introduction points its descriptor names
//! -- an encrypted message saying where that rendezvous point is. The service
//! builds its own circuit to the same place, the rendezvous point splices the
//! two together, and from then on the service is simply the far end of the
//! client's circuit.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::descriptor::{Descriptor, IntroPoint};
use super::mac;
use super::ntor::{HsNtorClient, IntroduceKeys, SERVER_HANDSHAKE_LEN};
use crate::ffi::aes::Aes256Ctr;
use crate::ffi::rand;
use crate::tor::circuit::{
    Circuit, RELAY_ESTABLISH_RENDEZVOUS, RELAY_INTRODUCE1, RELAY_INTRODUCE_ACK, RELAY_RENDEZVOUS2,
    RELAY_RENDEZVOUS_ESTABLISHED,
};
use crate::tor::client::TorClient;
use crate::tor::RelayInfo;
use crate::util::invalid_data;

/// AUTH_KEY_TYPE: an Ed25519 public key is the only value defined.
const AUTH_KEY_TYPE_ED25519: u8 = 0x02;
/// ONION_KEY_TYPE inside the encrypted plaintext.
const ONION_KEY_TYPE_NTOR: u8 = 0x01;

/// An introduction point refuses an INTRODUCE1 longer than this.
const MAX_INTRODUCE1_LEN: usize = 490;
/// What C Tor pads the encrypted plaintext to, so that the length of the
/// real contents does not show through.
const INTRODUCE_PLAINTEXT_LEN: usize = 246;

/// INTRODUCE_ACK status codes.
const INTRO_ACK_SUCCESS: u16 = 0;
const INTRO_ACK_NOT_RECOGNIZED: u16 = 1;

const ESTABLISH_TIMEOUT: Duration = Duration::from_secs(30);
const INTRODUCE_ACK_TIMEOUT: Duration = Duration::from_secs(30);
const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(60);
/// Budget for the whole dance, separate from the per-circuit timeouts.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(90);
/// How many of the service's introduction points to try.
const INTRO_ATTEMPTS: usize = 3;

/// Why reaching the service failed, and whether the caller can do anything
/// about it.
pub struct Failure {
    pub error: io::Error,
    /// Every introduction point we tried said it did not know the
    /// authentication key we named. That is not a network problem: the
    /// descriptor we are working from has been replaced.
    pub descriptor_is_stale: bool,
}

impl Failure {
    fn new(error: io::Error) -> Self {
        Self {
            error,
            descriptor_is_stale: false,
        }
    }
}

/// The rendezvous side: a circuit to a relay of our choosing, with a cookie
/// left there for the service to quote back.
struct Rendezvous {
    circuit: Circuit,
    point: RelayInfo,
    cookie: [u8; 20],
}

/// Build a circuit that ends at the onion service.
///
/// On success the returned circuit has four hops: guard, middle, rendezvous
/// point, and the service itself as a virtual hop.
pub fn establish(
    client: &Arc<TorClient>,
    descriptor: &Descriptor,
    subcredential: &[u8; 32],
) -> Result<Circuit, Failure> {
    let deadline = Instant::now() + TOTAL_TIMEOUT;

    // Nothing ties the two sides together until the INTRODUCE1 goes out, so
    // build them at the same time. Two three-hop circuits raised one after the
    // other is most of the wait on a cold `.onion`.
    let rendezvous_thread = {
        let client = Arc::clone(client);
        std::thread::Builder::new()
            .name("rendezvous".into())
            .spawn(move || open_rendezvous(&client))
    };

    let mut order: Vec<usize> = (0..descriptor.intro_points.len()).collect();
    rand::shuffle(&mut order).map_err(Failure::new)?;
    order.truncate(INTRO_ATTEMPTS);

    // Meanwhile, get a circuit to the first introduction point ready.
    let mut prepared = order.first().and_then(|&index| {
        match client.build_circuit_to(&descriptor.intro_points[index].relay) {
            Ok(circuit) => Some((index, circuit)),
            Err(e) => {
                crate::debug!("could not pre-build an introduction circuit: {e}");
                None
            }
        }
    });

    let rendezvous = match rendezvous_thread {
        Ok(handle) => handle
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("the rendezvous thread stopped"))),
        // Without a thread to run it on, do it here.
        Err(e) => {
            crate::debug!("could not start the rendezvous thread ({e}); doing it in line");
            open_rendezvous(client)
        }
    };
    let rendezvous = match rendezvous {
        Ok(rendezvous) => rendezvous,
        Err(e) => {
            if let Some((_, circuit)) = prepared {
                circuit.close();
            }
            return Err(Failure::new(e));
        }
    };

    match introduce_until_met(
        client,
        &rendezvous,
        descriptor,
        subcredential,
        &order,
        &mut prepared,
        deadline,
    ) {
        Ok(()) => Ok(rendezvous.circuit),
        Err(failure) => {
            rendezvous.circuit.close();
            if let Some((_, circuit)) = prepared {
                circuit.close();
            }
            Err(failure)
        }
    }
}

/// Build the rendezvous circuit and leave the cookie at its far end.
fn open_rendezvous(client: &Arc<TorClient>) -> io::Result<Rendezvous> {
    let point = client.choose_rendezvous_point()?;
    let circuit = client.build_circuit_to(&point)?;
    let cookie: [u8; 20] = match rand::bytes() {
        Ok(cookie) => cookie,
        Err(e) => {
            circuit.close();
            return Err(e);
        }
    };
    let established = (|| {
        circuit.send_control(RELAY_ESTABLISH_RENDEZVOUS, &cookie)?;
        circuit.wait_for_control(RELAY_RENDEZVOUS_ESTABLISHED, ESTABLISH_TIMEOUT)
    })();
    if let Err(e) = established {
        circuit.close();
        return Err(e);
    }
    crate::debug!(
        "rendezvous point {} established on circuit {}",
        point.addr,
        circuit.circ_id()
    );
    Ok(Rendezvous {
        circuit,
        point,
        cookie,
    })
}

/// Try the service's introduction points in turn until one of them puts us in
/// touch with it.
fn introduce_until_met(
    client: &Arc<TorClient>,
    rendezvous: &Rendezvous,
    descriptor: &Descriptor,
    subcredential: &[u8; 32],
    order: &[usize],
    prepared: &mut Option<(usize, Circuit)>,
    deadline: Instant,
) -> Result<(), Failure> {
    let mut last: Option<io::Error> = None;
    let mut all_unrecognized = true;
    let mut attempts = 0usize;

    for &index in order {
        if Instant::now() >= deadline {
            last = Some(io::Error::new(
                io::ErrorKind::TimedOut,
                "ran out of time reaching the onion service",
            ));
            break;
        }
        // The circuit built while the rendezvous point was being set up, if
        // this is the introduction point it was built for.
        let ready = match prepared {
            Some((prepared_index, _)) if *prepared_index == index => {
                prepared.take().map(|(_, circuit)| circuit)
            }
            _ => None,
        };
        let intro = &descriptor.intro_points[index];
        attempts += 1;
        match introduce(client, rendezvous, intro, subcredential, ready) {
            Ok(()) => return Ok(()),
            Err(e) => {
                crate::debug!("introduction point {}: {e}", intro.relay.addr);
                all_unrecognized &= is_unrecognized_key(&e);
                last = Some(e);
            }
        }
    }

    let error = last.unwrap_or_else(|| invalid_data("the descriptor named no introduction points"));
    Err(Failure {
        // Only a rejection tells us the descriptor is stale. Running out of
        // time before trying anything says nothing about it.
        descriptor_is_stale: attempts > 0 && all_unrecognized,
        error,
    })
}

/// One attempt through one introduction point: introduce ourselves, then wait
/// for the service to turn up at the rendezvous point.
fn introduce(
    client: &Arc<TorClient>,
    rendezvous: &Rendezvous,
    intro: &IntroPoint,
    subcredential: &[u8; 32],
    ready: Option<Circuit>,
) -> io::Result<()> {
    let handshake = HsNtorClient::new(&intro.auth_key, &intro.enc_key)?;
    let keys = handshake.introduce_keys(subcredential);
    let plaintext = introduce_plaintext(&rendezvous.cookie, &rendezvous.point);
    let message = assemble_introduce1(
        &intro.auth_key,
        &handshake.client_public(),
        &plaintext,
        &keys,
    )?;

    // The introduction circuit exists only to carry this one message, and is
    // closed as soon as it is acknowledged.
    let intro_circuit = match ready {
        Some(circuit) => circuit,
        None => client.build_circuit_to(&intro.relay)?,
    };
    let ack = (|| {
        intro_circuit.send_control(RELAY_INTRODUCE1, &message)?;
        intro_circuit.wait_for_control(RELAY_INTRODUCE_ACK, INTRODUCE_ACK_TIMEOUT)
    })();
    intro_circuit.close();
    check_introduce_ack(&ack?)?;

    let reply = rendezvous
        .circuit
        .wait_for_control(RELAY_RENDEZVOUS2, RENDEZVOUS_TIMEOUT)?;
    if reply.len() < SERVER_HANDSHAKE_LEN {
        return Err(invalid_data("RENDEZVOUS2 is too short to be a handshake"));
    }
    let circuit_keys = handshake.finish(&reply)?;
    rendezvous.circuit.add_virtual_hop(&circuit_keys);
    Ok(())
}

/// The plaintext the service decrypts: where to meet, and with which key.
fn introduce_plaintext(cookie: &[u8; 20], rendezvous_point: &RelayInfo) -> Vec<u8> {
    let mut out = Vec::with_capacity(INTRODUCE_PLAINTEXT_LEN);
    out.extend_from_slice(cookie);
    out.push(0); // no extensions
    out.push(ONION_KEY_TYPE_NTOR);
    out.extend_from_slice(&(rendezvous_point.ntor_onion_key.len() as u16).to_be_bytes());
    out.extend_from_slice(&rendezvous_point.ntor_onion_key);
    out.extend_from_slice(&rendezvous_point.link_specifiers());
    // Pad with zeros so that the length says nothing about the contents.
    if out.len() < INTRODUCE_PLAINTEXT_LEN {
        out.resize(INTRODUCE_PLAINTEXT_LEN, 0);
    }
    out
}

/// Wrap the plaintext in the INTRODUCE1 framing, encrypt it, and authenticate
/// the whole message up to the MAC field.
fn assemble_introduce1(
    auth_key: &[u8; 32],
    client_public: &[u8; 32],
    plaintext: &[u8],
    keys: &IntroduceKeys,
) -> io::Result<Vec<u8>> {
    let mut message = Vec::with_capacity(56 + 32 + plaintext.len() + 32);
    // LEGACY_KEY_ID is all zeros: this is not a v2 introduction.
    message.extend_from_slice(&[0u8; 20]);
    message.push(AUTH_KEY_TYPE_ED25519);
    message.extend_from_slice(&(auth_key.len() as u16).to_be_bytes());
    message.extend_from_slice(auth_key);
    message.push(0); // no extensions
    message.extend_from_slice(client_public);

    let mut encrypted = plaintext.to_vec();
    Aes256Ctr::new(&keys.enc_key).apply(&mut encrypted);
    message.extend_from_slice(&encrypted);

    // The MAC covers everything before it, the client's public key included.
    let tag = mac(&keys.mac_key, &message);
    message.extend_from_slice(&tag);

    if message.len() > MAX_INTRODUCE1_LEN {
        return Err(invalid_data("INTRODUCE1 message would be over-long"));
    }
    Ok(message)
}

fn check_introduce_ack(body: &[u8]) -> io::Result<()> {
    if body.len() < 2 {
        return Err(invalid_data("INTRODUCE_ACK is too short"));
    }
    match u16::from_be_bytes([body[0], body[1]]) {
        INTRO_ACK_SUCCESS => Ok(()),
        INTRO_ACK_NOT_RECOGNIZED => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "introduction point does not know that authentication key",
        )),
        status => Err(invalid_data(format!(
            "introduction point refused the request, status {status}"
        ))),
    }
}

/// Did this failure mean "the key you named is not one of mine"?
fn is_unrecognized_key(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::InvalidInput
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_decode;

    fn key(hex: &str) -> [u8; 32] {
        hex_decode(hex).unwrap().try_into().unwrap()
    }

    /// rend-spec appendix G.1 again, this time for the message itself: given
    /// the documented keys, plaintext and client key, the bytes on the wire
    /// must come out exactly as recorded.
    ///
    /// This pins the header layout, the encryption and the extent of the MAC
    /// all at once.
    #[test]
    fn rend_spec_introduce1_body() {
        let auth_key = key("34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F");
        let client_public = key("BF04348B46D09AED726F1D66C618FDEA1DE58E8CB8B89738D7356A0C59111D5D");
        let keys = IntroduceKeys {
            enc_key: key("9B8917BA3D05F3130DACCE5300C3DC27F6D012912F1C733036F822D0ED238706"),
            mac_key: key("FC4058DA59D4DF61E7B40985D122F502FD59336BC21C30CAF5E7F0D4A2C38FD5"),
        };
        let plaintext = hex_decode(concat!(
            "6BD364C12638DD5C3BE23D76ACA05B04E6CE932C0101000100200DE6130E4FCA",
            "C4EDDA24E21220CC3EADAE403EF6B7D11C8273AC71908DE565450300067F0000",
            "0113890214F823C4F8CC085C792E0AEE0283FE00AD7520B37D0320728D5DF39B",
            "7B7077A0118A900FF4456C382F0041300ACF9C58E51C392795EF870000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000000000000000000000000000000000000000",
        ))
        .unwrap();
        let expected = hex_decode(concat!(
            "000000000000000000000000000000000000000002002034E171E4358E501BFF",
            "21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F00BF04348B46D09AED",
            "726F1D66C618FDEA1DE58E8CB8B89738D7356A0C59111D5DADBECCCB38E37830",
            "4DCC179D3D9E437B452AF5702CED2CCFEC085BC02C4C175FA446525C1B9D5530",
            "563C362FDFFB802DAB8CD9EBC7A5EE17DA62E37DEEB0EB187FBB48C63298B0E8",
            "3F391B7566F42ADC97C46BA7588278273A44CE96BC68FFDAE31EF5F0913B9A9C",
            "7E0F173DBC0BDDCD4ACB4C4600980A7DDD9EAEC6E7F3FA3FC37CD95E5B8BFB3E",
            "35717012B78B4930569F895CB349A07538E42309C993223AEA77EF8AEA64F25D",
            "DEE97DA623F1AEC0A47F150002150455845C385E5606E41A9A199E7111D54EF2",
            "D1A51B7554D8B3692D85AC587FB9E69DF990EFB776D8",
        ))
        .unwrap();

        let message = assemble_introduce1(&auth_key, &client_public, &plaintext, &keys).unwrap();
        assert_eq!(message, expected);
        // The header is the first 56 bytes: 20 zero bytes, the key type, its
        // length, the key, and an empty extension list.
        assert_eq!(&message[..20], &[0u8; 20]);
        assert_eq!(message[20], AUTH_KEY_TYPE_ED25519);
        assert_eq!(u16::from_be_bytes([message[21], message[22]]), 32);
        assert_eq!(&message[23..55], &auth_key);
        assert_eq!(message[55], 0);
    }

    #[test]
    fn plaintext_is_padded_to_a_fixed_length() {
        let relay = RelayInfo {
            addr: "10.9.8.7:9001".parse().unwrap(),
            rsa_identity: [0xa1; 20],
            ed_identity: Some([0xb2; 32]),
            ntor_onion_key: [0xc3; 32],
        };
        let cookie = [0x5a; 20];
        let plaintext = introduce_plaintext(&cookie, &relay);
        assert_eq!(plaintext.len(), INTRODUCE_PLAINTEXT_LEN);
        assert_eq!(&plaintext[..20], &cookie);
        assert_eq!(plaintext[20], 0, "no extensions");
        assert_eq!(plaintext[21], ONION_KEY_TYPE_NTOR);
        assert_eq!(u16::from_be_bytes([plaintext[22], plaintext[23]]), 32);
        assert_eq!(&plaintext[24..56], &relay.ntor_onion_key);
        assert_eq!(&plaintext[56..56 + 65], &relay.link_specifiers()[..]);
        assert!(plaintext[121..].iter().all(|&b| b == 0), "padding is zeros");

        // The whole message has to fit in one relay cell, with room to spare.
        let keys = IntroduceKeys {
            enc_key: [1u8; 32],
            mac_key: [2u8; 32],
        };
        let message = assemble_introduce1(&[3u8; 32], &[4u8; 32], &plaintext, &keys).unwrap();
        assert_eq!(message.len(), 56 + 32 + INTRODUCE_PLAINTEXT_LEN + 32);
        assert!(message.len() <= MAX_INTRODUCE1_LEN);
        assert!(message.len() <= crate::tor::circuit::RELAY_DATA_MAX);

        // A plaintext that would overflow the limit is refused rather than
        // silently truncated.
        assert!(assemble_introduce1(&[3u8; 32], &[4u8; 32], &[0u8; 400], &keys).is_err());
    }

    #[test]
    fn introduce_ack_status_codes() {
        assert!(check_introduce_ack(&[0, 0, 0]).is_ok());
        let stale = check_introduce_ack(&[0, 1, 0]).unwrap_err();
        assert!(
            is_unrecognized_key(&stale),
            "status 1 means a stale descriptor"
        );
        let bad = check_introduce_ack(&[0, 2, 0]).unwrap_err();
        assert!(!is_unrecognized_key(&bad));
        assert!(check_introduce_ack(&[0]).is_err());
        assert!(check_introduce_ack(&[]).is_err());
    }
}
