# rust-tor-proxy

A dependency-free Tor client with a SOCKS5 listener, written in Rust.

`[dependencies]` is empty. The Tor protocol — link handshake, ntor, circuits,
relay cells, flow control, directory fetching and signature verification — is
implemented in this repository, and every cryptographic primitive comes from
the system OpenSSL 3 through hand-written FFI (`src/ffi/`). The point is to fit
`cargo build --release`, and the running proxy, into a 128–240MB machine, where
building `arti` is not possible at all.

## Requirements

- Linux, Rust stable (verified with 1.96)
- OpenSSL **3.x** shared libraries: `libssl.so.3` and `libcrypto.so.3`.
  **No headers and no `-dev`/`-devel` package are needed**, at build time or at
  run time. Check with:
  ```sh
  ldconfig -p | grep -E 'libssl|libcrypto'   # or: find / -name 'libssl.so*' 2>/dev/null
  ```
  The 1.1 series is not supported: `SSL_get1_peer_certificate` and
  `EVP_PKEY_CTX_set_rsa_padding` are a 3.0 name and a 3.0 function. If only 1.1
  is present the program says so by name at start-up.

OpenSSL is loaded with `dlopen` when the process starts, not linked at build
time, so the binary records no `DT_NEEDED` entry for it and the file name and
directory may both vary. If it lives somewhere the dynamic loader does not
look:

| Variable | Meaning |
|---|---|
| `TOR_OPENSSL_DIR` | Directory holding the libraries, whatever they are named. |
| `TOR_LIBSSL` / `TOR_LIBCRYPTO` | Exact paths, when even the names differ. |

A setting that cannot be loaded produces a warning and the normal search
continues, so a stale value from another machine is not fatal.

## Run

```sh
SERVER_PORT=9050 cargo run --release
```

| Variable | Meaning |
|---|---|
| `SERVER_PORT` | Required. TCP port for the SOCKS5 listener. |
| `TOR_STATE_DIR` | Directory cache and pinned guard. Default `./state`. |
| `TOR_LOG` | `error`, `warn`, `info` (default), `debug`, `trace`. |

The first start fetches and verifies a consensus, so it takes a few seconds;
afterwards the cache in `TOR_STATE_DIR` makes startup nearly instant.

Use it as a SOCKS5 proxy — always with **remote DNS**, so that host names are
resolved by the exit relay and never locally:

```sh
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
ALL_PROXY=socks5h://127.0.0.1:9050 curl https://check.torproject.org/api/ip
```

Both print `{"IsTor":true, ...}`.

Version 3 `.onion` addresses work through the same listener:

```sh
curl --socks5-hostname 127.0.0.1:9050 \
    http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/
```

The first `.onion` request of a session is slow — it needs a microdescriptor
for every directory relay in the consensus before it can work out which of them
hold the service's descriptor — and later ones are not. Onion addresses appear
in the log only at `TOR_LOG=debug`, so that an ordinary log does not record
which services were visited.

## Measured footprint

On aarch64 with Rust 1.96 and OpenSSL 3.6.4:

| Measurement | Result |
|---|---|
| `cargo build --release -j1` under `MemoryMax=200M` | passes |
| Release binary | ~1.0MB |
| Proxy `VmHWM` after bootstrap and a 2MB download | **18.9MB** |
| Proxy `VmHWM` after also visiting an onion service | **26.5MB** |
| Threads | 4 idle (main, guard channel I/O, circuit pump, plus one per SOCKS connection) |
| Cold bootstrap to "SOCKS5 listening" | 13–27s |
| Throughput, 2MB range request | 410KB/s |
| `TOR_STATE_DIR` after bootstrap | ~4MB (3.6MB of it the consensus) |
| `TOR_STATE_DIR` after one onion request | ~25MB (a microdescriptor per HSDir) |

Onion services, against `2gzyxa5…wid.onion`:

| Measurement | Result |
|---|---|
| HSDir hash ring, first build (2858 relays, 31 directory requests) | 38s |
| HSDir hash ring, rebuilt from the disk cache | 0.6s |
| First `.onion` request of a cold session | 51s, 38s of it the ring |
| First `.onion` request with a warm cache | 13s |
| Second request to the same service (rendezvous circuit reused) | 1.2s |
| A port the service does not serve | 0.5s, and the circuit is kept |

Reproduce the build and runtime figures with:

```sh
systemd-run --user --scope -q -p MemoryMax=200M -p MemorySwapMax=0 \
    cargo build --release -j1

SERVER_PORT=9050 ./target/release/rust-tor-proxy &
grep -E 'VmRSS|VmHWM' /proc/$!/status
```

## Tests

```sh
cargo test                 # 129 unit tests, no network
cargo test -- --ignored    # 7 live tests against the real Tor network
```

The unit tests pin the cryptography to published vectors wherever there are
any: RFC 4231, 7748, 8032 and NIST SP 800-38A for the primitives, C Tor's
`ed25519_vectors.inc` for key blinding, and rend-spec appendix G.1 for the
hs-ntor handshake and the INTRODUCE1 message.

The live tests do a link handshake with a fallback relay, build a one-hop
CREATE_FAST circuit and fetch over BEGIN_DIR, bootstrap a signature-verified
consensus, carry HTTP over a three-hop circuit, compute the directory nodes
responsible for a known onion service, fetch and decrypt its descriptor, and
fetch a page from it over a rendezvous circuit.

## Limitations

Anonymity is weaker than the real Tor client. Specifically:

- Path selection ignores the consensus `bandwidth-weights`, so guard and exit
  capacity is drawn from the same bandwidth distribution rather than the
  position-specific one.
- One guard is pinned and used until it stops working; there is no guard set,
  no rotation schedule, and no `MiddleOnly`-aware retry logic.
- Directory documents are fetched over one-hop circuits — to a fallback mirror
  during bootstrap, and to the guard afterwards. This is how C Tor bootstraps,
  but it does mean that relay learns a client is fetching directory data.
- Circuits are reused for 10 minutes and are keyed only by destination port, so
  requests to different sites can share an exit.
- The first `.onion` request fetches a microdescriptor for every HSDir in the
  consensus. A directory relay watching that fetch learns nothing about which
  service is wanted, but it does learn that this client is about to visit one.

Onion services are supported as a **client**, for version 3 addresses only.
Not supported: running a service, restricted discovery (client authorisation),
and version 2 addresses — which are long retired, and are refused by name.

Not implemented at all: bridges and pluggable transports, `RESOLVE` cells, IPv6
destinations, ntor-v3, congestion control, link padding (link protocol v5 is
deliberately not offered), proof-of-work for onion services, and consensus
diffs or compression.

`TASKS.md` has the full implementation plan and the measurements that motivated
dropping `arti`.
