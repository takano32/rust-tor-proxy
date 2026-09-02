# sorahost-tor-proxy

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
  Headers are not needed. Check with:
  ```sh
  ldconfig -p | grep -E 'libssl|libcrypto'
  ```
  The 1.1 series is not supported: `SSL_get1_peer_certificate` and
  `EVP_PKEY_CTX_set_rsa_padding` are a 3.0 name and a 3.0 function.

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

## Measured footprint

On aarch64 with Rust 1.96 and OpenSSL 3.6.4:

| Measurement | Result |
|---|---|
| `cargo build --release -j1` under `MemoryMax=200M` | passes |
| Release binary | ~1.0MB |
| Proxy `VmHWM` after bootstrap and a 2MB download | **18.9MB** |
| Threads | 4 idle (main, guard channel I/O, circuit pump, plus one per SOCKS connection) |
| Cold bootstrap to "SOCKS5 listening" | 13s |
| Throughput, 2MB range request | 410KB/s |
| `TOR_STATE_DIR` after bootstrap | ~4MB (3.6MB of it the consensus) |

Reproduce the build and runtime figures with:

```sh
systemd-run --user --scope -q -p MemoryMax=200M -p MemorySwapMax=0 \
    cargo build --release -j1

SERVER_PORT=9050 ./target/release/sorahost-tor-proxy &
grep -E 'VmRSS|VmHWM' /proc/$!/status
```

## Tests

```sh
cargo test                 # 66 unit tests, no network
cargo test -- --ignored    # 4 live tests against the real Tor network
```

The live tests do a link handshake with a fallback relay, build a one-hop
CREATE_FAST circuit and fetch over BEGIN_DIR, bootstrap a signature-verified
consensus, and carry HTTP over a three-hop circuit.

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

Not implemented at all: onion services, bridges and pluggable transports,
`RESOLVE` cells, IPv6 destinations, ntor-v3, congestion control, link padding
(link protocol v5 is deliberately not offered), and consensus diffs or
compression.

`TASKS.md` has the full implementation plan and the measurements that motivated
dropping `arti`.
