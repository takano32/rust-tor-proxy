# rust-tor-proxy

A dependency-free Tor client with a SOCKS5, SOCKS4a and HTTP CONNECT
listener, written in Rust.

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
cargo run --release
```

| Variable | Meaning |
|---|---|
| `SERVER_PORT` | TCP port to listen on. Default 9050, the port Tor clients look for. |
| `TOR_STATE_DIR` | Directory cache and remembered guards. Default `./state`. |
| `TOR_LOG` | `error`, `warn`, `info` (default), `debug`, `trace`. |

The first start fetches and verifies a consensus, so it takes a few seconds;
afterwards the cache in `TOR_STATE_DIR` makes startup nearly instant, and the
consensus is kept up to date in the background for as long as the process
runs.

One port serves three protocols, told apart by the first byte a client sends,
so most things that can use a proxy at all can use this one unconfigured:

```sh
# SOCKS5, always with remote DNS so host names are resolved by the exit
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
ALL_PROXY=socks5h://127.0.0.1:9050 curl https://check.torproject.org/api/ip

# SOCKS4a — what proxychains sends with its stock configuration
curl --socks4a 127.0.0.1:9050 https://check.torproject.org/api/ip

# HTTP CONNECT
https_proxy=http://127.0.0.1:9050 curl https://check.torproject.org/api/ip
```

All four print `{"IsTor":true, ...}`.

`http_proxy` is deliberately not served: a proxied plain-HTTP request would
travel in clear through the exit, so anything but CONNECT gets a 501 saying to
use CONNECT or `socks5h://` instead. A SOCKS5 client that offers only
username/password authentication is accepted and its credentials discarded —
there are no users here, and refusing would only turn those clients away.

Version 3 `.onion` addresses work through the same listener:

```sh
curl --socks5-hostname 127.0.0.1:9050 \
    http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/
```

The first `.onion` request of a session is slower than later ones — it needs a
microdescriptor for every directory relay in the consensus before it can work
out which of them hold the service's descriptor. Onion addresses appear in the
log only at `TOR_LOG=debug`, so that an ordinary log does not record which
services were visited.

## Measured

On aarch64 with Rust 1.96 and OpenSSL 3.6.4, against the live Tor network.
Speeds vary by an easy factor of two with the relays a circuit happens to
draw, so these are medians of five runs unless stated.

| Measurement | Result |
|---|---|
| `cargo build --release -j1` under `MemoryMax=200M` | passes, 26s |
| Release binary | 1.4MB |
| `VmHWM` after bootstrap and a 2MB download | **17.3MB** |
| `VmHWM` after also visiting an onion service | **31.4MB** |
| `VmHWM` for a session that used all three protocols and an onion service | 35.2MB |
| Threads | 5 idle (main, maintenance, circuit builder, guard channel I/O, circuit pump), plus one per SOCKS connection |
| `TOR_STATE_DIR` after bootstrap | 4.1MB (3.6MB of it the consensus) |
| `TOR_STATE_DIR` after one onion request | 25MB, and it stays there: microdescriptors the consensus no longer names are pruned |

Latency:

| Measurement | Result |
|---|---|
| Cold start to "listening" | **7–9s** |
| Warm start (cached consensus) | 1.4s |
| First request, to the first byte of the response | **0.95s** |
| First request, to the tunnelled TLS being up | 0.49s |
| First `.onion` request of a cold session | **12–15s** |
| Second request to the same service | 0.4–0.6s |

Throughput:

| Measurement | Result |
|---|---|
| One stream, 10MB | 689KB/s |
| One stream, 30MB | 668–1449KB/s over eight runs on two circuits |
| One stream, 100MB | 1054KB/s |
| Four streams at once, 2MB each | **1514KB/s** together, against 340KB/s for one |

The four-stream figure is the one to trust: the four transfers ran at the same
moment over the same guard, so the fourfold gain is the striping across
circuits and not the network being kind.

Single-stream numbers are **not** a fair test of the flow control. Throughput
on one stream is decided mostly by which relays the circuit drew, and a
circuit cannot be run twice under two different schemes. Comparing runs of two builds gave 689KB/s for congestion
control against 381KB/s for fixed windows, but the two sets of runs used
different circuits, so that difference is not evidence about the scheme.

What can be said per circuit is this: fixed-window flow control can never
carry more than 1000 cells per round trip, and the proxy logs each circuit's
round trip when it is built, so the ceiling is known for the circuit actually
carrying a transfer. Eight 30MB transfers over two circuits of 316ms and 334ms
round trip — ceilings of 1576 and 1488KB/s — achieved between 577 and
1449KB/s, every one of them under its own ceiling. On circuits like these the
fixed window was never the constraint, so congestion control has no throughput
to win, and it is implemented because the network is moving to it (the
consensus already lists `FlowCtrl=1-2` under `required-relay-protocols`) and
because it does win on circuits whose round trip times their bandwidth to more
than 1000 cells.

Reproduce the build and footprint figures with:

```sh
systemd-run --user --scope -q -p MemoryMax=200M -p MemorySwapMax=0 \
    cargo build --release -j1

./target/release/rust-tor-proxy &
grep -E 'VmRSS|VmHWM' /proc/$!/status
```

## Tests

```sh
cargo test                 # 198 unit tests, no network
cargo test -- --ignored    # 8 live tests against the real Tor network
```

The unit tests pin the cryptography to published vectors wherever there are
any: RFC 4231, 7748, 8032 and NIST SP 800-38A for the primitives, C Tor's
`ed25519_vectors.inc` for key blinding, rend-spec appendix G.1 for the hs-ntor
handshake and the INTRODUCE1 message, and proposal 332's worked example for
ntor-v3. Where no vectors exist — ntor, ntor-v3, hs-ntor, congestion control —
the tests write the other side of the protocol and run it against ours.

The live tests do a link handshake with a fallback relay, build a one-hop
CREATE_FAST circuit and fetch over BEGIN_DIR, bootstrap a signature-verified
consensus, ask a directory cache for a consensus diff, carry HTTP over a
three-hop circuit, compute the directory nodes responsible for a known onion
service, fetch and decrypt its descriptor, and fetch a page from it over a
rendezvous circuit.

## Limitations

Anonymity is weaker than the real Tor client. Specifically:

- Concurrent streams are spread across up to four circuits, because each
  circuit has its own flow-control window and striping is what makes parallel
  transfers add up. The price is that four exits see this client's traffic at
  once rather than one.
- Up to three guards are remembered in priority order, and the first is
  returned to as soon as it answers again; but there is no rotation schedule,
  no sampled guard set, and no `MiddleOnly`-aware retry logic.
- Directory documents are fetched over one-hop circuits — to a fallback mirror
  during a first bootstrap, and to a guard afterwards. This is how C Tor
  bootstraps, but it does mean that relay learns a client is fetching
  directory data.
- Circuits are reused for 10 minutes from their first stream and are keyed
  only by destination port, so requests to different sites can share an exit.
- The first `.onion` request fetches a microdescriptor for every HSDir in the
  consensus. A directory relay watching that fetch learns nothing about which
  service is wanted, but it does learn that this client is about to visit one.

Streams are opened optimistically: the SOCKS reply goes out as soon as the
BEGIN has been sent, without waiting for the exit to confirm, which takes a
round trip off every connection. A refusal therefore arrives after the client
has been told the connection succeeded, and shows up as the connection closing
rather than as a SOCKS error code. Refusals that are the exit's fault
(EXITPOLICY, RESOLVEFAILED, NOROUTE, TIMEOUT) are retried on another circuit
with the bytes written so far replayed, up to 16kB, so most of them are
invisible; the reason for the rest is logged at `info`.

Onion services are supported as a **client**, for version 3 addresses only.
Not supported: running a service, restricted discovery (client authorisation),
and version 2 addresses — which are long retired, and are refused by name.

Not implemented at all: bridges and pluggable transports, `RESOLVE` cells,
IPv6 destinations, link padding (link protocol v5 is deliberately not
offered), proof-of-work for onion services, conflux, and vanguards.

`TASKS.md` has the full implementation plan and the measurements that motivated
dropping `arti`.
