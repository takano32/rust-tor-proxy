# sorahost-tor-proxy

A dependency-free Tor client with a SOCKS5 listener, written in Rust.

There are no crates in `[dependencies]`: the Tor protocol (link handshake, ntor,
circuits, relay cells, directory fetching and validation) is implemented in this
repository, and all cryptography comes from the system OpenSSL 3 through
hand-written FFI. The point is to fit `cargo build --release` — and the running
proxy — into a 128–240MB machine, where building `arti` is not possible.

## Requirements

- Linux, Rust stable (verified with 1.96)
- OpenSSL 3 shared libraries: `libssl.so.3` and `libcrypto.so.3`
  (headers are not needed). Check with:
  ```sh
  ldconfig -p | grep -E 'libssl|libcrypto'
  ```

## Run

```sh
SERVER_PORT=9050 cargo run --release
```

`SERVER_PORT` is required and must be a valid TCP port. Directory data is cached
under `TOR_STATE_DIR` (default `./state`), so the first start is the slow one.
`TOR_LOG` selects the log level (`error`, `warn`, `info`, `debug`, `trace`).

Use it as a SOCKS5 proxy — always with remote DNS, so that host names are
resolved by the exit relay and not locally:

```sh
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
ALL_PROXY=socks5h://127.0.0.1:9050 curl https://check.torproject.org/api/ip
```

## Limitations

- Anonymity is weaker than the real Tor client: path selection and guard
  handling are simplified (see `TASKS.md`).
- No onion services, no bridges or pluggable transports, no `RESOLVE` cells,
  no IPv6-only exits.
- OpenSSL 3.x only; the 1.1 series is not supported.
