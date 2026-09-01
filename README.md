# sorahost-tor-proxy

Small HTTP/HTTPS forward proxy written in Rust. Outbound connections are made through a Tor SOCKS5 proxy, so DNS names are also sent to Tor for resolution.

## Run

Start Tor with a SOCKS listener (the usual default is `127.0.0.1:9050`), then:

```sh
SERVER_PORT=8080 cargo run --release
```

Set `TOR_SOCKS_ADDR` if Tor listens elsewhere:

```sh
SERVER_PORT=8080 TOR_SOCKS_ADDR=127.0.0.1:9150 cargo run --release
```

Use it with an HTTP proxy client, for example:

```sh
curl --proxy http://127.0.0.1:8080 https://check.torproject.org/
```

`SERVER_PORT` is required and must be an integer in the valid TCP-port range. The proxy supports HTTP absolute-form requests and HTTPS `CONNECT` tunnels.
