# sorahost-tor-proxy

Small HTTP/HTTPS forward proxy written in Rust. It embeds the Arti Tor client and routes outbound connections through the Tor network; no separate `tor` daemon or SOCKS listener is required.

## Run

```sh
SERVER_PORT=8080 cargo run --release
```

On first launch, Arti downloads Tor directory information and creates its persistent state automatically. Startup may therefore take a little longer.

Use it with an HTTP proxy client, for example:

```sh
curl --proxy http://127.0.0.1:8080 https://check.torproject.org/
```

`SERVER_PORT` is required and must be an integer in the valid TCP-port range. The proxy supports HTTP absolute-form requests and HTTPS `CONNECT` tunnels.
