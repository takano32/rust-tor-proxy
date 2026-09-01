mod config;
mod http;
mod relay;
mod server;
mod socks5;

fn main() -> std::io::Result<()> {
    server::run(config::Config::from_env()?)
}
