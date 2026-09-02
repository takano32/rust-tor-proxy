#[macro_use]
mod log;

mod config;
mod relay;

fn main() -> std::io::Result<()> {
    log::init();
    let config = config::Config::from_env()?;
    info!(
        "starting: socks5 port {}, state dir {}",
        config.listen_port,
        config.state_dir.display()
    );
    Ok(())
}
