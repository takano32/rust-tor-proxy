mod config;
mod http;
mod relay;
mod server;

#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    server::run(config::Config::from_env()?).await
}
