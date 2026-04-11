use anyhow::{Context, Result};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::info;
use warpgate_common::GlobalParams;

use crate::config::load_config;

pub async fn command(params: &GlobalParams) -> Result<()> {
    let config = load_config(params, true)?;

    // Check HTTP listener
    let url = format!(
        "https://{}/@warpgate/api/info",
        config.store.http.listen.address()
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .use_rustls_tls()
        .build()?;

    let response = timeout(std::time::Duration::from_secs(5), client.get(&url).send())
        .await
        .context("Timeout")?
        .context("Failed to send request")?;

    response.error_for_status()?;
    info!("HTTP listener is healthy");

    // Check RDP listener if enabled
    if config.store.rdp.enable {
        let rdp_addr = config.store.rdp.listen.address();
        timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(rdp_addr.to_string()),
        )
        .await
        .context("RDP listener health check timed out")?
        .context("RDP listener is not accepting connections")?;
        info!("RDP listener is healthy");
    }

    Ok(())
}
