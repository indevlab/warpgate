pub mod acceptor;
pub mod credssp;
pub mod session;
pub mod session_handle;

use anyhow::{Context, Result};
use futures::TryStreamExt;
use tracing::{error, info, Instrument};
use warpgate_common::ListenEndpoint;
use warpgate_core::Services;

pub async fn run_server(services: Services, address: ListenEndpoint) -> Result<()> {
    let mut listener = address.tcp_accept_stream().await?;

    info!(?address, "RDP server listening");

    while let Some(stream) = listener
        .try_next()
        .await
        .context("accepting RDP connection")?
    {
        let remote_address = match stream.peer_addr() {
            Ok(addr) => addr,
            Err(e) => {
                error!(error = ?e, "Failed to get RDP peer address");
                continue;
            }
        };

        let services = services.clone();

        tokio::spawn(
            async move {
                if let Err(error) = session::handle_session(services, stream, remote_address).await
                {
                    error!(?error, %remote_address, "RDP session error");
                }
            }
            .instrument(tracing::info_span!("RDP", %remote_address)),
        );
    }

    Ok(())
}
