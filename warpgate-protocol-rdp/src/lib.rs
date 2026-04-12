mod client;
mod common;
pub mod keys;
pub use keys::generate_certificate_if_needed;
mod known_hosts;
mod recorder_tap;
mod server;

use std::fmt::Debug;

use anyhow::Result;
pub use common::*;
pub use known_hosts::*;
pub use server::session_handle::RDPSessionHandle;
use warpgate_common::{ListenEndpoint, ProtocolName};
use warpgate_core::{ProtocolServer, Services};

pub static PROTOCOL_NAME: ProtocolName = "RDP";

#[derive(Clone)]
pub struct RDPProtocolServer {
    services: Services,
}

impl RDPProtocolServer {
    pub fn new(services: &Services) -> Self {
        Self {
            services: services.clone(),
        }
    }
}

impl ProtocolServer for RDPProtocolServer {
    async fn run(self, address: ListenEndpoint) -> Result<()> {
        server::run_server(self.services, address).await
    }

    fn name(&self) -> &'static str {
        "RDP"
    }
}

impl Debug for RDPProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RDPProtocolServer").finish()
    }
}
