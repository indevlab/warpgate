use warpgate_common::ProtocolName;

pub static RDP_PROTOCOL_NAME: ProtocolName = "RDP";

#[derive(thiserror::Error, Debug)]
pub enum RdpError {
    #[error("RDP protocol error: {0}")]
    Protocol(String),

    #[error("RDP authentication failed: {0}")]
    AuthFailed(String),

    #[error("RDP connection error: {0}")]
    Connection(String),

    #[error("RDP TLS error: {0}")]
    Tls(String),

    #[error(
        "RDP TOFU certificate mismatch for target {target}: expected {expected}, got {actual}"
    )]
    TofuMismatch {
        target: String,
        expected: String,
        actual: String,
    },

    #[error(transparent)]
    Warpgate(#[from] warpgate_common::WarpgateError),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
