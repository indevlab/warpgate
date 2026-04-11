use warpgate_common::WarpgateError;

#[derive(thiserror::Error, Debug)]
pub enum ConnectError {
    #[error("RDP target connection failed: {0}")]
    Network(#[from] std::io::Error),

    #[error("RDP target authentication rejected: {0}")]
    AuthRejected(String),

    #[error("RDP target TLS failure: {0}")]
    TlsFailure(String),

    #[error("RDP target TOFU certificate mismatch: expected {expected}, got {actual}")]
    TofuMismatch { expected: String, actual: String },

    #[error("RDP connector error: {0}")]
    Connector(String),
}

impl From<ConnectError> for WarpgateError {
    fn from(e: ConnectError) -> Self {
        WarpgateError::Other(Box::new(e))
    }
}
