use std::fmt::Debug;
use std::sync::Arc;

use data_encoding::HEXLOWER;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{info, warn};
use uuid::Uuid;
use warpgate_db_entities::RdpKnownHost;

/// TOFU (Trust On First Use) certificate store for RDP target connections.
///
/// Mirrors the SSH `KnownHosts` pattern but stores X.509 certificate
/// SHA-256 fingerprints instead of SSH public keys.
pub struct RdpKnownHosts {
    db: Arc<Mutex<DatabaseConnection>>,
    target_id: Uuid,
    host: String,
    port: u16,
}

impl Debug for RdpKnownHosts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RdpKnownHosts")
            .field("target_id", &self.target_id)
            .field("host", &self.host)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

/// Result of validating an RDP target certificate against the known-hosts store.
pub enum RdpKnownHostValidationResult {
    /// The certificate matches the stored fingerprint.
    Valid,
    /// A certificate is on record for this target+host+port but the fingerprint
    /// does not match (possible MITM or host key rotation).
    Invalid {
        expected_sha256: String,
        actual_sha256: String,
    },
    /// No certificate has ever been recorded for this target+host+port.
    Unknown,
}

impl RdpKnownHosts {
    pub fn new(
        db: Arc<Mutex<DatabaseConnection>>,
        target_id: Uuid,
        host: String,
        port: u16,
    ) -> Self {
        Self {
            db,
            target_id,
            host,
            port,
        }
    }

    /// Compute the lowercase hex SHA-256 fingerprint of a DER-encoded certificate.
    fn sha256_hex(cert_der: &[u8]) -> String {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, cert_der);
        HEXLOWER.encode(digest.as_ref())
    }

    /// Look up the certificate fingerprint for this target+host+port and compare
    /// it against the presented certificate.
    pub async fn validate(
        &self,
        cert_der: &[u8],
    ) -> Result<RdpKnownHostValidationResult, sea_orm::DbErr> {
        let actual_sha256 = Self::sha256_hex(cert_der);

        let db = self.db.lock().await;
        let entries = RdpKnownHost::Entity::find()
            .filter(RdpKnownHost::Column::TargetId.eq(self.target_id))
            .filter(RdpKnownHost::Column::Host.eq(&self.host))
            .filter(RdpKnownHost::Column::Port.eq(self.port as i32))
            .all(&*db)
            .await?;

        if entries
            .iter()
            .any(|e| e.certificate_sha256 == actual_sha256)
        {
            return Ok(RdpKnownHostValidationResult::Valid);
        }

        if let Some(first) = entries.first() {
            return Ok(RdpKnownHostValidationResult::Invalid {
                expected_sha256: first.certificate_sha256.clone(),
                actual_sha256,
            });
        }

        Ok(RdpKnownHostValidationResult::Unknown)
    }

    /// Store the certificate as trusted for this target+host+port.
    pub async fn trust(&self, cert_der: &[u8]) -> Result<(), sea_orm::DbErr> {
        use sea_orm::ActiveValue::Set;

        let sha256 = Self::sha256_hex(cert_der);
        let der_base64 = data_encoding::BASE64.encode(cert_der);
        let now = OffsetDateTime::now_utc();

        let values = RdpKnownHost::ActiveModel {
            id: Set(Uuid::new_v4()),
            target_id: Set(self.target_id),
            host: Set(self.host.clone()),
            port: Set(self.port as i32),
            certificate_sha256: Set(sha256),
            certificate_der_base64: Set(der_base64),
            created: Set(now),
            updated: Set(now),
        };

        let db = self.db.lock().await;
        values.insert(&*db).await?;

        Ok(())
    }
}

/// A `rustls` `ServerCertVerifier` that implements TOFU semantics for RDP
/// target connections.
///
/// On first contact (`Unknown`), the certificate is automatically trusted.
/// On subsequent connections, the certificate must match the stored fingerprint.
#[derive(Debug)]
pub struct RdpKnownHostVerifier {
    known_hosts: Arc<tokio::sync::Mutex<RdpKnownHosts>>,
    runtime_handle: tokio::runtime::Handle,
}

impl RdpKnownHostVerifier {
    pub fn new(
        known_hosts: Arc<tokio::sync::Mutex<RdpKnownHosts>>,
        runtime_handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            known_hosts,
            runtime_handle,
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for RdpKnownHostVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let cert_der = end_entity.as_ref();

        let known_hosts = self.known_hosts.clone();
        let cert_der_owned = cert_der.to_vec();

        let result = self.runtime_handle.block_on(async {
            let kh = known_hosts.lock().await;
            kh.validate(&cert_der_owned).await
        });

        match result {
            Ok(RdpKnownHostValidationResult::Valid) => {
                info!("RDP target certificate is trusted (TOFU)");
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            Ok(RdpKnownHostValidationResult::Unknown) => {
                info!("RDP target certificate unknown — auto-trusting (TOFU)");
                let trust_result = self.runtime_handle.block_on(async {
                    let kh = known_hosts.lock().await;
                    kh.trust(&cert_der_owned).await
                });
                if let Err(e) = trust_result {
                    warn!("Failed to store RDP target certificate: {e}");
                    return Err(rustls::Error::General(format!(
                        "Failed to store trusted RDP certificate: {e}"
                    )));
                }
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            Ok(RdpKnownHostValidationResult::Invalid {
                expected_sha256,
                actual_sha256,
            }) => {
                warn!(
                    %expected_sha256,
                    %actual_sha256,
                    "RDP target certificate mismatch — possible MITM attack"
                );
                Err(rustls::Error::General(format!(
                    "RDP target certificate mismatch (TOFU): expected SHA-256 {expected_sha256}, got {actual_sha256}"
                )))
            }
            Err(e) => Err(rustls::Error::General(format!(
                "Database error during RDP certificate validation: {e}"
            ))),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
