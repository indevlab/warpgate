use std::path::PathBuf;

use anyhow::{Context, Result};
use rcgen::generate_simple_self_signed;
use tracing::info;
use warpgate_common::helpers::fs::{secure_directory, secure_file};
use warpgate_common::{GlobalParams, WarpgateConfig};

/// Resolve the certificate and key paths from config, relative to the config directory.
fn get_rdp_tls_paths(config: &WarpgateConfig, params: &GlobalParams) -> (PathBuf, PathBuf) {
    let base = params.paths_relative_to();
    (
        base.join(&config.store.rdp.certificate),
        base.join(&config.store.rdp.key),
    )
}

/// Generate a self-signed TLS certificate for the RDP listener if one does not
/// already exist on disk. Mirrors the HTTP certificate generation in `setup.rs`.
pub fn generate_certificate_if_needed(
    config: &WarpgateConfig,
    params: &GlobalParams,
) -> Result<()> {
    let (cert_path, key_path) = get_rdp_tls_paths(config, params);

    if cert_path.exists() && key_path.exists() {
        return Ok(());
    }

    // Ensure the parent directory exists
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent).context("creating directory for RDP TLS certificate")?;
        if params.should_secure_files() {
            secure_directory(parent)?;
        }
    }

    info!("Generating RDP TLS certificate");
    let cert =
        generate_simple_self_signed(vec!["warpgate.local".to_string(), "localhost".to_string()])
            .context("generating self-signed RDP certificate")?;

    std::fs::write(&cert_path, cert.cert.pem()).context("writing RDP certificate")?;
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).context("writing RDP private key")?;

    if params.should_secure_files() {
        secure_file(&cert_path)?;
        secure_file(&key_path)?;
    }

    info!(?cert_path, ?key_path, "RDP TLS certificate generated");
    Ok(())
}

/// Load the RDP listener TLS certificate and private key from disk.
pub async fn load_certificate_and_key(
    config: &WarpgateConfig,
    params: &GlobalParams,
) -> Result<warpgate_tls::TlsCertificateAndPrivateKey> {
    let (cert_path, key_path) = get_rdp_tls_paths(config, params);

    let certificate = warpgate_tls::TlsCertificateBundle::from_file(&cert_path)
        .await
        .with_context(|| format!("loading RDP certificate from {}", cert_path.display()))?;

    let private_key = warpgate_tls::TlsPrivateKey::from_file(&key_path)
        .await
        .with_context(|| format!("loading RDP private key from {}", key_path.display()))?;

    Ok(warpgate_tls::TlsCertificateAndPrivateKey {
        certificate,
        private_key,
    })
}
