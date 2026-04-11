pub mod error;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use ironrdp_connector::{
    ClientConnector, ConnectionResult, Credentials as ConnectorCredentials, DesktopSize,
};
use ironrdp_pdu::gcc::KeyboardType;
use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp_pdu::rdp::client_info::PerformanceFlags;
use ironrdp_tokio::TokioFramed;
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, info};
use warpgate_common::TargetRDPOptions;

use self::error::ConnectError;

/// Result of a successful outbound RDP connection.
pub struct ConnectedTarget {
    /// The framed stream ready for active-stage PDU exchange.
    pub framed: TokioFramed<tokio_rustls::client::TlsStream<TcpStream>>,
    /// Session result including channel IDs, capabilities, and desktop size.
    pub result: ConnectionResult,
}

/// Build the `ironrdp-connector` Config from target options.
fn build_connector_config(
    opts: &TargetRDPOptions,
    desktop_size: DesktopSize,
) -> ironrdp_connector::Config {
    ironrdp_connector::Config {
        credentials: ConnectorCredentials::UsernamePassword {
            username: opts.username.clone(),
            password: opts.password.expose_secret().to_string(),
        },
        domain: opts.domain.clone(),
        enable_tls: true,
        enable_credssp: true,
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: 0x0409, // US English
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size,
        desktop_scale_factor: 0,
        bitmap: None,
        client_build: 2600,
        client_name: "Warpgate".to_string(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_string(),
        platform: MajorPlatformType::WINDOWS,
        enable_server_pointer: false,
        autologon: false,
        pointer_software_rendering: false,
        performance_flags: PerformanceFlags::empty(),
        hardware_id: None,
        request_data: None,
        enable_audio_playback: false,
        license_cache: None,
        timezone_info: Default::default(),
    }
}

/// Connect to a remote RDP target using `ironrdp-connector`.
///
/// Performs the full outbound connection sequence:
/// 1. TCP connect
/// 2. X.224 negotiation
/// 3. TLS upgrade
/// 4. CredSSP with target credentials (if negotiated)
/// 5. MCS + capability exchange + finalization
///
/// The `cert_verifier` is required — callers must provide an
/// `RdpKnownHostVerifier` (TOFU) for certificate validation.
pub async fn connect_to_target(
    opts: &TargetRDPOptions,
    desktop_size: DesktopSize,
    cert_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
) -> Result<ConnectedTarget, ConnectError> {
    let target_addr = format!("{}:{}", opts.host, opts.port);
    info!(%target_addr, "Connecting to RDP target");

    let tcp_stream = TcpStream::connect(&target_addr)
        .await
        .map_err(ConnectError::Network)?;

    let local_addr = tcp_stream
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));

    let config = build_connector_config(opts, desktop_size);
    let mut connector = ClientConnector::new(config, local_addr);

    // Phase 1: X.224 negotiation up to security upgrade
    let mut framed: TokioFramed<TcpStream> = TokioFramed::new(tcp_stream);

    let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector)
        .await
        .map_err(|e| ConnectError::Connector(format!("connect_begin failed: {e}")))?;

    // Phase 2: TLS upgrade
    debug!("RDP client: performing TLS upgrade to target");

    let tls_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(cert_verifier)
        .with_no_client_auth();

    let host = opts.host.clone();
    let server_name = rustls::pki_types::ServerName::try_from(host).unwrap_or_else(|_| {
        rustls::pki_types::ServerName::IpAddress(
            opts.host
                .parse()
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
                .into(),
        )
    });

    let tls_connector = TlsConnector::from(Arc::new(tls_config));
    let inner_tcp = framed.into_inner_no_leftover();
    let tls_stream = tls_connector
        .connect(server_name.clone(), inner_tcp)
        .await
        .map_err(|e| ConnectError::TlsFailure(format!("TLS handshake with target failed: {e}")))?;

    let mut tls_framed: TokioFramed<tokio_rustls::client::TlsStream<TcpStream>> =
        TokioFramed::new(tls_stream);

    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);

    // Phase 3: CredSSP + MCS + capability exchange + finalization
    // `connect_finalize` handles CredSSP internally if negotiated.
    // Extract the server's certificate DER from the TLS session for CredSSP binding.
    let server_public_key = {
        let (tls_stream, _buf) = tls_framed.get_inner();
        let (_, conn) = tls_stream.get_ref();
        conn.peer_certificates()
            .and_then(|certs: &[rustls::pki_types::CertificateDer<'_>]| certs.first())
            .map(|cert| cert.as_ref().to_vec())
            .unwrap_or_default()
    };
    let result = ironrdp_tokio::connect_finalize(
        upgraded,
        &mut tls_framed,
        connector,
        ironrdp_connector::ServerName::new(server_name.to_str().as_ref()),
        server_public_key,
        None, // no async network client for Kerberos
        None, // no Kerberos config
    )
    .await
    .map_err(|e| ConnectError::Connector(format!("connect_finalize failed: {e}")))?;

    info!("RDP client: connected to target");

    Ok(ConnectedTarget {
        framed: tls_framed,
        result,
    })
}
