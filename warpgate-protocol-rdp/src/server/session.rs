use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use ironrdp_connector::DesktopSize;
use rustls::ServerConfig;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use warpgate_common::auth::{
    AuthCredential, AuthResult, AuthState, AuthStateUserInfo, CredentialKind,
};
use warpgate_common::{Secret, TargetOptions};
use warpgate_core::recordings::{RdpRecorder, RdpRecordingTarget};
use warpgate_core::{ConfigProvider, Services, SessionStateInit, State as WarpgateState};
use warpgate_tls::SingleCertResolver;

use super::session_handle::RDPSessionHandle;
use crate::common::RDP_PROTOCOL_NAME;
use crate::known_hosts::{RdpKnownHostVerifier, RdpKnownHosts};
use crate::server::acceptor::accept_rdp;

pub async fn handle_session(
    services: Services,
    client_stream: TcpStream,
    remote_address: SocketAddr,
) -> Result<()> {
    let (session_handle, mut close_rx) = RDPSessionHandle::new();

    let server_handle = WarpgateState::register_session(
        &services.state,
        &RDP_PROTOCOL_NAME,
        SessionStateInit {
            remote_address: Some(remote_address),
            handle: Box::new(session_handle),
        },
    )
    .await
    .context("registering RDP session")?;

    let session_id = server_handle.lock().await.id();

    info!(%session_id, %remote_address, "New RDP session");

    let result = tokio::select! {
        result = run_session(services.clone(), client_stream, remote_address, server_handle.clone()) => result,
        _ = close_rx.recv() => {
            info!(%session_id, "RDP session closed by config reload");
            Ok(())
        }
    };

    // Bounded session cleanup: ensure session state is finalized within 5 seconds
    // even if the session ended abruptly (client disconnect, network error, etc.)
    let cleanup_timeout = Duration::from_secs(5);
    let cleanup_result = tokio::time::timeout(cleanup_timeout, async {
        // Session removal is handled by WarpgateServerHandle::Drop
        // when server_handle goes out of scope — dropping it here ensures
        // the session is marked as ended in the admin UI promptly.
        drop(server_handle);
    })
    .await;

    if cleanup_result.is_err() {
        warn!(%session_id, "RDP session cleanup timed out after 5 seconds");
    }

    if let Err(ref e) = result {
        warn!(%session_id, error = ?e, "RDP session ended with error");
    } else {
        info!(%session_id, "RDP session ended");
    }

    result
}

/// Metadata stored alongside an RDP recording in the database.
#[derive(Serialize, Deserialize, Debug)]
struct RdpRecordingMetadata {
    target_name: String,
    target_host: String,
}

/// Build a `rustls::ServerConfig` for the inbound RDP TLS listener.
fn build_rdp_server_tls_config(
    cert_key: warpgate_tls::TlsCertificateAndPrivateKey,
) -> Result<Arc<ServerConfig>> {
    let config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(SingleCertResolver::new(cert_key)));
    Ok(Arc::new(config))
}

async fn run_session(
    services: Services,
    client_stream: TcpStream,
    _remote_address: SocketAddr,
    server_handle: Arc<Mutex<warpgate_core::WarpgateServerHandle>>,
) -> Result<()> {
    // Phase 1: Read the X.224 Connection Request to extract the routing cookie.
    //
    // The RDP client sends "Cookie: mstshash=username#target\r\n" in the initial
    // X.224 Connection Request PDU. We peek at this (without consuming bytes) to
    // determine which Warpgate user and target the session is for. The acceptor
    // will then read the same bytes properly during its state machine.
    let mut peek_buf = [0u8; 4096];
    let n = client_stream
        .peek(&mut peek_buf)
        .await
        .context("peeking at initial RDP data")?;

    if n == 0 {
        anyhow::bail!("RDP client disconnected before sending data");
    }

    // Log the raw X.224 data for debugging cookie extraction issues
    debug!(
        bytes = n,
        hex = %hex::encode(&peek_buf[..n.min(256)]),
        lossy_text = %String::from_utf8_lossy(&peek_buf[..n.min(256)]),
        "Raw X.224 Connection Request data"
    );

    let raw_username = extract_cookie_username(&peek_buf[..n]).ok_or_else(|| {
        anyhow::anyhow!(
            "No mstshash cookie in X.224 Connection Request — \
             RDP clients must set the username field to 'user#target'"
        )
    })?;

    let (warpgate_username, target_name) = parse_username_target(&raw_username)?;

    info!(%warpgate_username, %target_name, "RDP auth: parsed user#target from cookie");

    // Authenticate and authorize via ConfigProvider
    let mut cp = services.config_provider.lock().await;

    // Look up user to get AuthStateUserInfo
    let users = cp.list_users().await?;
    let user = users
        .iter()
        .find(|u| u.username == warpgate_username)
        .ok_or_else(|| anyhow::anyhow!("User '{}' not found", warpgate_username))?;
    let user_info = AuthStateUserInfo::from(user);

    // Authorize target access
    if !cp
        .authorize_target(&warpgate_username, &target_name)
        .await?
    {
        warn!(%warpgate_username, %target_name, "RDP authorization denied");
        anyhow::bail!(
            "User '{}' is not authorized for target '{}'",
            warpgate_username,
            target_name
        );
    }

    // Look up target configuration
    let targets = cp.list_targets().await?;
    let (target, target_rdp_opts) = targets
        .iter()
        .filter_map(|t| match &t.options {
            TargetOptions::Rdp(opts) => Some((t.clone(), opts.clone())),
            _ => None,
        })
        .find(|(t, _)| t.name == target_name)
        .ok_or_else(|| anyhow::anyhow!("RDP target '{}' not found", target_name))?;

    // Create an auth state for the audit trail.
    let credential_kinds = get_rdp_credential_requirements(&mut cp, &warpgate_username).await?;
    let sid = server_handle.lock().await.id();
    let (_auth_state_id, _auth_state) = services
        .auth_state_store
        .lock()
        .await
        .create(
            Some(&sid),
            &warpgate_username,
            crate::common::RDP_PROTOCOL_NAME,
            &credential_kinds,
        )
        .await?;

    drop(cp);

    // Update session with user and target info
    {
        let handle = server_handle.lock().await;
        handle.set_user_info(user_info).await?;
        handle.set_target(&target).await?;
    }

    info!(
        %target_name,
        host = %target_rdp_opts.host,
        port = %target_rdp_opts.port,
        "Connecting to RDP target"
    );

    // Phase 2: Run the IronRDP acceptor on the inbound stream.
    //
    // This performs X.224 negotiation, TLS upgrade, CredSSP (deferred validation),
    // and MCS/capability exchange. The result is a fully-negotiated framed stream
    // wrapped in TLS.
    let tls_cert_key = {
        let config = services.config.lock().await;
        crate::keys::load_certificate_and_key(&config, &services.global_params)
            .await
            .context("loading RDP TLS certificate")?
    };

    let server_tls_config =
        build_rdp_server_tls_config(tls_cert_key).context("building RDP TLS config")?;

    let accepted = accept_rdp(client_stream, server_tls_config)
        .await
        .context("RDP acceptor failed")?;

    info!("RDP acceptor: inbound connection accepted, TLS established");

    // Phase 3: Connect to the target using IronRDP connector with TOFU verification.
    let desktop_size = DesktopSize {
        width: 1920,
        height: 1080,
    };

    // Build the TOFU certificate verifier for this target
    let known_hosts = RdpKnownHosts::new(
        services.db.clone(),
        target.id,
        target_rdp_opts.host.clone(),
        target_rdp_opts.port,
    );
    let runtime_handle = tokio::runtime::Handle::current();
    let verifier = Arc::new(RdpKnownHostVerifier::new(
        Arc::new(Mutex::new(known_hosts)),
        runtime_handle,
    ));

    // connect_to_target calls ironrdp_tokio::connect_finalize which takes
    // `Option<&mut dyn AsyncNetworkClient>`. That trait is not Send, so the
    // returned future is !Send and cannot live across .await inside a
    // tokio::spawn task. We bridge this with block_in_place + block_on,
    // which is safe on Warpgate's multi-threaded tokio runtime.
    let runtime_handle_for_connect = tokio::runtime::Handle::current();
    let connect_opts = target_rdp_opts.clone();
    let connect_verifier = verifier.clone();
    let connected = tokio::task::block_in_place(|| {
        runtime_handle_for_connect.block_on(crate::client::connect_to_target(
            &connect_opts,
            desktop_size,
            connect_verifier,
        ))
    })
    .map_err(|e| anyhow::anyhow!("RDP connector failed: {e}"))?;

    info!("RDP connector: outbound connection established with TOFU verification");

    // Phase 4: Start recording
    let session_id = server_handle.lock().await.id();
    let recorder = {
        let recordings = services.recordings.lock().await;
        let metadata = RdpRecordingMetadata {
            target_name: target_name.clone(),
            target_host: target_rdp_opts.host.clone(),
        };
        match recordings
            .start::<RdpRecorder, _>(&session_id, None, metadata)
            .await
        {
            Ok(recorder) => {
                info!("RDP recording started");
                Some(recorder)
            }
            Err(warpgate_core::recordings::Error::Disabled) => {
                debug!("RDP recording disabled");
                None
            }
            Err(e) => {
                warn!(error = %e, "Failed to start RDP recording — continuing without recording");
                None
            }
        }
    };

    // Write the recording header
    if let Some(ref recorder) = recorder {
        if let Err(e) = recorder
            .write_header(
                u32::from(desktop_size.width),
                u32::from(desktop_size.height),
                RdpRecordingTarget {
                    name: target_name.clone(),
                    host: target_rdp_opts.host.clone(),
                },
            )
            .await
        {
            warn!(error = %e, "Failed to write RDP recording header");
        }
    }

    // Phase 5: Extract TLS streams from both framed wrappers and start the proxy.
    //
    // After both handshakes complete, the client thinks it's talking to Warpgate's
    // RDP server, and the target thinks it's talking to Warpgate's RDP client.
    // We extract the underlying TLS streams and proxy raw bytes between them.
    let (client_tls_stream, _client_leftover) = accepted.framed.into_inner();
    let (target_tls_stream, _target_leftover) = connected.framed.into_inner();

    // Read inactivity timeout from config
    let inactivity_timeout = {
        let config = services.config.lock().await;
        config.store.rdp.inactivity_timeout
    };

    info!(
        %target_name,
        ?inactivity_timeout,
        "Both TLS sessions established, starting proxy loop"
    );

    proxy_bidirectional(
        client_tls_stream,
        target_tls_stream,
        inactivity_timeout,
        &target_name,
    )
    .await
}

/// Check the user's credential policy for the RDP protocol.
///
/// Returns the list of required credential kinds for RDP, falling back
/// to `[Password]` if no RDP-specific policy is configured.
async fn get_rdp_credential_requirements(
    config_provider: &mut warpgate_core::ConfigProviderEnum,
    username: &str,
) -> Result<Vec<CredentialKind>> {
    let users: Vec<warpgate_common::User> = config_provider.list_users().await?;
    let user = users.iter().find(|u| u.username == username);

    match user {
        Some(user) => {
            if let Some(ref policy) = user.credential_policy {
                if let Some(ref rdp_kinds) = policy.rdp {
                    return Ok(rdp_kinds.clone());
                }
            }
            // Default: password only
            Ok(vec![CredentialKind::Password])
        }
        None => Ok(vec![CredentialKind::Password]),
    }
}

/// Validate RDP credentials against the Warpgate user store.
///
/// This function is used by the full IronRDP acceptor flow to validate a
/// password extracted from the CredSSP exchange.
///
/// If the password is valid, it is added to the auth state. If MFA (TOTP)
/// is additionally required, a warning is logged since TOTP cannot be
/// supplied through the standard RDP credential dialog.
pub async fn validate_rdp_credentials(
    services: &Services,
    username: &str,
    password: &Secret<String>,
    auth_state: &Arc<Mutex<AuthState>>,
) -> Result<AuthResult> {
    let password_cred = AuthCredential::Password(password.clone());

    let mut cp = services.config_provider.lock().await;
    let valid = cp.validate_credential(username, &password_cred).await?;

    if valid {
        let mut state = auth_state.lock().await;
        state.add_valid_credential(password_cred);

        let result = state.verify();
        if let AuthResult::Need(ref remaining) = result {
            if remaining.contains(&CredentialKind::Totp) {
                warn!(
                    %username,
                    "RDP target requires TOTP but MFA via RDP is not yet supported — \
                     session will remain unauthenticated"
                );
            }
        }
        Ok(result)
    } else {
        let mut state = auth_state.lock().await;
        state.reject();
        Ok(AuthResult::Rejected)
    }
}

/// Bidirectional TLS proxy with inactivity timeout.
///
/// Copies bytes between `client` and `target` until one side disconnects
/// or the session is idle longer than `inactivity_timeout`. Works with any
/// `AsyncRead + AsyncWrite` stream (raw TCP, TLS, etc.).
async fn proxy_bidirectional<C, T>(
    client: C,
    target: T,
    inactivity_timeout: Duration,
    target_name: &str,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut target_read, mut target_write) = tokio::io::split(target);

    let mut c2t_buf = vec![0u8; 65536];
    let mut t2c_buf = vec![0u8; 65536];

    loop {
        tokio::select! {
            result = client_read.read(&mut c2t_buf) => {
                match result {
                    Ok(0) => {
                        debug!("Client disconnected");
                        let _ = target_write.shutdown().await;
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = target_write.write_all(&c2t_buf[..n]).await {
                            debug!("Write to target failed: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("Read from client failed: {}", e);
                        break;
                    }
                }
            }
            result = target_read.read(&mut t2c_buf) => {
                match result {
                    Ok(0) => {
                        debug!("Target disconnected");
                        let _ = client_write.shutdown().await;
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = client_write.write_all(&t2c_buf[..n]).await {
                            debug!("Write to client failed: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("Read from target failed: {}", e);
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(inactivity_timeout) => {
                warn!(%target_name, ?inactivity_timeout, "RDP session timed out due to inactivity");
                let _ = client_write.shutdown().await;
                let _ = target_write.shutdown().await;
                break;
            }
        }
    }

    info!(%target_name, "RDP proxy session ended");
    Ok(())
}

/// Extract the username from the X.224 Connection Request's mstshash cookie.
///
/// The cookie format is: `Cookie: mstshash=<value>\r\n`
/// embedded in the X.224 TPDU header. We scan for this pattern in the raw bytes.
fn extract_cookie_username(data: &[u8]) -> Option<String> {
    let haystack = String::from_utf8_lossy(data);
    let prefix = "Cookie: mstshash=";
    let start = haystack.find(prefix)?;
    let after_prefix = &haystack[start + prefix.len()..];
    let end = after_prefix.find("\r\n").unwrap_or(after_prefix.len());
    let value = after_prefix[..end].trim();
    if value.is_empty() {
        return None;
    }
    Some(value.to_string())
}

/// Parse "username#target" into (username, target_name).
fn parse_username_target(raw: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = raw.splitn(2, '#').collect();
    if parts.len() != 2 {
        anyhow::bail!(
            "Invalid RDP username format '{}' — expected 'username#target'",
            raw
        );
    }
    let username = parts.first().map(|s| s.to_string()).unwrap_or_default();
    let target = parts.get(1).map(|s| s.to_string()).unwrap_or_default();
    if username.is_empty() || target.is_empty() {
        anyhow::bail!(
            "Invalid RDP username format '{}' — username and target must be non-empty",
            raw
        );
    }
    Ok((username, target))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_username_target_valid() {
        let (u, t) = parse_username_target("alice#myserver").expect("should parse");
        assert_eq!(u, "alice");
        assert_eq!(t, "myserver");
    }

    #[test]
    fn test_parse_username_target_with_hash_in_target() {
        let (u, t) = parse_username_target("alice#my#server").expect("should parse");
        assert_eq!(u, "alice");
        assert_eq!(t, "my#server");
    }

    #[test]
    fn test_parse_username_target_missing_hash() {
        assert!(parse_username_target("alice").is_err());
    }

    #[test]
    fn test_parse_username_target_empty_parts() {
        assert!(parse_username_target("#target").is_err());
        assert!(parse_username_target("user#").is_err());
    }

    #[test]
    fn test_extract_cookie_username() {
        let data = b"\x03\x00\x00*%\xe0\x00\x00\x00\x00\x00Cookie: mstshash=alice#srv\r\n\x01\x00\x08\x00\x03\x00\x00\x00";
        assert_eq!(extract_cookie_username(data), Some("alice#srv".to_string()));
    }

    #[test]
    fn test_extract_cookie_username_missing() {
        let data = b"\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00";
        assert_eq!(extract_cookie_username(data), None);
    }
}
