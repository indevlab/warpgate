//! Drives the `ironrdp-acceptor` state machine for inbound RDP connections.
//!
//! Flow:
//! 1. X.224 Connection Request → Connection Confirm (SSL-only, no NLA/CredSSP)
//! 2. TLS upgrade
//! 3. MCS channel join, capability exchange, connection finalization
//!    — during SecureSettingsExchange we intercept the ClientInfo PDU to
//!      extract the client's username and password before the acceptor
//!      validates them.
//! 4. Return the fully-accepted framed stream + `AcceptorResult` + credentials

use std::sync::Arc;

use anyhow::{Context, Result};
use ironrdp_acceptor::{self, Acceptor, AcceptorResult, BeginResult};
use ironrdp_async::{FramedRead, FramedWrite};
use ironrdp_connector::{DesktopSize, Sequence};
use ironrdp_core::{WriteBuf, decode};
use ironrdp_pdu::nego::SecurityProtocol;
use ironrdp_pdu::rdp::capability_sets::CapabilitySet;
use ironrdp_pdu::rdp::client_info::Credentials;
use ironrdp_pdu::{mcs, rdp, x224::X224};
use ironrdp_tokio::{Framed, TokioFramed, TokioStream};
use rustls::ServerConfig;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};

/// Result of a successful inbound RDP accept.
pub struct AcceptedConnection<S> {
    /// The framed stream ready for active-stage PDU exchange.
    pub framed: Framed<S>,
    /// Channel, capability, and session info from the acceptor.
    pub result: AcceptorResult,
    /// Credentials extracted from the ClientInfo PDU (username, password, domain).
    pub credentials: Credentials,
}

/// Build minimal server capabilities for the acceptor.
///
/// These are intentionally minimal — we do not advertise any virtual channel
/// extensions per the spec's out-of-scope requirements.
///
/// **Rejected channels** (not advertised in capabilities):
/// - Smart card redirection (RDPDR)
/// - Drive/printer/clipboard redirection (cliprdr, rdpdr)
/// - RemoteApp (RAIL)
/// - GPU streaming (RDPGFX)
/// - Audio/video redirection (rdpsnd, audin, video)
///
/// By not including these capability sets, the server signals to the client
/// that these features are unsupported. Compliant RDP clients will not
/// attempt to use channels that weren't negotiated.
fn build_server_capabilities() -> Vec<CapabilitySet> {
    use ironrdp_pdu::rdp::capability_sets::*;

    vec![
        CapabilitySet::General(General {
            major_platform_type: MajorPlatformType::WINDOWS,
            minor_platform_type: MinorPlatformType::WINDOWS_NT,
            protocol_version: 0x0200,
            extra_flags: GeneralExtraFlags::FASTPATH_OUTPUT_SUPPORTED
                | GeneralExtraFlags::NO_BITMAP_COMPRESSION_HDR
                | GeneralExtraFlags::ENC_SALTED_CHECKSUM
                | GeneralExtraFlags::LONG_CREDENTIALS_SUPPORTED,
            refresh_rect_support: true,
            suppress_output_support: true,
        }),
        CapabilitySet::Bitmap(Bitmap {
            pref_bits_per_pix: 32,
            desktop_width: 1920,
            desktop_height: 1080,
            desktop_resize_flag: true,
            drawing_flags: BitmapDrawingFlags::empty(),
        }),
        CapabilitySet::Order(Order::new(
            OrderFlags::NEGOTIATE_ORDER_SUPPORT | OrderFlags::ZERO_BOUNDS_DELTAS_SUPPORT,
            OrderSupportExFlags::empty(),
            0,
            0,
        )),
        CapabilitySet::Input(Input {
            input_flags: InputFlags::SCANCODES | InputFlags::MOUSEX | InputFlags::UNICODE,
            keyboard_layout: 0,
            keyboard_type: None,
            keyboard_subtype: 0,
            keyboard_function_key: 0,
            keyboard_ime_filename: String::new(),
        }),
        CapabilitySet::Pointer(Pointer {
            color_pointer_cache_size: 25,
            pointer_cache_size: 25,
        }),
        CapabilitySet::VirtualChannel(VirtualChannel {
            flags: VirtualChannelFlags::COMPRESSION_SERVER_TO_CLIENT,
            chunk_size: None,
        }),
    ]
}

/// Run the inbound acceptor state machine on a raw TCP stream.
///
/// Returns the accepted connection with the TLS-upgraded framed stream,
/// the extracted client credentials (from the ClientInfo PDU), or an
/// error if negotiation fails at any point.
///
/// Only TLS (SSL) security is advertised — NLA/CredSSP is not supported
/// for the inbound leg. This allows the server to receive the client's
/// plaintext credentials in the ClientInfo PDU (over the TLS channel)
/// without requiring a CredSSP implementation.
pub async fn accept_rdp(
    tcp_stream: TcpStream,
    tls_config: Arc<ServerConfig>,
) -> Result<AcceptedConnection<TokioStream<tokio_rustls::server::TlsStream<TcpStream>>>> {
    let desktop_size = DesktopSize {
        width: 1920,
        height: 1080,
    };

    let capabilities = build_server_capabilities();

    // Advertise SSL only — no HYBRID/CredSSP.
    //
    // This forces clients to send credentials in the ClientInfo PDU (over TLS)
    // rather than through CredSSP/NLA. This simplifies the flow because:
    // 1. We don't need to implement CredSSP server-side
    // 2. We can intercept ClientInfo to extract the username#target
    // 3. The TLS channel already provides confidentiality
    let security = SecurityProtocol::SSL;

    // Pass None for creds — we'll set them from the intercepted ClientInfo
    // before the acceptor validates them at SecureSettingsExchange.
    let mut acceptor = Acceptor::new(security, desktop_size, capabilities, None);

    // Phase 1: X.224 negotiation up to security upgrade point
    let framed: TokioFramed<TcpStream> = TokioFramed::new(tcp_stream);

    let begin_result = ironrdp_acceptor::accept_begin(framed, &mut acceptor)
        .await
        .map_err(|e| anyhow::anyhow!("RDP accept_begin failed: {e}"))?;

    debug!("RDP acceptor: X.224 negotiation complete");

    // Phase 2: TLS upgrade
    let inner_stream = match begin_result {
        BeginResult::ShouldUpgrade(inner_stream) => inner_stream,
        BeginResult::Continue(_framed) => {
            anyhow::bail!(
                "RDP client did not request TLS; Standard Security is not yet \
                 supported for the inbound leg"
            );
        }
    };

    let tls_acceptor = TlsAcceptor::from(tls_config);
    let tls_stream = tls_acceptor
        .accept(inner_stream)
        .await
        .context("TLS handshake with RDP client failed")?;

    let tls_framed: TokioFramed<tokio_rustls::server::TlsStream<TcpStream>> =
        TokioFramed::new(tls_stream);

    acceptor.mark_security_upgrade_as_done();

    // Phase 3: MCS + capability exchange + connection finalization
    // We use a custom finalize loop that intercepts the ClientInfo PDU
    // to extract credentials before the acceptor validates them.
    let (framed, result, credentials) = accept_finalize_with_credentials(tls_framed, &mut acceptor)
        .await
        .context("RDP accept_finalize failed")?;

    info!("RDP acceptor: connection fully accepted");

    Ok(AcceptedConnection {
        framed,
        result,
        credentials,
    })
}

/// Custom version of `ironrdp_acceptor::accept_finalize` that intercepts the
/// ClientInfo PDU to extract client credentials.
///
/// When the acceptor reaches the `SecureSettingsExchange` state, we:
/// 1. Read the raw PDU bytes from the framed stream
/// 2. Parse the ClientInfo PDU to extract credentials
/// 3. Set `acceptor.creds` to match the client's credentials
/// 4. Let the acceptor process the PDU normally (validation will pass)
async fn accept_finalize_with_credentials<S>(
    mut framed: Framed<S>,
    acceptor: &mut Acceptor,
) -> Result<(Framed<S>, AcceptorResult, Credentials)>
where
    S: FramedRead + FramedWrite,
{
    let mut buf = WriteBuf::new();
    let mut captured_credentials: Option<Credentials> = None;

    loop {
        if let Some(result) = acceptor.get_result() {
            let creds = captured_credentials.ok_or_else(|| {
                anyhow::anyhow!(
                    "RDP acceptor completed without receiving ClientInfo PDU — \
                     this should not happen"
                )
            })?;
            return Ok((framed, result, creds));
        }

        // Check if the acceptor is waiting for the ClientInfo PDU
        if acceptor.state().name() == "SecureSettingsExchange" {
            // Read the PDU bytes manually
            let hint = acceptor
                .next_pdu_hint()
                .ok_or_else(|| anyhow::anyhow!("no PDU hint at SecureSettingsExchange"))?;

            let pdu_bytes = framed
                .read_by_hint(hint)
                .await
                .map_err(|e| anyhow::anyhow!("failed to read ClientInfo PDU: {e}"))?;

            // Parse ClientInfo to extract credentials
            let data: X224<mcs::SendDataRequest<'_>> =
                decode(&pdu_bytes).map_err(|e| anyhow::anyhow!("failed to decode ClientInfo X224 wrapper: {e}"))?;
            let client_info: rdp::ClientInfoPdu =
                decode(data.0.user_data.as_ref())
                    .map_err(|e| anyhow::anyhow!("failed to decode ClientInfo PDU: {e}"))?;

            let creds = client_info.client_info.credentials.clone();
            debug!(
                username = %creds.username,
                domain = ?creds.domain,
                "Intercepted ClientInfo credentials"
            );

            captured_credentials = Some(creds.clone());

            // Set matching credentials on the acceptor so the validation passes
            acceptor.creds = Some(creds);

            // Now let the acceptor process the same bytes
            buf.clear();
            let written = acceptor
                .step(&pdu_bytes, &mut buf)
                .map_err(|e| anyhow::anyhow!("acceptor step at SecureSettingsExchange failed: {e}"))?;

            // Write any output from this step
            if let Some(size) = written.size() {
                let response = &buf[..size];
                framed
                    .write_all(response)
                    .await
                    .map_err(|e| anyhow::anyhow!("failed to write acceptor output: {e}"))?;
            }

            continue;
        }

        // For all other states, use the normal step flow
        ironrdp_async::single_sequence_step(&mut framed, acceptor, &mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("acceptor step failed: {e}"))?;
    }
}
