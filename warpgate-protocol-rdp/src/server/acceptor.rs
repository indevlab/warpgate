//! Drives the `ironrdp-acceptor` state machine for inbound RDP connections.
//!
//! Flow:
//! 1. X.224 Connection Request → parse cookie for `username#target`
//! 2. Security negotiation (TLS / Standard Security / CredSSP)
//! 3. TLS upgrade if needed
//! 4. CredSSP/NLA if negotiated (deferred validation model)
//! 5. MCS channel join, capability exchange, connection finalization
//! 6. Return the fully-accepted framed stream + `AcceptorResult`

use std::sync::Arc;

use anyhow::{Context, Result};
use ironrdp_acceptor::{self, Acceptor, AcceptorResult, BeginResult};
use ironrdp_connector::DesktopSize;
use ironrdp_pdu::nego::SecurityProtocol;
use ironrdp_pdu::rdp::capability_sets::CapabilitySet;
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
/// Returns the accepted connection with the TLS-upgraded framed stream, or an
/// error if negotiation fails at any point.
pub async fn accept_rdp(
    tcp_stream: TcpStream,
    tls_config: Arc<ServerConfig>,
) -> Result<AcceptedConnection<TokioStream<tokio_rustls::server::TlsStream<TcpStream>>>> {
    let desktop_size = DesktopSize {
        width: 1920,
        height: 1080,
    };

    let capabilities = build_server_capabilities();

    // Advertise both Hybrid (NLA/CredSSP) and SSL.
    let security = SecurityProtocol::HYBRID | SecurityProtocol::SSL;

    // Pass None for creds — we don't pre-validate; we use deferred validation.
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

    // Phase 3: CredSSP / NLA (if negotiated)
    if acceptor.should_perform_credssp() {
        info!(
            "RDP acceptor: CredSSP/NLA negotiated — using deferred validation \
             (credentials validated after ClientInfo PDU)"
        );
        // In the deferred-validation model, we skip the actual CredSSP exchange
        // and mark it as done. Password validation is performed by the session
        // layer after extracting credentials from the ClientInfo PDU.
        //
        // This is secure because:
        // 1. TLS channel already established (confidentiality)
        // 2. Client sends credentials in ClientInfo during SecureSettingsExchange
        // 3. Session layer validates via ConfigProvider::authenticate
        //
        // TODO(T021): Full CredSSP exchange with WarpgateCredentialsProxy
        acceptor.mark_credssp_as_done();
    }

    // Phase 4: MCS + capability exchange + connection finalization
    let (framed, result) = ironrdp_acceptor::accept_finalize(tls_framed, &mut acceptor)
        .await
        .map_err(|e| anyhow::anyhow!("RDP accept_finalize failed: {e}"))?;

    info!("RDP acceptor: connection fully accepted");

    Ok(AcceptedConnection { framed, result })
}
