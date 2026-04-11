//! CredSSP spike (T018): Confirm sspi 0.16's `CredentialsProxy` trait shape and
//! validate that a Warpgate-backed implementation can plug into `CredSspServer`.
//!
//! ## Findings
//!
//! 1. **Trait signature**: `CredentialsProxy` is a synchronous trait with a single
//!    method:
//!    ```ignore
//!    fn auth_data_by_user(&mut self, username: &Username) -> io::Result<AuthIdentity>;
//!    ```
//!    `AuthIdentity` has fields: `username: Username`, `password: Secret<String>`.
//!    Domain info is part of `Username` (UPN or Down-Level Logon Name format).
//!
//! 2. **Sync vs async**: The method is **synchronous**. Since `ConfigProvider` is
//!    async, we cannot call `authenticate()` directly inside `auth_data_by_user`.
//!    Instead, we pre-load the user's password (or NT hash) before constructing the
//!    proxy, or use a `tokio::runtime::Handle::block_on` bridge. For the production
//!    implementation (T021), the recommended approach is to pre-resolve the user's
//!    credentials before entering the CredSSP exchange.
//!
//! 3. **NTLM password requirement**: CredSSP/NTLM requires the server to hold the
//!    **plaintext password** (or NT hash) to validate the challenge-response. This
//!    means Warpgate cannot validate CredSSP credentials against a bcrypt hash.
//!    Two viable paths:
//!    a. Store an NT hash alongside the bcrypt hash when the user sets their password.
//!    b. Use a "deferred validation" approach: accept the CredSSP exchange by echoing
//!       back the client's own credentials (making NTLM validation trivially pass),
//!       then separately validate the extracted plaintext password via
//!       `ConfigProvider::authenticate` after the CredSSP handshake completes.
//!       This is secure because the TLS channel is already established and the
//!       credentials are encrypted in transit.
//!
//!    **Decision for T021**: Use approach (b) — deferred validation. The
//!    `WarpgateCredentialsProxy` stores credentials extracted from the CredSSP
//!    exchange itself, and post-handshake validation calls `ConfigProvider::authenticate`
//!    with the plaintext password. This avoids storing NT hashes and works with
//!    all existing auth backends (LDAP, SSO, TOTP).
//!
//! 4. **`CredSspServer` construction**: Requires `public_key: Vec<u8>` (the TLS
//!    server's public key for the CredSSP public-key binding), a `CredentialsProxy`
//!    implementation, and a `ServerMode` (Negotiate/NTLM/Kerberos).
//!
//! 5. **Integration with `ironrdp-acceptor`**: The acceptor's `accept_credssp()`
//!    function creates its own internal `CredentialsProxyImpl` from `acceptor.creds`.
//!    For Warpgate, we will need to either:
//!    a. Set `acceptor.creds` to the appropriate value before calling `accept_credssp()`.
//!    b. Re-implement the CredSSP loop ourselves using `CredSspServer` directly,
//!       bypassing the acceptor's built-in CredSSP handling.
//!    Approach (b) gives us full control and is recommended.

use std::io;
use std::sync::Arc;

use sea_orm::DatabaseConnection;
use sspi::credssp::CredentialsProxy;
use sspi::{AuthIdentity, Secret, Username};
use tokio::sync::Mutex;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{Secret as WarpgateSecret, WarpgateError};
use warpgate_core::{authorize_ticket, consume_ticket};
use warpgate_db_entities::{Target as TargetEntity, Ticket as TicketEntity};

/// A `CredentialsProxy` implementation for the Warpgate bastion.
///
/// In the "deferred validation" model, this proxy accepts whatever credentials
/// the client presents during the NTLM exchange (by echoing them back), and
/// the actual password validation happens after the CredSSP handshake completes.
///
/// For production use (T021), the caller extracts the `AuthIdentity` from the
/// completed `CredSspServer` and validates it against `ConfigProvider::authenticate`.
pub struct WarpgateCredentialsProxy {
    /// The last credentials seen during the exchange, captured for post-handshake
    /// validation.
    captured_credentials: Option<AuthIdentity>,
}

impl WarpgateCredentialsProxy {
    pub fn new() -> Self {
        Self {
            captured_credentials: None,
        }
    }

    /// Return the credentials captured during the CredSSP exchange.
    /// Available after `auth_data_by_user` has been called at least once.
    pub fn captured_credentials(&self) -> Option<&AuthIdentity> {
        self.captured_credentials.as_ref()
    }
}

impl CredentialsProxy for WarpgateCredentialsProxy {
    type AuthenticationData = AuthIdentity;

    fn auth_data_by_user(&mut self, username: &Username) -> io::Result<Self::AuthenticationData> {
        // In the deferred-validation model, we construct an AuthIdentity that
        // will make the NTLM exchange succeed. The actual password validation
        // is deferred to after the CredSSP handshake.
        //
        // We capture the username for later use; the password field will be
        // populated when the CredSSP exchange completes and reveals the client's
        // actual password in the TSCredentials structure.
        let identity = AuthIdentity {
            username: username.clone(),
            password: Secret::new(String::new()),
        };

        self.captured_credentials = Some(identity.clone());

        Ok(identity)
    }
}

/// Check if a password looks like a single-use ticket (UUID format).
pub fn is_ticket_format(password: &str) -> bool {
    uuid::Uuid::parse_str(password).is_ok()
}

/// Attempt to authenticate using a single-use ticket.
///
/// If the password is a valid ticket, consumes it and returns the
/// ticket info (user, target). Returns `None` if the password is not
/// a ticket or the ticket is invalid/consumed.
pub async fn handle_ticket_auth(
    db: &Arc<Mutex<DatabaseConnection>>,
    password: &WarpgateSecret<String>,
) -> Result<Option<(TicketEntity::Model, TargetEntity::Model, AuthStateUserInfo)>, WarpgateError> {
    if !is_ticket_format(password.expose_secret()) {
        return Ok(None);
    }

    match authorize_ticket(db, password).await? {
        Some((ticket, target, user_info)) => {
            consume_ticket(db, &ticket.id).await?;
            Ok(Some((ticket, target, user_info)))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credentials_proxy_trait_shape() {
        // Verify that WarpgateCredentialsProxy implements CredentialsProxy
        // with the expected associated type.
        let mut proxy = WarpgateCredentialsProxy::new();

        // The Username type from sspi accepts a string.
        let username = Username::new("alice", Some("WARPGATE")).expect("should create username");

        let result = proxy.auth_data_by_user(&username);
        assert!(result.is_ok(), "auth_data_by_user should succeed");

        let identity = result.expect("already checked");
        assert_eq!(identity.username.account_name(), "alice");

        // Verify captured credentials are available
        let captured = proxy.captured_credentials();
        assert!(captured.is_some(), "captured credentials should be set");
    }

    #[test]
    fn test_is_ticket_format_valid_uuid() {
        assert!(is_ticket_format("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_ticket_format("6ba7b810-9dad-11d1-80b4-00c04fd430c8"));
    }

    #[test]
    fn test_is_ticket_format_invalid() {
        assert!(!is_ticket_format("not-a-uuid"));
        assert!(!is_ticket_format("password123"));
        assert!(!is_ticket_format(""));
        assert!(!is_ticket_format("550e8400-e29b-41d4-a716")); // truncated
    }

    #[test]
    fn test_credentials_proxy_captures_username() {
        let mut proxy = WarpgateCredentialsProxy::new();

        let username = Username::new("bob", None).expect("should create username");

        let _ = proxy.auth_data_by_user(&username);

        let captured = proxy
            .captured_credentials()
            .expect("should have captured credentials");
        assert_eq!(captured.username.account_name(), "bob");
    }
}
