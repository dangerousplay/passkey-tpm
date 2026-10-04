//! Authorisation and policy sessions, chosen by [`BusProtection`] (TPM-10, AD-013).
//!
//! On a discrete TPM every secret travels inside salted sessions with parameter encryption,
//! so gate authValues and hmac-secret outputs never appear on the bus. On a firmware TPM
//! there is no bus; plain password authorisation and unsalted policy sessions avoid the
//! context swaps that make each extra session cost ~60 ms through the kernel resource manager.

use tss_esapi::attributes::SessionAttributesBuilder;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::SessionHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::session_handles::{AuthSession, PolicySession};
use tss_esapi::structures::SymmetricDefinition;
use tss_esapi::Context;

use crate::error::{Error, Result};
use crate::srk::{BusProtection, Srk};

fn start(
    ctx: &mut Context,
    srk: Option<&Srk>,
    kind: SessionType,
    encrypt: bool,
) -> Result<AuthSession> {
    let session = ctx
        .start_auth_session(
            srk.map(|s| s.handle),
            None,
            None,
            kind,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?
        .ok_or(Error::Corrupt("TPM returned no session"))?;
    if encrypt {
        let (attributes, mask) = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();
        if let Err(e) = ctx.tr_sess_set_attributes(session, attributes, mask) {
            flush(ctx, session);
            return Err(e.into());
        }
    }
    Ok(session)
}

/// Flushes a session, ignoring errors (it may already be gone after `continueSession=false`).
pub fn flush(ctx: &mut Context, session: AuthSession) {
    if !matches!(session, AuthSession::Password) {
        let _ = ctx.flush_context(SessionHandle::from(session).into());
    }
}

/// Starts a policy session. With `secret_response` on an encrypted bus it is salted and
/// encrypts the response (for hmac-secret output); otherwise it is unsalted and plain.
///
/// # Errors
/// TPM errors.
pub fn start_policy(ctx: &mut Context, srk: &Srk, secret_response: bool) -> Result<AuthSession> {
    match (srk.bus, secret_response) {
        (BusProtection::Encrypted, true) => start(ctx, Some(srk), SessionType::Policy, true),
        _ => start(ctx, None, SessionType::Policy, false),
    }
}

/// Runs `f` with a fresh policy session (see [`start_policy`]) and always flushes it.
///
/// # Errors
/// Errors from starting the session or from `f`.
pub fn with_policy<T>(
    ctx: &mut Context,
    srk: &Srk,
    secret_response: bool,
    f: impl FnOnce(&mut Context, AuthSession, PolicySession) -> Result<T>,
) -> Result<T> {
    let session = start_policy(ctx, srk, secret_response)?;
    let result = PolicySession::try_from(session)
        .map_err(Error::from)
        .and_then(|policy| f(ctx, session, policy));
    flush(ctx, session);
    result
}

/// Runs `f` with the session that should authorise a command carrying a secret (an
/// authValue to check, or a new authValue in its parameters): the password session on
/// firmware TPMs, a salted parameter-encrypting HMAC session on discrete ones.
///
/// # Errors
/// Errors from starting the session or from `f`.
pub fn with_auth<T>(
    ctx: &mut Context,
    srk: &Srk,
    f: impl FnOnce(&mut Context) -> Result<T>,
) -> Result<T> {
    let session = match srk.bus {
        BusProtection::Firmware => AuthSession::Password,
        BusProtection::Encrypted => start(ctx, Some(srk), SessionType::Hmac, true)?,
    };
    let result = ctx.execute_with_session(Some(session), |ctx| f(ctx));
    flush(ctx, session);
    result
}
