//! Per-user authenticator state kept in memory by the broker (lost on restart, which is
//! the "power cycle" of a virtual authenticator).

use passkey_tpm_wire::resident::ResidentEntry;

use crate::pin_protocol::{KeyAgreement, Protocol, SharedSecret};
use crate::token::{BootMismatches, PinUvAuthToken};
use crate::tpm_iface::{CredBlobs, RpIdHash};

/// A pinUvAuthToken and the protocol it was issued under.
#[derive(Debug)]
pub struct IssuedToken {
    pub token: PinUvAuthToken,
    pub protocol: Protocol,
}

/// hmac-secret input carried from request validation to the TPM step.
#[derive(Debug)]
pub struct HmacRequest {
    pub shared: SharedSecret,
    pub salt1: [u8; 32],
    pub salt2: Option<[u8; 32]>,
}

/// One credential found for a getAssertion.
#[derive(Debug, Clone)]
pub struct Found {
    pub id: Vec<u8>,
    pub blobs: CredBlobs,
    pub user: Option<ResidentEntry>,
}

/// Remaining credentials of a multi-credential getAssertion (CTAP 2.1 §6.3).
#[derive(Debug)]
pub struct NextAssertion {
    pub rp_id_hash: RpIdHash,
    pub client_data_hash: [u8; 32],
    pub remaining: Vec<Found>,
    pub started_ms: u64,
}

/// Enumeration cursor for credentialManagement GetNext* subcommands.
#[derive(Debug)]
pub enum CredMgmtCursor {
    Rps(Vec<(String, String)>),
    Credentials {
        rp_id_hash: RpIdHash,
        entries: Vec<ResidentEntry>,
    },
}

#[derive(Debug, Default)]
pub struct UserState {
    pub key_agreement: Option<KeyAgreement>,
    pub token: Option<IssuedToken>,
    pub mismatches: BootMismatches,
    pub uv_failures: u8,
    pub next_assertion: Option<NextAssertion>,
    pub cred_mgmt: Option<CredMgmtCursor>,
}

impl UserState {
    /// The key agreement key, generated on first use.
    ///
    /// # Errors
    /// The CTAP status if key generation fails.
    pub fn key_agreement(&mut self) -> Result<&KeyAgreement, u8> {
        if self.key_agreement.is_none() {
            self.key_agreement =
                Some(KeyAgreement::generate().map_err(|_| super::common::status::OTHER)?);
        }
        self.key_agreement
            .as_ref()
            .ok_or(super::common::status::OTHER)
    }

    /// Regenerates the key agreement key (after a PIN mismatch, CTAP 2.1 §6.5.5.7.2).
    pub fn regenerate_key_agreement(&mut self) {
        self.key_agreement = KeyAgreement::generate().ok();
    }

    /// Drops the token (PIN change, reset, new token).
    pub fn invalidate_token(&mut self) {
        self.token = None;
    }
}
