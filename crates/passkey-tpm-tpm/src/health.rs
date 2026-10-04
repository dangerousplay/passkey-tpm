//! TPM reset detection (TPM-15) and dictionary-attack status (TPM-14).

use tss_esapi::constants::tss::{
    TPM2_PT_LOCKOUT_COUNTER, TPM2_PT_LOCKOUT_INTERVAL, TPM2_PT_LOCKOUT_RECOVERY,
    TPM2_PT_MAX_AUTH_FAIL, TPM2_PT_PERMANENT,
};
use tss_esapi::constants::CapabilityType;
use tss_esapi::structures::CapabilityData;
use tss_esapi::Context;

use crate::error::{Error, Result};
use crate::srk;

/// Checks the SRK is the one this user's credentials were created under.
///
/// # Errors
/// [`Error::SrkMissing`]/[`Error::SrkMismatch`]/[`Error::NotAnSrk`] after a TPM clear
/// (all map to `TpmError::Reset`), TPM errors otherwise.
pub fn check(ctx: &mut Context, pinned_srk_name: &[u8]) -> Result<()> {
    srk::open_pinned(ctx, pinned_srk_name).map(|_| ())
}

/// The TPM's dictionary-attack state. Shared by every TPM user on the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaStatus {
    /// Whether an admin set a lockout password. If not, any TPM user can reset the DA
    /// counter, which weakens PIN brute-force protection (T5).
    pub lockout_auth_set: bool,
    pub in_lockout: bool,
    pub failed_tries: u32,
    pub max_tries: u32,
    /// Seconds after which one failure is forgotten.
    pub recovery_interval_s: u32,
    /// Seconds before lockout-hierarchy auth may be retried after a failure.
    pub lockout_recovery_s: u32,
}

impl DaStatus {
    /// CTAP allows up to 8 PIN retries; the TPM must not lock out before the CTAP counter
    /// blocks the PIN (AD-010).
    #[must_use]
    pub fn compatible_with_ctap(&self) -> bool {
        self.max_tries > 8
    }
}

const TPMA_PERMANENT_LOCKOUT_AUTH_SET: u32 = 1 << 2;
const TPMA_PERMANENT_IN_LOCKOUT: u32 = 1 << 9;

/// Reads the current dictionary-attack state. Bypasses tss-esapi's property cache, which
/// would return stale values for these variable properties.
///
/// # Errors
/// TPM errors; [`Error::Corrupt`] if a property is missing.
pub fn da_status(ctx: &mut Context) -> Result<DaStatus> {
    let count = TPM2_PT_LOCKOUT_RECOVERY - TPM2_PT_PERMANENT + 1;
    let (data, _) = ctx.execute_without_session(|ctx| {
        ctx.get_capability(CapabilityType::TpmProperties, TPM2_PT_PERMANENT, count)
    })?;
    let CapabilityData::TpmProperties(props) = data else {
        return Err(Error::Corrupt("TPM properties"));
    };
    let get = |tag: u32| {
        props
            .iter()
            .find(|p| u32::from(p.property()) == tag)
            .map(|p| p.value())
            .ok_or(Error::Corrupt("missing TPM property"))
    };
    let permanent = get(TPM2_PT_PERMANENT)?;
    Ok(DaStatus {
        lockout_auth_set: permanent & TPMA_PERMANENT_LOCKOUT_AUTH_SET != 0,
        in_lockout: permanent & TPMA_PERMANENT_IN_LOCKOUT != 0,
        failed_tries: get(TPM2_PT_LOCKOUT_COUNTER)?,
        max_tries: get(TPM2_PT_MAX_AUTH_FAIL)?,
        recovery_interval_s: get(TPM2_PT_LOCKOUT_INTERVAL)?,
        lockout_recovery_s: get(TPM2_PT_LOCKOUT_RECOVERY)?,
    })
}
