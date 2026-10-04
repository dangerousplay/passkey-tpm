//! Which TPM gate may authorise which operation (ADR 0003, CTAP 2.1 §12.1, §12.5).
//!
//! The TPM enforces these rules through each key's authPolicy; this module is the
//! verified statement of the same rules that the core uses to pick a gate, so a
//! request the TPM would reject is refused before any TPM work happens.

use passkey_tpm_wire::credid::CredProtect;
use vstd::prelude::*;

verus! {

// Spec-only shim telling Verus the shape of the wire crate's enum; never instantiated.
#[allow(missing_debug_implementations, dead_code)]
#[verifier::external_type_specification]
pub struct ExCredProtect(CredProtect);

/// A per-user TPM gate whose secret only the broker holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateKind {
    /// clientPIN verified (PIN gate, DA-protected NV index).
    Pin,
    /// Built-in user verification (fingerprint) succeeded.
    Uv,
    /// User presence only.
    Up,
}

impl GateKind {
    /// True for gates that set the UV flag in authenticator data.
    pub open spec fn spec_is_uv(self) -> bool {
        self matches GateKind::Pin || self matches GateKind::Uv
    }

    pub fn is_uv(self) -> (b: bool)
        ensures
            b == self.spec_is_uv(),
    {
        match self {
            GateKind::Pin | GateKind::Uv => true,
            GateKind::Up => false,
        }
    }
}

pub open spec fn spec_protect_requires_uv(p: CredProtect) -> bool {
    p == CredProtect::UvRequired
}

fn protect_requires_uv(p: CredProtect) -> (b: bool)
    ensures
        b == spec_protect_requires_uv(p),
{
    match p {
        CredProtect::UvRequired => true,
        CredProtect::UvOptional | CredProtect::UvOptionalWithCredIdList => false,
    }
}

/// May `gate` authorise a signature with a credential protected by `protect`?
pub open spec fn spec_sign_allowed(protect: CredProtect, gate: GateKind) -> bool {
    gate.spec_is_uv() || !spec_protect_requires_uv(protect)
}

pub fn sign_allowed(protect: CredProtect, gate: GateKind) -> (b: bool)
    ensures
        b == spec_sign_allowed(protect, gate),
        // credProtect=3 can never be exercised with presence alone.
        protect == CredProtect::UvRequired && gate == GateKind::Up ==> !b,
        // A UV gate always works.
        gate.spec_is_uv() ==> b,
{
    gate.is_uv() || !protect_requires_uv(protect)
}

/// Which hmac-secret key a gate selects: CTAP 2.1 §12.5 picks CredRandomWithUV exactly
/// when the response UV bit is set, i.e. when the gate is a UV gate.
pub fn hmac_uses_with_uv_key(gate: GateKind) -> (with_uv: bool)
    ensures
        with_uv == gate.spec_is_uv(),
{
    gate.is_uv()
}

} // verus!

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presence_cannot_use_uv_required_credentials() {
        assert!(!sign_allowed(CredProtect::UvRequired, GateKind::Up));
        assert!(sign_allowed(CredProtect::UvRequired, GateKind::Uv));
        assert!(sign_allowed(CredProtect::UvRequired, GateKind::Pin));
        assert!(sign_allowed(CredProtect::UvOptional, GateKind::Up));
    }

    #[test]
    fn hmac_key_follows_uv() {
        assert!(hmac_uses_with_uv_key(GateKind::Pin));
        assert!(hmac_uses_with_uv_key(GateKind::Uv));
        assert!(!hmac_uses_with_uv_key(GateKind::Up));
    }
}
