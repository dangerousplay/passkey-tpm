//! Software computation of TPM 2.0 policy digests (TPM 2.0 Part 3, §23).
//!
//! Credential keys are created with an authPolicy computed here, without a trial session.
//! Integration tests check every function against a real TPM trial session.

use passkey_tpm_core::tpm_iface::{CredProtect, GateKind, RpIdHash};
use sha2::{Digest as _, Sha256};

pub type Digest = [u8; 32];

/// TPM_CC values (TPM 2.0 Part 2, §6.5.2).
pub mod cc {
    pub const NV_CHANGE_AUTH: u32 = 0x0000_013B;
    pub const POLICY_SECRET: u32 = 0x0000_0151;
    pub const HMAC: u32 = 0x0000_0155;
    pub const SIGN: u32 = 0x0000_015D;
    pub const POLICY_AUTH_VALUE: u32 = 0x0000_016B;
    pub const POLICY_COMMAND_CODE: u32 = 0x0000_016C;
    pub const POLICY_OR: u32 = 0x0000_0171;
}

/// The initial (empty) policy digest.
pub const ZERO: Digest = [0; 32];

fn sha256(parts: &[&[u8]]) -> Digest {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

/// `TPM2_PolicyCommandCode`: digest' = H(digest ‖ TPM_CC_PolicyCommandCode ‖ code).
#[must_use]
pub fn command_code(digest: &Digest, code: u32) -> Digest {
    sha256(&[
        digest,
        &cc::POLICY_COMMAND_CODE.to_be_bytes(),
        &code.to_be_bytes(),
    ])
}

/// `TPM2_PolicyAuthValue`: digest' = H(digest ‖ TPM_CC_PolicyAuthValue).
#[must_use]
pub fn auth_value(digest: &Digest) -> Digest {
    sha256(&[digest, &cc::POLICY_AUTH_VALUE.to_be_bytes()])
}

/// `TPM2_PolicySecret` (via PolicyUpdate): digest' = H(H(digest ‖ TPM_CC_PolicySecret ‖ name) ‖ policyRef).
#[must_use]
pub fn secret(digest: &Digest, auth_object_name: &[u8], policy_ref: &[u8]) -> Digest {
    let inner = sha256(&[digest, &cc::POLICY_SECRET.to_be_bytes(), auth_object_name]);
    sha256(&[&inner, policy_ref])
}

/// Errors from [`or`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrError {
    /// `TPM2_PolicyOR` takes 2 to 8 branches.
    BranchCount,
}

/// `TPM2_PolicyOR`: digest' = H(0…0 ‖ TPM_CC_PolicyOR ‖ branch₁ ‖ … ‖ branchₙ).
///
/// # Errors
/// [`OrError::BranchCount`] unless there are 2 to 8 branches.
pub fn or(branches: &[Digest]) -> Result<Digest, OrError> {
    if !(2..=8).contains(&branches.len()) {
        return Err(OrError::BranchCount);
    }
    let mut h = Sha256::new();
    h.update(ZERO);
    h.update(cc::POLICY_OR.to_be_bytes());
    for b in branches {
        h.update(b);
    }
    Ok(h.finalize().into())
}

/// The TPM gates a credential key's policy can name (AD-013). A verified PIN unlocks the
/// UV gate: the PIN itself is checked against the DA-protected PIN gate first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyGate {
    Uv,
    Up,
}

impl From<GateKind> for KeyGate {
    fn from(kind: GateKind) -> Self {
        match kind {
            GateKind::Pin | GateKind::Uv => Self::Uv,
            GateKind::Up => Self::Up,
        }
    }
}

/// What a key is for; selects its branches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Sign,
    HmacWithUv,
    HmacWithoutUv,
}

/// `policyRef = SHA-256(tag ‖ rpIdHash)` binds a gate use to one relying party (TPM-06).
#[must_use]
pub fn policy_ref(gate: KeyGate, rp: &RpIdHash) -> Digest {
    let tag: &[u8] = match gate {
        KeyGate::Uv => b"passkey-tpm/v2/gate/uv",
        KeyGate::Up => b"passkey-tpm/v2/gate/up",
    };
    sha256(&[tag, &rp.0])
}

/// TPM Names of one user's key gates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateNames {
    pub uv: Vec<u8>,
    pub up: Vec<u8>,
}

impl GateNames {
    #[must_use]
    pub fn get(&self, gate: KeyGate) -> &[u8] {
        match gate {
            KeyGate::Uv => &self.uv,
            KeyGate::Up => &self.up,
        }
    }
}

/// One branch: `PolicySecret(gate, policyRef(gate, rp))`. No `PolicyCommandCode`: the gate
/// is the security property, and admin-role commands stay blocked because `adminWithPolicy`
/// requires a policy naming the command.
#[must_use]
pub fn branch(names: &GateNames, gate: KeyGate, rp: &RpIdHash) -> Digest {
    secret(&ZERO, names.get(gate), &policy_ref(gate, rp))
}

/// The branches of a key, in a fixed order (the order is part of the digest).
#[must_use]
pub fn gates_for(protect: CredProtect, purpose: Purpose) -> &'static [KeyGate] {
    match purpose {
        Purpose::HmacWithUv => &[KeyGate::Uv],
        Purpose::HmacWithoutUv => &[KeyGate::Up],
        Purpose::Sign if protect == CredProtect::UvRequired => &[KeyGate::Uv],
        Purpose::Sign => &[KeyGate::Uv, KeyGate::Up],
    }
}

/// All branch digests of a key's policy, in order (needed again at use time for PolicyOR).
#[must_use]
pub fn branches(names: &GateNames, rp: &RpIdHash, gates: &[KeyGate]) -> Vec<Digest> {
    gates.iter().map(|g| branch(names, *g, rp)).collect()
}

/// The authPolicy for a key whose branches are `gates`: the single branch, or their PolicyOR.
///
/// # Errors
/// [`OrError::BranchCount`] if `gates` is empty or has more than 8 entries.
pub fn key_policy(names: &GateNames, rp: &RpIdHash, gates: &[KeyGate]) -> Result<Digest, OrError> {
    let b = branches(names, rp, gates);
    match b.as_slice() {
        [only] => Ok(*only),
        _ => or(&b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> GateNames {
        GateNames {
            uv: vec![2; 34],
            up: vec![3; 34],
        }
    }

    #[test]
    fn command_code_matches_spec_layout() {
        // H(0^32 ‖ 0000016C ‖ 0000015D)
        let mut input = vec![0u8; 32];
        input.extend_from_slice(&[0, 0, 1, 0x6c, 0, 0, 1, 0x5d]);
        let expected: Digest = Sha256::digest(&input).into();
        assert_eq!(command_code(&ZERO, cc::SIGN), expected);
    }

    #[test]
    fn policy_ref_depends_on_gate_and_rp() {
        let a = RpIdHash([1; 32]);
        let b = RpIdHash([2; 32]);
        assert_ne!(policy_ref(KeyGate::Uv, &a), policy_ref(KeyGate::Uv, &b));
        assert_ne!(policy_ref(KeyGate::Uv, &a), policy_ref(KeyGate::Up, &a));
    }

    #[test]
    fn pin_unlocks_the_uv_gate() {
        assert_eq!(KeyGate::from(GateKind::Pin), KeyGate::Uv);
        assert_eq!(KeyGate::from(GateKind::Up), KeyGate::Up);
    }

    #[test]
    fn uv_required_has_a_single_branch() {
        assert_eq!(
            gates_for(CredProtect::UvRequired, Purpose::Sign),
            [KeyGate::Uv]
        );
        assert_eq!(
            gates_for(CredProtect::UvOptional, Purpose::Sign),
            [KeyGate::Uv, KeyGate::Up]
        );
        assert_eq!(
            gates_for(CredProtect::UvOptional, Purpose::HmacWithoutUv),
            [KeyGate::Up]
        );
        assert_eq!(
            gates_for(CredProtect::UvRequired, Purpose::HmacWithUv),
            [KeyGate::Uv]
        );
    }

    #[test]
    fn policies_differ_per_rp() {
        let n = names();
        let gates = gates_for(CredProtect::UvOptional, Purpose::Sign);
        let p1 = key_policy(&n, &RpIdHash([1; 32]), gates).unwrap();
        assert_ne!(p1, key_policy(&n, &RpIdHash([2; 32]), gates).unwrap());
    }

    #[test]
    fn or_rejects_bad_branch_counts() {
        assert_eq!(or(&[ZERO]), Err(OrError::BranchCount));
        assert_eq!(or(&[ZERO; 9]), Err(OrError::BranchCount));
        assert!(or(&[ZERO; 2]).is_ok());
    }
}
