//! pinUvAuthToken state (CTAP 2.1 §6.5.2.4, M2-05).
//!
//! The grant (permissions, rpId binding, UV/UP flags, issue time) is verified with Verus;
//! the 32 secret bytes live outside `verus!` in a zeroizing wrapper.

use vstd::prelude::*;
use zeroize::Zeroizing;

verus! {

/// Permission bits (CTAP 2.1 §6.5.5.7).
pub const PERM_MC: u8 = 0x01;
pub const PERM_GA: u8 = 0x02;
pub const PERM_CM: u8 = 0x04;
pub const PERM_BE: u8 = 0x08;
pub const PERM_LBW: u8 = 0x10;
pub const PERM_ACFG: u8 = 0x20;
/// Permissions this authenticator can grant (mc, ga, cm).
pub const SUPPORTED_PERMS: u8 = 0x07;
/// A token is usable for at most 10 minutes after it is issued.
pub const TOKEN_LIFETIME_MS: u64 = 600_000;
/// Consecutive PIN mismatches per broker start before PIN_AUTH_BLOCKED.
pub const MAX_BOOT_MISMATCHES: u8 = 3;

pub open spec fn spec_rp_ok(bound: Option<[u8; 32]>, rp: [u8; 32]) -> bool {
    match bound {
        None => true,
        Some(b) => b == rp,
    }
}

#[allow(clippy::indexing_slicing)] // Verus proves bounds
fn eq32(a: &[u8; 32], b: &[u8; 32]) -> (r: bool)
    ensures
        r == (*a == *b),
{
    let mut i: usize = 0;
    while i < 32
        invariant
            0 <= i <= 32,
            forall|j: int| 0 <= j < i ==> a[j] == b[j],
        decreases 32 - i,
    {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    assert(a@ =~= b@);
    assert(*a =~= *b);
    true
}

/// What a token permits, and what it attests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenGrant {
    permissions: u8,
    rp_id_hash: Option<[u8; 32]>,
    user_verified: bool,
    user_present: bool,
    issued_ms: u64,
}

impl TokenGrant {
    pub closed spec fn spec_permissions(&self) -> u8 {
        self.permissions
    }

    pub closed spec fn spec_rp(&self) -> Option<[u8; 32]> {
        self.rp_id_hash
    }

    pub closed spec fn spec_user_present(&self) -> bool {
        self.user_present
    }

    pub closed spec fn spec_user_verified(&self) -> bool {
        self.user_verified
    }

    pub closed spec fn spec_issued(&self) -> u64 {
        self.issued_ms
    }

    pub fn new(permissions: u8, rp_id_hash: Option<[u8; 32]>, user_verified: bool, user_present: bool, now_ms: u64) -> (g: Self)
        ensures
            g.spec_permissions() == permissions,
            g.spec_rp() == rp_id_hash,
            g.spec_user_verified() == user_verified,
            g.spec_user_present() == user_present,
            g.spec_issued() == now_ms,
    {
        TokenGrant { permissions, rp_id_hash, user_verified, user_present, issued_ms: now_ms }
    }

    /// Permits operation `perm` (a single bit) for relying party `rp` at time `now_ms`.
    pub fn allows(&self, perm: u8, rp: &[u8; 32], now_ms: u64) -> (b: bool)
        ensures
            b ==> perm != 0,
            b ==> (self.spec_permissions() & perm) == perm,
            b ==> spec_rp_ok(self.spec_rp(), *rp),
            b ==> now_ms >= self.spec_issued() && now_ms - self.spec_issued() <= TOKEN_LIFETIME_MS,
    {
        if perm == 0 || (self.permissions & perm) != perm {
            return false;
        }
        if now_ms < self.issued_ms || now_ms - self.issued_ms > TOKEN_LIFETIME_MS {
            return false;
        }
        match &self.rp_id_hash {
            None => true,
            Some(bound) => eq32(bound, rp),
        }
    }

    /// Permits an RP-less operation `perm` (credential-management metadata and RP
    /// enumeration): only tokens not bound to a relying party qualify.
    pub fn allows_unbound(&self, perm: u8, now_ms: u64) -> (b: bool)
        ensures
            b ==> perm != 0,
            b ==> (self.spec_permissions() & perm) == perm,
            b ==> self.spec_rp().is_none(),
            b ==> now_ms >= self.spec_issued() && now_ms - self.spec_issued() <= TOKEN_LIFETIME_MS,
    {
        if perm == 0 || (self.permissions & perm) != perm || self.rp_id_hash.is_some() {
            return false;
        }
        now_ms >= self.issued_ms && now_ms - self.issued_ms <= TOKEN_LIFETIME_MS
    }

    /// True if the token still carries a presence gesture; clears it (one use).
    pub fn take_user_present(&mut self) -> (up: bool)
        ensures
            up == old(self).spec_user_present(),
            !final(self).spec_user_present(),
            final(self).spec_permissions() == old(self).spec_permissions(),
            final(self).spec_rp() == old(self).spec_rp(),
            final(self).spec_user_verified() == old(self).spec_user_verified(),
            final(self).spec_issued() == old(self).spec_issued(),
    {
        let up = self.user_present;
        self.user_present = false;
        up
    }

    pub fn user_verified(&self) -> (uv: bool)
        ensures
            uv == self.spec_user_verified(),
    {
        self.user_verified
    }

    /// Binds an unbound token to `rp` on first use (CTAP 2.1 §6.1.2 step 9.d.ii).
    pub fn bind_rp(&mut self, rp: &[u8; 32])
        ensures
            old(self).spec_rp().is_none() ==> final(self).spec_rp() == Some(*rp),
            old(self).spec_rp().is_some() ==> final(self).spec_rp() == old(self).spec_rp(),
            final(self).spec_permissions() == old(self).spec_permissions(),
            final(self).spec_user_present() == old(self).spec_user_present(),
            final(self).spec_user_verified() == old(self).spec_user_verified(),
            final(self).spec_issued() == old(self).spec_issued(),
    {
        if self.rp_id_hash.is_none() {
            self.rp_id_hash = Some(*rp);
        }
    }
}

/// Consecutive wrong PINs since the broker started (CTAP 2.1 §6.5.5.7.2 "power cycle").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BootMismatches {
    count: u8,
}

impl BootMismatches {
    pub closed spec fn view(&self) -> nat {
        self.count as nat
    }

    pub fn blocked(&self) -> (b: bool)
        ensures
            b == (self.view() >= MAX_BOOT_MISMATCHES as nat),
    {
        self.count >= MAX_BOOT_MISMATCHES
    }

    /// Records a mismatch; returns true if the PIN is now blocked until restart.
    pub fn record(&mut self) -> (blocked: bool)
        ensures
            old(self).view() < MAX_BOOT_MISMATCHES as nat ==> final(self).view() == old(self).view() + 1,
            old(self).view() >= MAX_BOOT_MISMATCHES as nat ==> final(self).view() == old(self).view(),
            blocked == (final(self).view() >= MAX_BOOT_MISMATCHES as nat),
    {
        if self.count < MAX_BOOT_MISMATCHES {
            self.count += 1;
        }
        self.count >= MAX_BOOT_MISMATCHES
    }

    pub fn reset(&mut self)
        ensures
            final(self).view() == 0,
    {
        self.count = 0;
    }
}

} // verus!

/// A pinUvAuthToken: secret bytes plus its verified grant.
#[derive(Debug)]
pub struct PinUvAuthToken {
    secret: Zeroizing<[u8; 32]>,
    pub grant: TokenGrant,
}

impl PinUvAuthToken {
    #[must_use]
    pub fn new(secret: Zeroizing<[u8; 32]>, grant: TokenGrant) -> Self {
        Self { secret, grant }
    }

    #[must_use]
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_rp_and_expiry() {
        let rp = [1u8; 32];
        let g = TokenGrant::new(PERM_MC | PERM_GA, None, true, true, 1_000);
        assert!(g.allows(PERM_MC, &rp, 1_000));
        assert!(g.allows(PERM_GA, &rp, 1_000 + TOKEN_LIFETIME_MS));
        assert!(!g.allows(PERM_CM, &rp, 1_000));
        assert!(!g.allows(0, &rp, 1_000));
        assert!(
            !g.allows(PERM_MC, &rp, 1_001 + TOKEN_LIFETIME_MS),
            "expired"
        );
        assert!(!g.allows(PERM_MC, &rp, 999), "clock went backwards");
        let mut bound = g;
        bound.bind_rp(&rp);
        assert!(bound.allows(PERM_MC, &rp, 1_000));
        assert!(
            !bound.allows(PERM_MC, &[2u8; 32], 1_000),
            "bound to another RP"
        );
        bound.bind_rp(&[2u8; 32]);
        assert!(
            !bound.allows(PERM_MC, &[2u8; 32], 1_000),
            "binding is permanent"
        );
    }

    #[test]
    fn user_presence_is_consumed_once() {
        let mut g = TokenGrant::new(PERM_GA, None, true, true, 0);
        assert!(g.take_user_present());
        assert!(!g.take_user_present());
        assert!(g.user_verified());
    }

    #[test]
    fn three_mismatches_block_until_restart() {
        let mut m = BootMismatches::default();
        assert!(!m.record());
        assert!(!m.record());
        assert!(m.record());
        assert!(m.blocked());
        m.reset();
        assert!(!m.blocked());
    }
}
