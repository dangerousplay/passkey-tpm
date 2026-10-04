//! clientPIN retry counter (CTAP 2.1 §6.5.5).

use vstd::prelude::*;

verus! {

/// Maximum consecutive wrong PINs before the PIN is blocked.
pub const MAX_PIN_RETRIES: u8 = 8;

/// Remaining PIN attempts. Never exceeds [`MAX_PIN_RETRIES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinRetries {
    remaining: u8,
}

impl PinRetries {
    pub closed spec fn view(self) -> nat {
        self.remaining as nat
    }

    pub closed spec fn wf(self) -> bool {
        self.remaining <= MAX_PIN_RETRIES
    }

    pub fn new() -> (r: Self)
        ensures
            r.wf(),
            r.view() == MAX_PIN_RETRIES as nat,
    {
        PinRetries { remaining: MAX_PIN_RETRIES }
    }

    pub fn remaining(&self) -> (n: u8)
        ensures
            n as nat == self.view(),
    {
        self.remaining
    }

    pub fn is_blocked(&self) -> (b: bool)
        ensures
            b == (self.view() == 0),
    {
        self.remaining == 0
    }

    /// Consumes one attempt. Must be called *before* the PIN is compared, so an
    /// interrupted comparison still costs an attempt.
    pub fn consume(&mut self)
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            old(self).view() == 0 ==> final(self).view() == 0,
            old(self).view() > 0 ==> final(self).view() == old(self).view() - 1,
    {
        if self.remaining > 0 {
            self.remaining -= 1;
        }
    }

    /// Restores all attempts after a correct PIN.
    pub fn reset(&mut self)
        ensures
            final(self).wf(),
            final(self).view() == MAX_PIN_RETRIES as nat,
    {
        self.remaining = MAX_PIN_RETRIES;
    }
}

impl Default for PinRetries {
    fn default() -> Self {
        Self::new()
    }
}

} // verus!

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_max_failures_and_saturates() {
        let mut r = PinRetries::new();
        for _ in 0..MAX_PIN_RETRIES {
            assert!(!r.is_blocked());
            r.consume();
        }
        assert!(r.is_blocked());
        r.consume();
        assert_eq!(r.remaining(), 0);
        r.reset();
        assert_eq!(r.remaining(), MAX_PIN_RETRIES);
    }
}
