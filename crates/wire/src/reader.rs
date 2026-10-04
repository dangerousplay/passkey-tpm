//! Bounds-checked cursor over untrusted input.

/// Error returned when input ends before a read completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncated;

/// A forward-only cursor that never reads past the end of its buffer.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    #[must_use]
    pub fn new(input: &'a [u8]) -> Self {
        Self { rest: input }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.rest.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// Consumes exactly `n` bytes.
    ///
    /// # Errors
    /// [`Truncated`] if fewer than `n` bytes remain; the cursor is left unchanged.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Truncated> {
        let (head, tail) = self.rest.split_at_checked(n).ok_or(Truncated)?;
        self.rest = tail;
        Ok(head)
    }

    /// # Errors
    /// [`Truncated`] if the input is empty.
    pub fn u8(&mut self) -> Result<u8, Truncated> {
        let (&first, tail) = self.rest.split_first().ok_or(Truncated)?;
        self.rest = tail;
        Ok(first)
    }

    /// Big-endian `u16`.
    ///
    /// # Errors
    /// [`Truncated`] if fewer than 2 bytes remain.
    pub fn u16_be(&mut self) -> Result<u16, Truncated> {
        let bytes = self.take(2)?;
        let array: [u8; 2] = bytes.try_into().map_err(|_| Truncated)?;
        Ok(u16::from_be_bytes(array))
    }

    /// A `u16`-big-endian length followed by that many bytes (TPM2B layout).
    ///
    /// # Errors
    /// [`Truncated`] if the prefix or the body is incomplete; the cursor is left unchanged.
    pub fn len16_prefixed(&mut self) -> Result<&'a [u8], Truncated> {
        let mut probe = self.clone();
        let len = probe.u16_be()?;
        let body = probe.take(usize::from(len))?;
        *self = probe;
        Ok(body)
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    const MAX: usize = 8;

    #[kani::proof]
    #[kani::unwind(10)]
    fn len16_prefixed_never_panics_and_respects_bounds() {
        let buf: [u8; MAX] = kani::any();
        let len: usize = kani::any_where(|l| *l <= MAX);
        let input = &buf[..len];
        let mut r = Reader::new(input);
        let before = r.remaining();
        match r.len16_prefixed() {
            Ok(body) => {
                assert!(body.len() + 2 <= before);
                assert_eq!(r.remaining(), before - 2 - body.len());
            }
            Err(Truncated) => assert_eq!(r.remaining(), before),
        }
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn take_never_overreads() {
        let buf: [u8; MAX] = kani::any();
        let len: usize = kani::any_where(|l| *l <= MAX);
        let n: usize = kani::any();
        let mut r = Reader::new(&buf[..len]);
        match r.take(n) {
            Ok(head) => {
                assert_eq!(head.len(), n);
                assert_eq!(r.remaining(), len - n);
            }
            Err(Truncated) => {
                assert!(n > len);
                assert_eq!(r.remaining(), len);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_prefixed_body_and_leaves_rest() {
        let mut r = Reader::new(&[0, 2, 0xaa, 0xbb, 0xcc]);
        assert_eq!(r.len16_prefixed(), Ok(&[0xaa, 0xbb][..]));
        assert_eq!(r.u8(), Ok(0xcc));
        assert!(r.is_empty());
    }

    #[test]
    fn truncated_prefix_does_not_consume() {
        let mut r = Reader::new(&[0, 5, 1, 2]);
        assert_eq!(r.len16_prefixed(), Err(Truncated));
        assert_eq!(r.remaining(), 4);
    }
}
