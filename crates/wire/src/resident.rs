//! Discoverable credential store `resident.v1` (MVP-2 task R, M2-09, M2-11).
//!
//! Per-user metadata for discoverable (`rk: true`) credentials, kept by the broker under
//! `/var/lib/passkey-tpm/<uid>/` with mode 0600. It holds no secrets: the credential IDs
//! carry TPM-wrapped blobs whose policy binds them to the RP and the user (see
//! [`crate::credid`]).
//!
//! ```text
//! b"PKTR"  magic
//! u8       version = 1
//! u16      entry count (big-endian, <= MAX_ENTRIES)
//! per entry:
//!   u16-len rp_id              UTF-8, 1..=253 bytes
//!   u16-len rp_name            UTF-8, 0..=64 bytes
//!   u16-len user_id            1..=64 bytes
//!   u16-len user_name          UTF-8, 0..=64 bytes
//!   u16-len user_display_name  UTF-8, 0..=64 bytes
//!   u16-len credential_id      1..=1023 bytes
//!   u64     created            unix seconds, big-endian
//! ```
//!
//! Invariants enforced by both [`encode`] and [`decode`]: at most [`MAX_ENTRIES`] entries,
//! every field within its range, no two entries with the same `(rp_id, user_id)` and no two
//! with the same `credential_id`.

use core::ops::RangeInclusive;

use crate::reader::{Reader, Truncated};

pub const MAGIC: [u8; 4] = *b"PKTR";
pub const VERSION: u8 = 1;
/// At most this many discoverable credentials per user.
pub const MAX_ENTRIES: usize = 64;
/// DNS names are at most 253 bytes.
pub const MAX_RP_ID_LEN: usize = 253;
/// CTAP 2.1 §6.1.2 lets authenticators truncate names to 64 bytes.
pub const MAX_NAME_LEN: usize = 64;
/// WebAuthn limits `user.id` to 64 bytes.
pub const MAX_USER_ID_LEN: usize = 64;
/// WebAuthn L3 limits credential IDs to 1023 bytes.
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;

const RP_ID: RangeInclusive<usize> = 1..=MAX_RP_ID_LEN;
const NAME: RangeInclusive<usize> = 0..=MAX_NAME_LEN;
const USER_ID: RangeInclusive<usize> = 1..=MAX_USER_ID_LEN;
const CREDENTIAL_ID: RangeInclusive<usize> = 1..=MAX_CREDENTIAL_ID_LEN;

const HEADER_LEN: usize = 4 + 1 + 2;
const MAX_ENTRY_LEN: usize = 6 * 2
    + MAX_RP_ID_LEN
    + MAX_NAME_LEN
    + MAX_USER_ID_LEN
    + MAX_NAME_LEN
    + MAX_NAME_LEN
    + MAX_CREDENTIAL_ID_LEN
    + 8;
/// Largest valid file: a full store with every field at its maximum length.
pub const MAX_LEN: usize = HEADER_LEN + MAX_ENTRIES * MAX_ENTRY_LEN;

/// One discoverable credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidentEntry {
    pub rp_id: String,
    pub rp_name: String,
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    pub credential_id: Vec<u8>,
    /// Creation time, unix seconds.
    pub created: u64,
}

impl ResidentEntry {
    fn same_user(&self, rp_id: &str, user_id: &[u8]) -> bool {
        self.rp_id == rp_id && self.user_id == user_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    TooLong,
    BadMagic,
    UnknownVersion,
    TooManyEntries,
    FieldLength,
    InvalidUtf8,
    DuplicateUser,
    DuplicateCredential,
    TrailingBytes,
}

impl From<Truncated> for DecodeError {
    fn from(_: Truncated) -> Self {
        Self::Truncated
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    TooManyEntries,
    FieldLength,
    DuplicateUser,
    DuplicateCredential,
}

/// The store already holds [`MAX_ENTRIES`] credentials (`CTAP2_ERR_KEY_STORE_FULL`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreFull;

enum Duplicate {
    User,
    Credential,
}

/// Checks `e` against the entries already accepted.
fn check_unique(accepted: &[ResidentEntry], e: &ResidentEntry) -> Result<(), Duplicate> {
    for other in accepted {
        if other.same_user(&e.rp_id, &e.user_id) {
            return Err(Duplicate::User);
        }
        if other.credential_id == e.credential_id {
            return Err(Duplicate::Credential);
        }
    }
    Ok(())
}

fn put_field(
    out: &mut Vec<u8>,
    bytes: &[u8],
    range: &RangeInclusive<usize>,
) -> Result<(), EncodeError> {
    if !range.contains(&bytes.len()) {
        return Err(EncodeError::FieldLength);
    }
    let len = u16::try_from(bytes.len()).map_err(|_| EncodeError::FieldLength)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Serialises a store.
///
/// # Errors
/// [`EncodeError`] if there are more than [`MAX_ENTRIES`] entries, a field is out of range,
/// or two entries share `(rp_id, user_id)` or `credential_id`.
pub fn encode(entries: &[ResidentEntry]) -> Result<Vec<u8>, EncodeError> {
    if entries.len() > MAX_ENTRIES {
        return Err(EncodeError::TooManyEntries);
    }
    let count = u16::try_from(entries.len()).map_err(|_| EncodeError::TooManyEntries)?;
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&count.to_be_bytes());
    for (i, e) in entries.iter().enumerate() {
        let accepted = entries.get(..i).unwrap_or_default();
        check_unique(accepted, e).map_err(|kind| match kind {
            Duplicate::User => EncodeError::DuplicateUser,
            Duplicate::Credential => EncodeError::DuplicateCredential,
        })?;
        put_field(&mut out, e.rp_id.as_bytes(), &RP_ID)?;
        put_field(&mut out, e.rp_name.as_bytes(), &NAME)?;
        put_field(&mut out, &e.user_id, &USER_ID)?;
        put_field(&mut out, e.user_name.as_bytes(), &NAME)?;
        put_field(&mut out, e.user_display_name.as_bytes(), &NAME)?;
        put_field(&mut out, &e.credential_id, &CREDENTIAL_ID)?;
        out.extend_from_slice(&e.created.to_be_bytes());
    }
    Ok(out)
}

fn field<'a>(r: &mut Reader<'a>, range: &RangeInclusive<usize>) -> Result<&'a [u8], DecodeError> {
    let bytes = r.len16_prefixed()?;
    if !range.contains(&bytes.len()) {
        return Err(DecodeError::FieldLength);
    }
    Ok(bytes)
}

fn text(r: &mut Reader<'_>, range: &RangeInclusive<usize>) -> Result<String, DecodeError> {
    let bytes = field(r, range)?;
    core::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| DecodeError::InvalidUtf8)
}

fn u64_be(r: &mut Reader<'_>) -> Result<u64, DecodeError> {
    let array: [u8; 8] = r.take(8)?.try_into().map_err(|_| DecodeError::Truncated)?;
    Ok(u64::from_be_bytes(array))
}

/// Parses a store read from disk. A corrupt file is an error, never an empty store.
///
/// # Errors
/// Any [`DecodeError`]; never panics.
pub fn decode(bytes: &[u8]) -> Result<Vec<ResidentEntry>, DecodeError> {
    if bytes.len() > MAX_LEN {
        return Err(DecodeError::TooLong);
    }
    let mut r = Reader::new(bytes);
    if r.take(4)? != MAGIC.as_slice() {
        return Err(DecodeError::BadMagic);
    }
    if r.u8()? != VERSION {
        return Err(DecodeError::UnknownVersion);
    }
    let count = usize::from(r.u16_be()?);
    if count > MAX_ENTRIES {
        return Err(DecodeError::TooManyEntries);
    }
    let mut entries: Vec<ResidentEntry> = Vec::with_capacity(count);
    for _ in 0..count {
        let e = ResidentEntry {
            rp_id: text(&mut r, &RP_ID)?,
            rp_name: text(&mut r, &NAME)?,
            user_id: field(&mut r, &USER_ID)?.to_vec(),
            user_name: text(&mut r, &NAME)?,
            user_display_name: text(&mut r, &NAME)?,
            credential_id: field(&mut r, &CREDENTIAL_ID)?.to_vec(),
            created: u64_be(&mut r)?,
        };
        check_unique(&entries, &e).map_err(|kind| match kind {
            Duplicate::User => DecodeError::DuplicateUser,
            Duplicate::Credential => DecodeError::DuplicateCredential,
        })?;
        entries.push(e);
    }
    if !r.is_empty() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(entries)
}

/// Inserts `e`, replacing the entry with the same `(rp_id, user_id)` in place if there is one
/// (CTAP 2.1 §6.1.2).
///
/// # Errors
/// [`StoreFull`] if `e` is new and the store already holds [`MAX_ENTRIES`] entries.
pub fn upsert(entries: &mut Vec<ResidentEntry>, e: ResidentEntry) -> Result<(), StoreFull> {
    if let Some(slot) = entries
        .iter_mut()
        .find(|old| old.same_user(&e.rp_id, &e.user_id))
    {
        *slot = e;
        return Ok(());
    }
    if entries.len() >= MAX_ENTRIES {
        return Err(StoreFull);
    }
    entries.push(e);
    Ok(())
}

/// Entries for `rp_id`, most recent first: `created` descending, ties broken by later
/// insertion first (getAssertion without an allowList, enumerateCredentials).
#[must_use]
pub fn for_rp<'a>(entries: &'a [ResidentEntry], rp_id: &str) -> Vec<&'a ResidentEntry> {
    // Reverse insertion order first; the stable sort keeps it among equal timestamps.
    let mut found: Vec<&ResidentEntry> =
        entries.iter().rev().filter(|e| e.rp_id == rp_id).collect();
    found.sort_by_key(|e| core::cmp::Reverse(e.created));
    found
}

/// Distinct `(rp_id, rp_name)` pairs in first-seen order (enumerateRPs). The name is the one
/// stored with the first entry for that RP.
#[must_use]
pub fn rps(entries: &[ResidentEntry]) -> Vec<(&str, &str)> {
    let mut out: Vec<(&str, &str)> = Vec::new();
    for e in entries {
        if !out.iter().any(|(id, _)| *id == e.rp_id) {
            out.push((&e.rp_id, &e.rp_name));
        }
    }
    out
}

/// Removes the entry with `credential_id`; returns whether one was found (deleteCredential).
pub fn remove_credential(entries: &mut Vec<ResidentEntry>, credential_id: &[u8]) -> bool {
    let before = entries.len();
    entries.retain(|e| e.credential_id != credential_id);
    entries.len() != before
}

/// Truncates `s` to at most `max` bytes without splitting a character (CTAP 2.1 §6.1.2 lets
/// authenticators store rp/user names truncated to 64 bytes).
#[must_use]
pub fn truncate_utf8(s: &str, max: usize) -> String {
    let mut end = max.min(s.len());
    while !s.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    s.get(..end).unwrap_or_default().to_owned()
}

#[cfg(kani)]
mod proofs {
    use super::*;

    // A whole-`decode` harness (Vec<ResidentEntry> of symbolic length, String drop glue)
    // exhausts CBMC memory even at 10 bytes; panic-freedom of `decode` is covered by the
    // `resident_decode` fuzz target and the proptest, and its only parsing primitive beyond
    // `Reader` (already proven) is checked here.

    /// Every field decoder (length prefix, range check, UTF-8) on short symbolic input.
    #[kani::proof]
    #[kani::unwind(8)]
    fn text_never_panics_and_respects_range() {
        let buf: [u8; 6] = kani::any();
        let len: usize = kani::any_where(|l| *l <= 6);
        let mut r = Reader::new(&buf[..len]);
        if let Ok(s) = text(&mut r, &RP_ID) {
            assert!(RP_ID.contains(&s.len()));
            assert!(s.len() + 2 + r.remaining() == len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn entry(rp: &str, user: &[u8], cred: &[u8], created: u64) -> ResidentEntry {
        ResidentEntry {
            rp_id: rp.to_owned(),
            rp_name: format!("{rp} name"),
            user_id: user.to_vec(),
            user_name: "alice".to_owned(),
            user_display_name: "Alice Ação".to_owned(),
            credential_id: cred.to_vec(),
            created,
        }
    }

    fn sample() -> Vec<ResidentEntry> {
        vec![
            entry("example.com", b"u1", b"c1", 10),
            entry("example.org", b"u1", b"c2", 20),
        ]
    }

    fn header(count: u16) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.push(VERSION);
        out.extend_from_slice(&count.to_be_bytes());
        out
    }

    fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_be_bytes());
        out.extend_from_slice(bytes);
    }

    /// Hand-built single entry with raw fields, bypassing `encode`'s checks.
    fn raw(fields: [&[u8]; 6]) -> Vec<u8> {
        let mut out = header(1);
        for f in fields {
            push_field(&mut out, f);
        }
        out.extend_from_slice(&7u64.to_be_bytes());
        out
    }

    const GOOD: [&[u8]; 6] = [b"rp", b"", b"u", b"", b"", b"c"];

    #[test]
    fn round_trip_and_empty_store() {
        let entries = sample();
        assert_eq!(decode(&encode(&entries).unwrap()), Ok(entries));
        assert_eq!(encode(&[]).unwrap(), header(0));
        assert_eq!(decode(&header(0)), Ok(vec![]));
        assert_eq!(decode(&raw(GOOD)).unwrap().len(), 1);
    }

    #[test]
    fn max_len_matches_a_full_store() {
        let full: Vec<ResidentEntry> = (0..MAX_ENTRIES)
            .map(|i| {
                let tag = u8::try_from(i).unwrap();
                let mut cred = vec![0xcc; MAX_CREDENTIAL_ID_LEN];
                cred[0] = tag;
                ResidentEntry {
                    rp_id: "r".repeat(MAX_RP_ID_LEN),
                    rp_name: "n".repeat(MAX_NAME_LEN),
                    user_id: vec![tag; MAX_USER_ID_LEN],
                    user_name: "u".repeat(MAX_NAME_LEN),
                    user_display_name: "d".repeat(MAX_NAME_LEN),
                    credential_id: cred,
                    created: u64::MAX,
                }
            })
            .collect();
        let bytes = encode(&full).unwrap();
        assert_eq!(bytes.len(), MAX_LEN);
        assert_eq!(decode(&bytes), Ok(full));
    }

    #[test]
    fn header_rejections() {
        let good = encode(&sample()).unwrap();
        let mut magic = good.clone();
        magic[0] = b'X';
        assert_eq!(decode(&magic), Err(DecodeError::BadMagic));
        let mut version = good.clone();
        version[4] = 2;
        assert_eq!(decode(&version), Err(DecodeError::UnknownVersion));
        let too_many = u16::try_from(MAX_ENTRIES + 1).unwrap();
        assert_eq!(decode(&header(too_many)), Err(DecodeError::TooManyEntries));
        assert_eq!(decode(&[]), Err(DecodeError::Truncated));
        assert_eq!(decode(&good[..good.len() - 1]), Err(DecodeError::Truncated));
        assert_eq!(decode(&header(1)), Err(DecodeError::Truncated));
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(decode(&trailing), Err(DecodeError::TrailingBytes));
        assert_eq!(decode(&vec![0; MAX_LEN + 1]), Err(DecodeError::TooLong));
    }

    #[test]
    fn field_length_rejections() {
        let long_rp = vec![b'r'; MAX_RP_ID_LEN + 1];
        let long_name = vec![b'n'; MAX_NAME_LEN + 1];
        let long_user = vec![1; MAX_USER_ID_LEN + 1];
        let long_cred = vec![1; MAX_CREDENTIAL_ID_LEN + 1];
        let cases: [(usize, &[u8]); 9] = [
            (0, b""),
            (0, &long_rp),
            (1, &long_name),
            (2, b""),
            (2, &long_user),
            (3, &long_name),
            (4, &long_name),
            (5, b""),
            (5, &long_cred),
        ];
        for (index, value) in cases {
            let mut fields = GOOD;
            fields[index] = value;
            assert_eq!(
                decode(&raw(fields)),
                Err(DecodeError::FieldLength),
                "field {index}"
            );
        }
        // Boundary values are accepted.
        let max_rp = vec![b'r'; MAX_RP_ID_LEN];
        let max_name = vec![b'n'; MAX_NAME_LEN];
        let max_user = vec![1; MAX_USER_ID_LEN];
        let max_cred = vec![1; MAX_CREDENTIAL_ID_LEN];
        let max = raw([
            &max_rp, &max_name, &max_user, &max_name, &max_name, &max_cred,
        ]);
        assert!(decode(&max).is_ok());
    }

    #[test]
    fn invalid_utf8_rejected_in_every_text_field() {
        for index in [0, 1, 3, 4] {
            let mut fields = GOOD;
            fields[index] = b"\xff";
            assert_eq!(
                decode(&raw(fields)),
                Err(DecodeError::InvalidUtf8),
                "field {index}"
            );
        }
        // user_id is opaque bytes.
        let mut fields = GOOD;
        fields[2] = b"\xff";
        assert!(decode(&raw(fields)).is_ok());
    }

    #[test]
    fn duplicates_rejected() {
        let two = |a: (&[u8], &[u8]), b: (&[u8], &[u8])| {
            let mut out = header(2);
            for (user, cred) in [a, b] {
                for f in [&b"rp"[..], b"", user, b"", b"", cred] {
                    push_field(&mut out, f);
                }
                out.extend_from_slice(&1u64.to_be_bytes());
            }
            out
        };
        let same_user = two((b"u1", b"c1"), (b"u1", b"c2"));
        let same_cred = two((b"u1", b"c1"), (b"u2", b"c1"));
        assert_eq!(decode(&same_user), Err(DecodeError::DuplicateUser));
        assert_eq!(decode(&same_cred), Err(DecodeError::DuplicateCredential));

        // The same user id under different RPs is fine.
        assert!(decode(&encode(&sample()).unwrap()).is_ok());
    }

    #[test]
    fn encode_rejections() {
        let e = entry("rp", b"u", b"c", 1);
        let too_many = vec![e.clone(); MAX_ENTRIES + 1];
        assert_eq!(encode(&too_many), Err(EncodeError::TooManyEntries));
        let bad = ResidentEntry {
            rp_name: "x".repeat(MAX_NAME_LEN + 1),
            ..e.clone()
        };
        assert_eq!(encode(&[bad]), Err(EncodeError::FieldLength));
        let other_cred = ResidentEntry {
            credential_id: b"d".to_vec(),
            ..e.clone()
        };
        assert_eq!(
            encode(&[e.clone(), other_cred]),
            Err(EncodeError::DuplicateUser)
        );
        let other_user = ResidentEntry {
            user_id: b"v".to_vec(),
            ..e.clone()
        };
        assert_eq!(
            encode(&[e, other_user]),
            Err(EncodeError::DuplicateCredential)
        );
    }

    #[test]
    fn upsert_replaces_in_place_and_reports_full() {
        let mut entries = sample();
        let replacement = entry("example.com", b"u1", b"c9", 99);
        upsert(&mut entries, replacement.clone()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], replacement);

        let mut full: Vec<ResidentEntry> = (0..MAX_ENTRIES)
            .map(|i| {
                let i = u8::try_from(i).unwrap();
                entry("rp", &[i], &[i], 0)
            })
            .collect();
        assert_eq!(
            upsert(&mut full, entry("rp", b"new", b"new", 0)),
            Err(StoreFull)
        );
        assert_eq!(full.len(), MAX_ENTRIES);
        // Replacing still works when full.
        assert_eq!(upsert(&mut full, entry("rp", &[3], b"new", 5)), Ok(()));
        assert_eq!(full[3].created, 5);
    }

    #[test]
    fn for_rp_is_most_recent_first() {
        let entries = vec![
            entry("a", b"1", b"c1", 5),
            entry("b", b"1", b"c2", 100),
            entry("a", b"2", b"c3", 9),
            entry("a", b"3", b"c4", 5),
            entry("a", b"4", b"c5", 1),
        ];
        let ids: Vec<&[u8]> = for_rp(&entries, "a")
            .iter()
            .map(|e| e.credential_id.as_slice())
            .collect();
        assert_eq!(ids, [&b"c3"[..], b"c4", b"c1", b"c5"]);
        assert!(for_rp(&entries, "zzz").is_empty());
    }

    #[test]
    fn rps_unique_in_first_seen_order() {
        let entries = vec![
            entry("b", b"1", b"c1", 0),
            entry("a", b"1", b"c2", 0),
            entry("b", b"2", b"c3", 0),
        ];
        assert_eq!(rps(&entries), [("b", "b name"), ("a", "a name")]);
    }

    #[test]
    fn remove_credential_reports_presence() {
        let mut entries = sample();
        assert!(remove_credential(&mut entries, b"c1"));
        assert!(!remove_credential(&mut entries, b"c1"));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].credential_id, b"c2");
    }

    #[test]
    fn truncate_utf8_respects_char_boundaries() {
        assert_eq!(truncate_utf8("hello", 64), "hello");
        assert_eq!(truncate_utf8("hello", 3), "hel");
        assert_eq!(truncate_utf8("hello", 0), "");
        // "é" is 2 bytes, "€" 3, "😀" 4.
        assert_eq!(truncate_utf8("aé", 2), "a");
        assert_eq!(truncate_utf8("aé", 3), "aé");
        assert_eq!(truncate_utf8("€€", 5), "€");
        assert_eq!(truncate_utf8("😀😀", 7), "😀");
        assert_eq!(truncate_utf8("😀", 3), "");
        assert_eq!(truncate_utf8(&"ç".repeat(40), MAX_NAME_LEN).len(), 64);
        assert_eq!(truncate_utf8(&"€".repeat(30), MAX_NAME_LEN).len(), 63);
    }

    fn arb_entry() -> impl Strategy<Value = ResidentEntry> {
        (
            "[a-z0-9.é€😀-]{1,60}",
            "[ -~éç€😀]{0,16}",
            prop::collection::vec(any::<u8>(), 1..=MAX_USER_ID_LEN),
            "[ -~éç€😀]{0,16}",
            "[ -~éç€😀]{0,16}",
            prop::collection::vec(any::<u8>(), 1..=200),
            any::<u64>(),
        )
            .prop_map(
                |(
                    rp_id,
                    rp_name,
                    user_id,
                    user_name,
                    user_display_name,
                    credential_id,
                    created,
                )| {
                    ResidentEntry {
                        rp_id,
                        rp_name,
                        user_id,
                        user_name,
                        user_display_name,
                        credential_id,
                        created,
                    }
                },
            )
    }

    /// Entries within limits, keeping only the first of any duplicate key.
    fn arb_store() -> impl Strategy<Value = Vec<ResidentEntry>> {
        prop::collection::vec(arb_entry(), 0..=12).prop_map(|all| {
            let mut out: Vec<ResidentEntry> = Vec::new();
            for e in all {
                let dup = out.iter().any(|o| {
                    o.same_user(&e.rp_id, &e.user_id) || o.credential_id == e.credential_id
                });
                if !dup {
                    out.push(e);
                }
            }
            out
        })
    }

    proptest! {
        #[test]
        fn round_trip_generated(entries in arb_store()) {
            let bytes = encode(&entries).unwrap();
            prop_assert!(bytes.len() <= MAX_LEN);
            prop_assert_eq!(decode(&bytes), Ok(entries));
        }

        #[test]
        fn decode_never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
            if let Ok(entries) = decode(&bytes) {
                prop_assert_eq!(encode(&entries), Ok(bytes));
            }
        }

        #[test]
        fn truncate_utf8_is_a_maximal_prefix(s in "\\PC{0,40}", max in 0usize..100) {
            let cut = truncate_utf8(&s, max);
            prop_assert!(cut.len() <= max);
            prop_assert!(s.starts_with(&cut));
            if let Some(next) = s.get(cut.len()..).and_then(|rest| rest.chars().next()) {
                prop_assert!(cut.len().saturating_add(next.len_utf8()) > max);
            }
        }
    }
}
