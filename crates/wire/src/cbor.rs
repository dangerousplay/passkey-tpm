//! Minimal CTAP2 canonical CBOR (RFC 8949 subset).
//!
//! CTAP2 messages use a small, deterministic slice of CBOR: unsigned and negative integers,
//! byte and text strings, arrays, maps, `false`, `true` and `null`, all with definite lengths.
//! [`decode`] accepts exactly that slice from untrusted input and enforces hard resource
//! limits; [`encode`] emits the CTAP2 canonical form (shortest heads, map keys sorted
//! length-first, then bytewise).
//!
//! ```text
//! head   = major (3 bits) | info (5 bits) [ argument: 0, 1, 2, 4 or 8 bytes, big-endian ]
//! major  0 uint, 1 nint (-1 - arg), 2 bytes, 3 text, 4 array, 5 map, 7 simple
//! info   0..=23 inline argument, 24/25/26/27 one/two/four/eight-byte argument
//! ```
//!
//! Rejected on decode: indefinite lengths, tags (major 6), floats and simple values other
//! than `false`/`true`/`null`, non-shortest heads, invalid UTF-8, duplicate map keys,
//! trailing bytes, and anything exceeding [`MAX_INPUT`], [`MAX_DEPTH`] or [`MAX_ITEMS`].
//! Map key order is *not* checked on decode (requests from platforms are taken liberally).

use crate::reader::{Reader, Truncated};

/// Largest accepted encoded message, in bytes.
pub const MAX_INPUT: usize = 2048;
/// Deepest accepted container nesting; a top-level array or map counts as depth 1.
pub const MAX_DEPTH: usize = 4;
/// Most entries accepted in a single array, or key/value pairs in a single map.
pub const MAX_ITEMS: usize = 32;

const MAJOR_UINT: u8 = 0;
const MAJOR_NINT: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const MAJOR_SIMPLE: u8 = 7;

const SIMPLE_FALSE: u8 = 20;
const SIMPLE_TRUE: u8 = 21;
const SIMPLE_NULL: u8 = 22;

/// A decoded CBOR data item within the CTAP2 subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Major type 0.
    Uint(u64),
    /// Major type 1: represents the integer `-1 - n`.
    Nint(u64),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3.
    Text(String),
    /// Major type 4.
    Array(Vec<Value>),
    /// Major type 5, in insertion (decode) order; [`encode`] sorts canonically.
    Map(Vec<(Value, Value)>),
    /// Simple values 20 and 21.
    Bool(bool),
    /// Simple value 22.
    Null,
}

/// Why [`decode`] rejected its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborError {
    /// Input ended inside an item, or a length exceeds the remaining input.
    Truncated,
    /// Input is longer than [`MAX_INPUT`].
    TooLong,
    /// Containers nest deeper than [`MAX_DEPTH`].
    TooDeep,
    /// An array or map has more than [`MAX_ITEMS`] entries.
    TooManyItems,
    /// An integer or length is not encoded in its shortest form.
    NonCanonical,
    /// Indefinite length, tag, float, reserved info value or unsupported simple value.
    Unsupported,
    /// A text string is not valid UTF-8.
    InvalidUtf8,
    /// A map contains the same key twice.
    DuplicateKey,
    /// Bytes remain after the top-level item.
    TrailingBytes,
}

impl From<Truncated> for CborError {
    fn from(_: Truncated) -> Self {
        Self::Truncated
    }
}

/// Parses one CTAP2 CBOR item that must span the whole input.
///
/// Decoding runs in two passes. [`scan`] validates the input byte by byte without building
/// anything or touching the heap; only input it accepts is then built into a [`Value`] (which
/// also rejects duplicate map keys). No allocation is ever sized by an untrusted length larger
/// than the remaining input.
///
/// # Errors
/// Any [`CborError`]; never panics.
pub fn decode(input: &[u8]) -> Result<Value, CborError> {
    scan(input)?;
    build(input)
}

/// The raw encoding, as received, of the value stored under `key` in the top-level map
/// `input`; `None` if `input` is not a map or has no such key.
///
/// For checking a MAC over the bytes a peer sent (CTAP 2.1 §6.8 `subCommandParams`), which
/// may differ from [`encode`] of the decoded value because decoding accepts any map key order.
///
/// # Errors
/// Whatever [`decode`] reports for `input`; never panics.
pub fn map_value_raw<'a>(input: &'a [u8], key: &Value) -> Result<Option<&'a [u8]>, CborError> {
    // Full validation first, so the walk below only sees well-formed input.
    decode(input)?;
    let key = encode(key);
    let mut r = Reader::new(input);
    let Head::Map(count) = read_head(&mut r, 0)? else {
        return Ok(None);
    };
    for _ in 0..count {
        let k = skip_item(&mut r)?;
        let v = skip_item(&mut r)?;
        if k == key.as_slice() {
            return Ok(Some(v));
        }
    }
    Ok(None)
}

/// Consumes one complete item from `r` and returns its raw bytes.
fn skip_item<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], CborError> {
    let start = r.clone();
    let mut pending: usize = 1;
    while let Some(left) = pending.checked_sub(1) {
        pending = left;
        // Depth was checked by `decode`; 1 keeps `read_head` from refusing nested heads.
        let more = match read_head(r, 1)? {
            Head::Array(n) => n,
            Head::Map(n) => n.saturating_mul(2),
            _ => 0,
        };
        pending = pending.saturating_add(more);
    }
    let used = start
        .remaining()
        .checked_sub(r.remaining())
        .ok_or(CborError::Truncated)?;
    Ok(start.clone().take(used)?)
}

/// Splits an initial byte into (major type, additional info).
fn split_initial(initial: u8) -> (u8, u8) {
    (initial >> 5, initial & 0x1f)
}

/// Width in bytes of the argument for additional info 24..=27, with the smallest value that
/// needs that width (anything below is a non-shortest encoding).
fn arg_width(info: u8) -> Result<(u8, u64), CborError> {
    match info {
        24 => Ok((1, 24)),
        25 => Ok((2, 0x100)),
        26 => Ok((4, 0x1_0000)),
        27 => Ok((8, 0x1_0000_0000)),
        // 28..=30 are reserved, 31 is indefinite length / break.
        _ => Err(CborError::Unsupported),
    }
}

/// Converts a length argument to `usize`, failing if it exceeds the remaining input.
fn checked_len(remaining: usize, arg: u64) -> Result<usize, CborError> {
    let len = usize::try_from(arg).map_err(|_| CborError::Truncated)?;
    if len > remaining {
        return Err(CborError::Truncated);
    }
    Ok(len)
}

/// Validates an array/map entry count against [`MAX_ITEMS`] and the remaining input
/// (`min_bytes_each` is the smallest possible encoding of one entry).
fn checked_count(remaining: usize, arg: u64, min_bytes_each: usize) -> Result<usize, CborError> {
    let count = usize::try_from(arg).map_err(|_| CborError::TooManyItems)?;
    if count > MAX_ITEMS {
        return Err(CborError::TooManyItems);
    }
    let needed = count
        .checked_mul(min_bytes_each)
        .ok_or(CborError::Truncated)?;
    if needed > remaining {
        return Err(CborError::Truncated);
    }
    Ok(count)
}

/// UTF-8 lead byte rules (RFC 3629: no overlong forms, surrogates or code points above
/// U+10FFFF): (payload bits, continuation bytes, valid range of the first continuation).
fn utf8_lead(b: u8) -> Result<(u8, u8, u8, u8), CborError> {
    match b {
        0x00..=0x7f => Ok((b, 0, 0, 0)),
        0xc2..=0xdf => Ok((b & 0x1f, 1, 0x80, 0xbf)),
        0xe0 => Ok((b & 0x0f, 2, 0xa0, 0xbf)),
        0xe1..=0xec | 0xee..=0xef => Ok((b & 0x0f, 2, 0x80, 0xbf)),
        0xed => Ok((b & 0x0f, 2, 0x80, 0x9f)),
        0xf0 => Ok((b & 0x07, 3, 0x90, 0xbf)),
        0xf1..=0xf3 => Ok((b & 0x07, 3, 0x80, 0xbf)),
        0xf4 => Ok((b & 0x07, 3, 0x80, 0x8f)),
        _ => Err(CborError::InvalidUtf8),
    }
}

/// What [`scan`] expects the next byte to be.
#[derive(Clone, Copy)]
enum Expect {
    /// An initial byte.
    Head,
    /// `left` more big-endian argument bytes of a `major` head.
    Arg {
        major: u8,
        left: u8,
        acc: u64,
        min: u64,
    },
    /// `left` more bytes of a string body; for text, `need` UTF-8 continuation bytes are
    /// still owed, the next one within `lo..=hi`.
    Body {
        left: usize,
        text: bool,
        need: u8,
        lo: u8,
        hi: u8,
    },
}

/// Validates `input` as exactly one CTAP2 CBOR item, except for duplicate map keys (checked
/// by [`build`]), without building a [`Value`] and without touching the heap.
///
/// A byte-at-a-time state machine: one loop iteration per input byte and no recursion,
/// with open containers in a fixed array bounded by [`MAX_DEPTH`]. This keeps stack use
/// constant and makes the bounded proof cost grow linearly with the input size.
fn scan(input: &[u8]) -> Result<(), CborError> {
    if input.len() > MAX_INPUT {
        return Err(CborError::TooLong);
    }
    // Items still expected by each open container (a map counts keys and values).
    let mut open = [0_usize; MAX_DEPTH];
    let mut depth: usize = 0;
    let mut expect = Expect::Head;
    let mut complete = false;
    let mut consumed: usize = 0;
    while let Some(&b) = input.get(consumed) {
        if complete {
            return Err(CborError::TrailingBytes);
        }
        consumed = consumed.checked_add(1).ok_or(CborError::Truncated)?;
        let remaining = input
            .len()
            .checked_sub(consumed)
            .ok_or(CborError::Truncated)?;

        // Feed the byte; `head` is set once a complete (major, argument) head is known,
        // `item` once a whole item has been consumed.
        let mut head = None;
        let mut item = false;
        match expect {
            Expect::Head => {
                let (major, info) = split_initial(b);
                match major {
                    MAJOR_SIMPLE => match info {
                        SIMPLE_FALSE | SIMPLE_TRUE | SIMPLE_NULL => item = true,
                        _ => return Err(CborError::Unsupported),
                    },
                    MAJOR_TAG => return Err(CborError::Unsupported),
                    _ => {
                        if (major == MAJOR_ARRAY || major == MAJOR_MAP) && depth >= MAX_DEPTH {
                            return Err(CborError::TooDeep);
                        }
                        if info < 24 {
                            head = Some((major, u64::from(info)));
                        } else {
                            let (left, min) = arg_width(info)?;
                            expect = Expect::Arg {
                                major,
                                left,
                                acc: 0,
                                min,
                            };
                        }
                    }
                }
            }
            Expect::Arg {
                major,
                left,
                acc,
                min,
            } => {
                let acc = (acc << 8) | u64::from(b);
                let left = left.checked_sub(1).ok_or(CborError::Truncated)?;
                if left == 0 {
                    if acc < min {
                        return Err(CborError::NonCanonical);
                    }
                    expect = Expect::Head;
                    head = Some((major, acc));
                } else {
                    expect = Expect::Arg {
                        major,
                        left,
                        acc,
                        min,
                    };
                }
            }
            Expect::Body {
                left,
                text,
                mut need,
                mut lo,
                mut hi,
            } => {
                if text {
                    if need == 0 {
                        (_, need, lo, hi) = utf8_lead(b)?;
                    } else {
                        if b < lo || b > hi {
                            return Err(CborError::InvalidUtf8);
                        }
                        need = need.checked_sub(1).ok_or(CborError::InvalidUtf8)?;
                        (lo, hi) = (0x80, 0xbf);
                    }
                }
                let left = left.checked_sub(1).ok_or(CborError::Truncated)?;
                if left == 0 {
                    if need != 0 {
                        return Err(CborError::InvalidUtf8);
                    }
                    expect = Expect::Head;
                    item = true;
                } else {
                    expect = Expect::Body {
                        left,
                        text,
                        need,
                        lo,
                        hi,
                    };
                }
            }
        }

        if let Some((major, arg)) = head {
            match major {
                MAJOR_UINT | MAJOR_NINT => item = true,
                MAJOR_BYTES | MAJOR_TEXT => {
                    let left = checked_len(remaining, arg)?;
                    if left == 0 {
                        item = true;
                    } else {
                        expect = Expect::Body {
                            left,
                            text: major == MAJOR_TEXT,
                            need: 0,
                            lo: 0,
                            hi: 0,
                        };
                    }
                }
                _ => {
                    let left = if major == MAJOR_ARRAY {
                        checked_count(remaining, arg, 1)?
                    } else {
                        checked_count(remaining, arg, 2)?
                            .checked_mul(2)
                            .ok_or(CborError::TooManyItems)?
                    };
                    if left == 0 {
                        item = true;
                    } else {
                        let slot = open.get_mut(depth).ok_or(CborError::TooDeep)?;
                        *slot = left;
                        depth = depth.checked_add(1).ok_or(CborError::TooDeep)?;
                    }
                }
            }
        }

        if item {
            // Count the item against its container, closing every container that fills up.
            // At most MAX_DEPTH closes plus one stop; the constant trip count lets the model
            // checker unroll this exactly instead of up to the global unwind bound.
            let mut settled = false;
            let mut step: usize = 0;
            while step <= MAX_DEPTH {
                step = step.saturating_add(1);
                let Some(top) = depth.checked_sub(1).and_then(|i| open.get_mut(i)) else {
                    complete = true;
                    settled = true;
                    break;
                };
                *top = top.checked_sub(1).ok_or(CborError::Truncated)?;
                if *top > 0 {
                    settled = true;
                    break;
                }
                depth = depth.checked_sub(1).ok_or(CborError::Truncated)?;
            }
            if !settled {
                return Err(CborError::TooDeep);
            }
        }
    }
    if complete {
        Ok(())
    } else {
        Err(CborError::Truncated)
    }
}

/// One item head, with string bodies borrowed from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Head<'a> {
    Uint(u64),
    Nint(u64),
    Bytes(&'a [u8]),
    /// Raw body; [`utf8_for_each`] validates it while building.
    Text(&'a [u8]),
    /// Array with this many items (`<= MAX_ITEMS`).
    Array(usize),
    /// Map with this many key/value pairs (`<= MAX_ITEMS`).
    Map(usize),
    Bool(bool),
    Null,
}

/// Reads one head (and the body of a string) for [`build`]. `open` is the number of
/// enclosing containers. Repeats [`scan`]'s checks so that it is safe on any input.
fn read_head<'a>(r: &mut Reader<'a>, open: usize) -> Result<Head<'a>, CborError> {
    let (major, info) = split_initial(r.u8()?);
    match major {
        MAJOR_SIMPLE => {
            return match info {
                SIMPLE_FALSE => Ok(Head::Bool(false)),
                SIMPLE_TRUE => Ok(Head::Bool(true)),
                SIMPLE_NULL => Ok(Head::Null),
                _ => Err(CborError::Unsupported),
            }
        }
        MAJOR_TAG => return Err(CborError::Unsupported),
        _ => {}
    }
    if (major == MAJOR_ARRAY || major == MAJOR_MAP) && open >= MAX_DEPTH {
        return Err(CborError::TooDeep);
    }
    let arg = read_arg(r, info)?;
    match major {
        MAJOR_UINT => Ok(Head::Uint(arg)),
        MAJOR_NINT => Ok(Head::Nint(arg)),
        MAJOR_BYTES => Ok(Head::Bytes(r.take(checked_len(r.remaining(), arg)?)?)),
        MAJOR_TEXT => Ok(Head::Text(r.take(checked_len(r.remaining(), arg)?)?)),
        MAJOR_ARRAY => Ok(Head::Array(checked_count(r.remaining(), arg, 1)?)),
        // MAJOR_MAP is the only value left for a 3-bit major type.
        _ => Ok(Head::Map(checked_count(r.remaining(), arg, 2)?)),
    }
}

/// Reads the argument that follows an initial byte with additional info `info`,
/// rejecting reserved/indefinite encodings and non-shortest forms.
fn read_arg(r: &mut Reader<'_>, info: u8) -> Result<u64, CborError> {
    if info < 24 {
        return Ok(u64::from(info));
    }
    let (_, min) = arg_width(info)?;
    // Straight-line per width rather than a byte loop: cheaper to model check.
    let value = match info {
        24 => u64::from(r.u8()?),
        25 => u64::from(r.u16_be()?),
        26 => {
            let bytes: [u8; 4] = r.take(4)?.try_into().map_err(|_| CborError::Truncated)?;
            u64::from(u32::from_be_bytes(bytes))
        }
        _ => {
            let bytes: [u8; 8] = r.take(8)?.try_into().map_err(|_| CborError::Truncated)?;
            u64::from_be_bytes(bytes)
        }
    };
    if value < min {
        return Err(CborError::NonCanonical);
    }
    Ok(value)
}

/// Decodes `bytes` as strict UTF-8 (see [`utf8_lead`]), passing each scalar value to `sink`.
///
/// A small byte-at-a-time decoder rather than `core::str::from_utf8`, whose word-at-a-time
/// fast path is expensive for the bounded model checker; a proptest checks it agrees with
/// the standard library.
fn utf8_for_each(bytes: &[u8], mut sink: impl FnMut(char)) -> Result<(), CborError> {
    const BAD: CborError = CborError::InvalidUtf8;
    let mut r = Reader::new(bytes);
    while let Ok(b0) = r.u8() {
        let (lead, extra, lo, hi) = utf8_lead(b0)?;
        if extra == 0 {
            sink(char::from(b0));
            continue;
        }
        let b1 = r.u8().map_err(|_| BAD)?;
        if b1 < lo || b1 > hi {
            return Err(BAD);
        }
        // Straight-line rather than a loop over the continuation bytes: cheaper to model check.
        let mut cp = (u32::from(lead) << 6) | u32::from(b1 & 0x3f);
        if extra >= 2 {
            cp = (cp << 6) | continuation(&mut r)?;
        }
        if extra >= 3 {
            cp = (cp << 6) | continuation(&mut r)?;
        }
        sink(char::from_u32(cp).ok_or(BAD)?);
    }
    Ok(())
}

/// Payload bits of one UTF-8 continuation byte (`0b10xx_xxxx`).
fn continuation(r: &mut Reader<'_>) -> Result<u32, CborError> {
    let b = r.u8().map_err(|_| CborError::InvalidUtf8)?;
    if b & 0xc0 != 0x80 {
        return Err(CborError::InvalidUtf8);
    }
    Ok(u32::from(b & 0x3f))
}

/// A container whose entries are still being built.
enum Frame<'a> {
    Array {
        items: Vec<Value>,
        count: usize,
    },
    Map {
        entries: Vec<(Value, Value)>,
        count: usize,
        /// Raw encodings of the keys seen so far. Heads are canonical, so two keys are
        /// equal values exactly when their encodings are equal bytes.
        keys: Vec<&'a [u8]>,
        /// A decoded key waiting for its value.
        pending: Option<Value>,
        /// Reader position at the start of the key currently being decoded.
        key_start: Reader<'a>,
    },
}

impl<'a> Frame<'a> {
    /// Adds a finished item; `r` is the reader just past it.
    fn push(&mut self, value: Value, r: &Reader<'a>) -> Result<(), CborError> {
        match self {
            Frame::Array { items, .. } => items.push(value),
            Frame::Map {
                entries,
                keys,
                pending,
                key_start,
                ..
            } => match pending.take() {
                Some(key) => entries.push((key, value)),
                None => {
                    let used = key_start
                        .remaining()
                        .checked_sub(r.remaining())
                        .ok_or(CborError::Truncated)?;
                    let raw = key_start.clone().take(used)?;
                    if keys.contains(&raw) {
                        return Err(CborError::DuplicateKey);
                    }
                    keys.push(raw);
                    *pending = Some(value);
                }
            },
        }
        Ok(())
    }

    fn is_full(&self) -> bool {
        match self {
            Frame::Array { items, count } => items.len() >= *count,
            Frame::Map {
                entries,
                count,
                pending,
                ..
            } => pending.is_none() && entries.len() >= *count,
        }
    }

    fn into_value(self) -> Value {
        match self {
            Frame::Array { items, .. } => Value::Array(items),
            Frame::Map { entries, .. } => Value::Map(entries),
        }
    }
}

/// Builds the [`Value`] for input that [`scan`] accepted, rejecting duplicate map keys.
/// Every other check still runs (those errors are unreachable after a successful scan), so
/// this never panics on any input either.
fn build(input: &[u8]) -> Result<Value, CborError> {
    let mut r = Reader::new(input);
    let mut stack: Vec<Frame<'_>> = Vec::with_capacity(MAX_DEPTH);
    loop {
        if let Some(Frame::Map {
            key_start,
            pending: None,
            ..
        }) = stack.last_mut()
        {
            *key_start = r.clone();
        }
        let mut done = match read_head(&mut r, stack.len())? {
            Head::Uint(n) => Value::Uint(n),
            Head::Nint(n) => Value::Nint(n),
            Head::Bytes(b) => Value::Bytes(b.to_vec()),
            Head::Text(t) => {
                let mut text = String::with_capacity(t.len());
                utf8_for_each(t, |c| text.push(c))?;
                Value::Text(text)
            }
            Head::Bool(b) => Value::Bool(b),
            Head::Null => Value::Null,
            Head::Array(0) => Value::Array(Vec::new()),
            Head::Map(0) => Value::Map(Vec::new()),
            Head::Array(count) => {
                stack.push(Frame::Array {
                    items: Vec::with_capacity(count),
                    count,
                });
                continue;
            }
            Head::Map(count) => {
                stack.push(Frame::Map {
                    entries: Vec::with_capacity(count),
                    count,
                    keys: Vec::with_capacity(count),
                    pending: None,
                    key_start: r.clone(),
                });
                continue;
            }
        };
        // Attach the finished item to its container, closing every container that fills up.
        loop {
            let Some(top) = stack.last_mut() else {
                if !r.is_empty() {
                    return Err(CborError::TrailingBytes);
                }
                return Ok(done);
            };
            top.push(done, &r)?;
            if !top.is_full() {
                break;
            }
            let Some(full) = stack.pop() else {
                return Err(CborError::Truncated);
            };
            done = full.into_value();
        }
    }
}

/// Serialises `value` in CTAP2 canonical form.
///
/// Heads use the shortest encoding; map entries are ordered by their encoded keys, shorter
/// keys first, then bytewise. Duplicate keys are emitted as given (callers build maps).
#[must_use]
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(&mut out, value);
    out
}

fn len_arg(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn put_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if let Ok(small) = u8::try_from(arg) {
        if small < 24 {
            out.push(m | small);
        } else {
            out.push(m | 24);
            out.push(small);
        }
    } else if let Ok(v) = u16::try_from(arg) {
        out.push(m | 25);
        out.extend_from_slice(&v.to_be_bytes());
    } else if let Ok(v) = u32::try_from(arg) {
        out.push(m | 26);
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn encode_into(out: &mut Vec<u8>, value: &Value) {
    match value {
        Value::Uint(n) => put_head(out, MAJOR_UINT, *n),
        Value::Nint(n) => put_head(out, MAJOR_NINT, *n),
        Value::Bytes(b) => {
            put_head(out, MAJOR_BYTES, len_arg(b.len()));
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            put_head(out, MAJOR_TEXT, len_arg(t.len()));
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            put_head(out, MAJOR_ARRAY, len_arg(items.len()));
            for item in items {
                encode_into(out, item);
            }
        }
        Value::Map(entries) => {
            put_head(out, MAJOR_MAP, len_arg(entries.len()));
            let mut encoded: Vec<(Vec<u8>, &Value)> =
                entries.iter().map(|(k, v)| (encode(k), v)).collect();
            encoded.sort_by(|(a, _), (b, _)| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
            for (key, v) in encoded {
                out.extend_from_slice(&key);
                encode_into(out, v);
            }
        }
        Value::Bool(false) => put_head(out, MAJOR_SIMPLE, u64::from(SIMPLE_FALSE)),
        Value::Bool(true) => put_head(out, MAJOR_SIMPLE, u64::from(SIMPLE_TRUE)),
        Value::Null => put_head(out, MAJOR_SIMPLE, u64::from(SIMPLE_NULL)),
    }
}

impl Value {
    /// An integer map key or value: non-negative → [`Value::Uint`], negative → [`Value::Nint`].
    #[must_use]
    pub fn int_key(i: i64) -> Value {
        match u64::try_from(i) {
            Ok(n) => Value::Uint(n),
            // For negative i, -1 - i == !i, which is non-negative.
            Err(_) => Value::Nint(u64::try_from(!i).unwrap_or(0)),
        }
    }

    /// Looks up `key` in a map; `None` for non-maps or missing keys.
    #[must_use]
    pub fn map_get(&self, key: &Value) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find_map(|(k, v)| (k == key).then_some(v))
    }

    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Value::Uint(n) => Some(*n),
            _ => None,
        }
    }

    /// Any integer that fits in `i64` (e.g. COSE algorithm identifiers such as `-7`).
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Uint(n) => i64::try_from(*n).ok(),
            Value::Nint(n) => i64::try_from(*n).ok().map(|n| !n),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(entries) => Some(entries),
            _ => None,
        }
    }
}

impl From<u64> for Value {
    fn from(n: u64) -> Self {
        Value::Uint(n)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Text(s.to_owned())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Text(s)
    }
}

impl From<&[u8]> for Value {
    fn from(b: &[u8]) -> Self {
        Value::Bytes(b.to_vec())
    }
}

impl From<Vec<u8>> for Value {
    fn from(b: Vec<u8>) -> Self {
        Value::Bytes(b)
    }
}

impl From<Vec<Value>> for Value {
    fn from(items: Vec<Value>) -> Self {
        Value::Array(items)
    }
}

impl From<Vec<(Value, Value)>> for Value {
    fn from(entries: Vec<(Value, Value)>) -> Self {
        Value::Map(entries)
    }
}

#[cfg(kani)]
mod proofs {
    //! Modular, bounded proofs. `scan` (every rejection rule except duplicate keys) is
    //! checked end to end; `build` is covered through its parts (`read_head`, `read_arg`,
    //! `utf8_for_each`), plus proptest and the `cbor_decode` fuzz target for whole-`decode`
    //! behaviour and scan/build agreement. A whole-`decode` harness is not included: CBMC
    //! unrolls the recursive drop glue of `Value` trees exponentially, and even a 1-byte
    //! bound did not finish within 5 minutes. For the same reason `map_value_raw` is covered
    //! through `skip_item`.

    use super::*;

    /// Kani explores every byte string up to `SCAN_N` bytes.
    const SCAN_N: usize = 8;

    #[kani::proof]
    #[kani::unwind(10)]
    fn scan_never_panics() {
        let buf: [u8; SCAN_N] = kani::any();
        let len: usize = kani::any_where(|l| *l <= SCAN_N);
        let _ = scan(&buf[..len]);
    }

    /// The builder's head reader never panics and never reads past its input.
    #[kani::proof]
    #[kani::unwind(10)]
    fn read_head_never_panics() {
        let buf: [u8; 9] = kani::any();
        let len: usize = kani::any_where(|l| *l <= 9);
        let mut r = Reader::new(&buf[..len]);
        let open: usize = kani::any_where(|d| *d <= MAX_DEPTH);
        if let Ok(head) = read_head(&mut r, open) {
            match head {
                Head::Array(n) | Head::Map(n) => assert!(n <= MAX_ITEMS && n <= r.remaining()),
                Head::Bytes(b) | Head::Text(b) => assert!(b.len() < len),
                _ => {}
            }
        }
    }

    /// Every accepted head argument is in shortest form and consumes exactly its width.
    #[kani::proof]
    #[kani::unwind(10)]
    fn read_arg_is_canonical_and_bounded() {
        let buf: [u8; 9] = kani::any();
        let len: usize = kani::any_where(|l| *l <= 9);
        let info: u8 = kani::any_where(|i| *i < 32);
        let mut r = Reader::new(&buf[..len]);
        let before = r.remaining();
        if let Ok(arg) = read_arg(&mut r, info) {
            let used = before - r.remaining();
            match info {
                0..=23 => assert!(used == 0 && arg == u64::from(info)),
                24 => assert!(used == 1 && (24..=0xff).contains(&arg)),
                25 => assert!(used == 2 && (0x100..=0xffff).contains(&arg)),
                26 => assert!(used == 4 && (0x1_0000..=0xffff_ffff).contains(&arg)),
                _ => assert!(info == 27 && used == 8 && arg > 0xffff_ffff),
            }
        }
    }

    /// The raw-span walker behind `map_value_raw` never panics and returns a prefix of its
    /// input that it consumed exactly.
    #[kani::proof]
    #[kani::unwind(10)]
    fn skip_item_never_panics() {
        let buf: [u8; SCAN_N] = kani::any();
        let len: usize = kani::any_where(|l| *l <= SCAN_N);
        let mut r = Reader::new(&buf[..len]);
        if let Ok(raw) = skip_item(&mut r) {
            assert!(!raw.is_empty() && raw.len() + r.remaining() == len);
        }
    }

    /// The builder's UTF-8 decoder never panics.
    #[kani::proof]
    #[kani::unwind(6)]
    fn utf8_for_each_never_panics() {
        let buf: [u8; 4] = kani::any();
        let len: usize = kani::any_where(|l| *l <= 4);
        let _ = utf8_for_each(&buf[..len], |_| ());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    fn text(s: &str) -> Value {
        Value::from(s)
    }

    fn map(entries: Vec<(Value, Value)>) -> Value {
        Value::Map(entries)
    }

    /// RFC 8949 Appendix A vectors within the CTAP2 subset (all already canonical).
    fn rfc_vectors() -> Vec<(Value, &'static str)> {
        use Value::{Array, Bool, Bytes, Nint, Null, Uint};
        vec![
            (Uint(0), "00"),
            (Uint(1), "01"),
            (Uint(10), "0a"),
            (Uint(23), "17"),
            (Uint(24), "1818"),
            (Uint(25), "1819"),
            (Uint(100), "1864"),
            (Uint(1000), "1903e8"),
            (Uint(1_000_000), "1a000f4240"),
            (Uint(1_000_000_000_000), "1b000000e8d4a51000"),
            (Uint(u64::MAX), "1bffffffffffffffff"),
            (Nint(u64::MAX), "3bffffffffffffffff"),
            (Value::int_key(-1), "20"),
            (Value::int_key(-10), "29"),
            (Value::int_key(-100), "3863"),
            (Value::int_key(-1000), "3903e7"),
            (Bytes(vec![]), "40"),
            (Bytes(vec![1, 2, 3, 4]), "4401020304"),
            (text(""), "60"),
            (text("a"), "6161"),
            (text("IETF"), "6449455446"),
            (text("\"\\"), "62225c"),
            (text("\u{fc}"), "62c3bc"),
            (text("\u{6c34}"), "63e6b0b4"),
            (Array(vec![]), "80"),
            (Array(vec![Uint(1), Uint(2), Uint(3)]), "83010203"),
            (
                Array(vec![
                    Uint(1),
                    Array(vec![Uint(2), Uint(3)]),
                    Array(vec![Uint(4), Uint(5)]),
                ]),
                "8301820203820405",
            ),
            (
                Array((1..=25).map(Uint).collect()),
                "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
            ),
            (map(vec![]), "a0"),
            (
                map(vec![(Uint(1), Uint(2)), (Uint(3), Uint(4))]),
                "a201020304",
            ),
            (
                map(vec![
                    (text("a"), Uint(1)),
                    (text("b"), Array(vec![Uint(2), Uint(3)])),
                ]),
                "a26161016162820203",
            ),
            (
                Array(vec![text("a"), map(vec![(text("b"), text("c"))])]),
                "826161a161626163",
            ),
            (Bool(false), "f4"),
            (Bool(true), "f5"),
            (Null, "f6"),
        ]
    }

    #[test]
    fn rfc8949_vectors_decode_and_encode() {
        for (value, h) in rfc_vectors() {
            let bytes = hex(h);
            assert_eq!(decode(&bytes), Ok(value.clone()), "decode {h}");
            assert_eq!(encode(&value), bytes, "encode {h}");
        }
    }

    #[test]
    fn encode_sorts_map_keys_length_first_then_bytewise() {
        // RFC 8949 §4.2.3 example (length-first variant used by CTAP2), supported types only.
        let keys = [
            Value::Uint(10),
            Value::Uint(100),
            Value::int_key(-1),
            text("z"),
            text("aa"),
            Value::Array(vec![Value::Uint(100)]),
            Value::Array(vec![Value::int_key(-1)]),
            Value::Bool(false),
        ];
        // Insert in reverse so the encoder has to reorder.
        let entries = keys
            .iter()
            .rev()
            .map(|k| (k.clone(), Value::Null))
            .collect();
        let got = encode(&map(entries));
        let want = hex("a8 0af6 20f6 f4f6 1864f6 617af6 8120f6 626161f6 811864f6");
        assert_eq!(got, want);
        // Re-encoding the decoded canonical form is a fixed point.
        assert_eq!(encode(&decode(&got).unwrap()), got);
    }

    #[test]
    fn decode_accepts_non_canonical_map_order() {
        let v = decode(&hex("a203040102")).unwrap();
        assert_eq!(v.map_get(&Value::Uint(1)), Some(&Value::Uint(2)));
        assert_eq!(encode(&v), hex("a201020304"));
    }

    #[test]
    fn rejects_truncated() {
        for h in [
            "",
            "18",
            "19ff",
            "1a0000ff",
            "42aa",
            "62c3",
            "8201",
            "a101",
            "5a00010000",
            "9818",
        ] {
            assert_eq!(decode(&hex(h)), Err(CborError::Truncated), "{h}");
        }
        // Length larger than the remaining input is rejected before allocating.
        assert_eq!(
            decode(&hex("5bffffffffffffffff")),
            Err(CborError::Truncated)
        );
    }

    #[test]
    fn rejects_too_long() {
        let mut big = hex("5907fd");
        big.resize(MAX_INPUT, 0);
        assert_eq!(
            decode(&big).map(|v| v.as_bytes().map(<[u8]>::len)),
            Ok(Some(2045))
        );
        big.push(0);
        assert_eq!(decode(&big), Err(CborError::TooLong));
    }

    #[test]
    fn rejects_too_deep() {
        assert!(decode(&hex("8181818100")).is_ok());
        assert!(decode(&hex("a100a100a100a10000")).is_ok());
        assert_eq!(decode(&hex("818181818100")), Err(CborError::TooDeep));
        assert_eq!(
            decode(&hex("a100a100a100a100a10000")),
            Err(CborError::TooDeep)
        );
    }

    #[test]
    fn rejects_too_many_items() {
        let mut ok = hex("9820");
        ok.extend([0; 32]);
        assert!(decode(&ok).is_ok());
        let mut arr = hex("9821");
        arr.extend([0; 33]);
        assert_eq!(decode(&arr), Err(CborError::TooManyItems));
        assert_eq!(decode(&hex("b821")), Err(CborError::TooManyItems));
        assert_eq!(
            decode(&hex("9bffffffffffffffff")),
            Err(CborError::TooManyItems)
        );
    }

    #[test]
    fn rejects_non_canonical_heads() {
        for h in [
            "1817",
            "1900ff",
            "1a0000ffff",
            "1b00000000ffffffff",
            "3800",
            "580100",
            "780161",
            "980100",
            "b8010000",
        ] {
            assert_eq!(decode(&hex(h)), Err(CborError::NonCanonical), "{h}");
        }
    }

    #[test]
    fn rejects_unsupported() {
        for h in [
            "5f4100ff",                                     // indefinite byte string
            "7f6161ff",                                     // indefinite text string
            "9fff",                                         // indefinite array
            "bfff",                                         // indefinite map
            "c074323031332d30332d32315432303a30343a30305a", // tag 0
            "d82000",                                       // tag 32
            "f90000",                                       // half float
            "fa47c35000",                                   // single float
            "fb3ff199999999999a",                           // double float
            "f7",                                           // undefined
            "f0",                                           // simple(16)
            "f820",                                         // simple(32)
            "ff",                                           // break
            "1c",                                           // reserved info 28
            "3d",                                           // reserved info 29
            "5e",                                           // reserved info 30
        ] {
            assert_eq!(decode(&hex(h)), Err(CborError::Unsupported), "{h}");
        }
    }

    #[test]
    fn rejects_invalid_utf8() {
        for h in [
            "61ff",       // invalid byte
            "6180",       // lone continuation
            "61c2",       // truncated sequence
            "62c328",     // bad continuation
            "62c080",     // overlong
            "63e08080",   // overlong
            "63eda080",   // surrogate
            "64f4908080", // above U+10FFFF
            "61f5",       // invalid lead
        ] {
            assert_eq!(decode(&hex(h)), Err(CborError::InvalidUtf8), "{h}");
        }
    }

    #[test]
    fn rejects_duplicate_keys() {
        assert_eq!(decode(&hex("a201020103")), Err(CborError::DuplicateKey));
        assert_eq!(decode(&hex("a261610161610f")), Err(CborError::DuplicateKey));
    }

    #[test]
    fn rejects_trailing_bytes() {
        assert_eq!(decode(&hex("0000")), Err(CborError::TrailingBytes));
        assert_eq!(decode(&hex("80f6")), Err(CborError::TrailingBytes));
    }

    #[test]
    fn helpers_read_ctap_style_maps() {
        let v = map(vec![
            (Value::Uint(1), Value::from(&[0xaa_u8][..])),
            (Value::Uint(2), map(vec![(text("id"), text("example.com"))])),
            (Value::Uint(3), Value::Array(vec![Value::int_key(-7)])),
            (Value::Uint(5), Value::from(true)),
        ]);
        let v = decode(&encode(&v)).unwrap();
        assert_eq!(
            v.map_get(&Value::int_key(1)).and_then(Value::as_bytes),
            Some(&[0xaa][..])
        );
        assert_eq!(
            v.map_get(&Value::Uint(2))
                .and_then(|rp| rp.map_get(&text("id")))
                .and_then(Value::as_text),
            Some("example.com")
        );
        let algs = v
            .map_get(&Value::Uint(3))
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(algs[0], Value::Nint(6));
        assert_eq!(algs[0].as_i64(), Some(-7));
        assert_eq!(algs[0].as_uint(), None);
        assert_eq!(
            v.map_get(&Value::Uint(5)).and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(v.map_get(&Value::Uint(9)), None);
        assert_eq!(Value::Null.map_get(&Value::Uint(1)), None);
        assert_eq!(v.as_map().map(<[_]>::len), Some(4));
        assert_eq!(
            Value::int_key(i64::MIN),
            Value::Nint(i64::MAX.unsigned_abs())
        );
        assert_eq!(Value::int_key(i64::MIN).as_i64(), Some(i64::MIN));
        assert_eq!(Value::Uint(u64::MAX).as_i64(), None);
    }

    /// `scan` and `build` must agree: `build` may only add `DuplicateKey`.
    fn assert_passes_agree(bytes: &[u8]) -> Result<(), TestCaseError> {
        if bytes.len() > MAX_INPUT {
            return Ok(());
        }
        match (scan(bytes), build(bytes)) {
            (Ok(()), Ok(_) | Err(CborError::DuplicateKey)) | (Err(_), Err(_)) => Ok(()),
            (s, b) => Err(TestCaseError::fail(format!(
                "scan {s:?} vs build {b:?} for {bytes:02x?}"
            ))),
        }
    }

    fn depth(v: &Value) -> usize {
        match v {
            Value::Array(items) => items.iter().map(depth).max().unwrap_or(0).saturating_add(1),
            Value::Map(entries) => entries
                .iter()
                .map(|(k, v)| depth(k).max(depth(v)))
                .max()
                .unwrap_or(0)
                .saturating_add(1),
            _ => 0,
        }
    }

    fn arb_leaf() -> impl Strategy<Value = Value> {
        prop_oneof![
            any::<u64>().prop_map(Value::Uint),
            (0u64..30).prop_map(Value::Uint),
            any::<u64>().prop_map(Value::Nint),
            prop::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
            prop::collection::vec(any::<char>(), 0..8)
                .prop_map(|c| Value::Text(c.into_iter().collect())),
            any::<bool>().prop_map(Value::Bool),
            Just(Value::Null),
        ]
    }

    fn arb_value() -> impl Strategy<Value = Value> {
        arb_leaf().prop_recursive(4, 64, 8, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
                prop::collection::vec((arb_leaf(), inner), 0..8).prop_map(|pairs| {
                    let mut entries: Vec<(Value, Value)> = Vec::new();
                    for (k, v) in pairs {
                        if !entries.iter().any(|(e, _)| *e == k) {
                            entries.push((k, v));
                        }
                    }
                    Value::Map(entries)
                }),
            ]
        })
    }

    /// Puts map entries in canonical order, as [`decode`] returns them for canonical input.
    fn canonicalize(v: Value) -> Value {
        match v {
            Value::Array(items) => Value::Array(items.into_iter().map(canonicalize).collect()),
            Value::Map(entries) => {
                let mut entries: Vec<(Value, Value)> = entries
                    .into_iter()
                    .map(|(k, v)| (canonicalize(k), canonicalize(v)))
                    .collect();
                entries.sort_by_cached_key(|(k, _)| {
                    let e = encode(k);
                    (e.len(), e)
                });
                Value::Map(entries)
            }
            other => other,
        }
    }

    #[test]
    fn map_value_raw_returns_the_bytes_as_received() {
        // {2: {"b": 1, "a": 2}, 1: 0}: both maps out of canonical order.
        let input = hex("a2 02 a2 6162 01 6161 02 01 00");
        assert_eq!(
            map_value_raw(&input, &Value::Uint(2)),
            Ok(Some(&input[2..9]))
        );
        assert_eq!(
            map_value_raw(&input, &Value::Uint(1)),
            Ok(Some(&input[10..]))
        );
        assert_eq!(map_value_raw(&input, &Value::Uint(3)), Ok(None));
        assert_eq!(map_value_raw(&hex("82 01 02"), &Value::Uint(0)), Ok(None));
        assert_eq!(
            map_value_raw(&hex("a2 01 00 01 00"), &Value::Uint(1)),
            Err(CborError::DuplicateKey)
        );
        assert_eq!(
            map_value_raw(&hex("a1 01 1800"), &Value::Uint(1)),
            Err(CborError::NonCanonical)
        );
    }

    proptest! {
        #[test]
        fn encode_decode_round_trip(v in arb_value()) {
            prop_assume!(depth(&v) <= MAX_DEPTH);
            let bytes = encode(&v);
            prop_assume!(bytes.len() <= MAX_INPUT);
            let decoded = decode(&bytes);
            prop_assert_eq!(&decoded, &Ok(canonicalize(v)));
            // Canonical encoding is a fixed point.
            prop_assert_eq!(encode(&decoded.unwrap()), bytes);
        }

        #[test]
        fn utf8_matches_std(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
            let mut ours = String::new();
            let got = utf8_for_each(&bytes, |c| ours.push(c)).map(|()| ours);
            let want = core::str::from_utf8(&bytes).map(str::to_owned).map_err(|_| CborError::InvalidUtf8);
            prop_assert_eq!(got, want);
        }

        #[test]
        fn utf8_accepts_all_strings(s in ".*") {
            let mut ours = String::new();
            prop_assert_eq!(utf8_for_each(s.as_bytes(), |c| ours.push(c)), Ok(()));
            prop_assert_eq!(ours, s);
        }

        #[test]
        fn scan_and_build_agree_on_mutated_encodings(
            v in arb_value(),
            idx in any::<prop::sample::Index>(),
            byte in any::<u8>(),
            truncate in any::<bool>(),
        ) {
            let mut bytes = encode(&v);
            assert_passes_agree(&bytes)?;
            let i = idx.index(bytes.len());
            if truncate {
                bytes.truncate(i);
            } else {
                bytes[i] = byte;
            }
            assert_passes_agree(&bytes)?;
        }

        #[test]
        fn map_value_raw_finds_each_entry_as_encoded(v in arb_value()) {
            prop_assume!(depth(&v) <= MAX_DEPTH);
            let bytes = encode(&v);
            prop_assume!(bytes.len() <= MAX_INPUT);
            match canonicalize(v) {
                Value::Map(entries) => {
                    for (k, val) in &entries {
                        let want = encode(val);
                        prop_assert_eq!(map_value_raw(&bytes, k), Ok(Some(want.as_slice())));
                    }
                    let absent = Value::Text("\u{10ffff} absent".into());
                    if !entries.iter().any(|(k, _)| *k == absent) {
                        prop_assert_eq!(map_value_raw(&bytes, &absent), Ok(None));
                    }
                }
                _ => prop_assert_eq!(map_value_raw(&bytes, &Value::Uint(0)), Ok(None)),
            }
        }

        #[test]
        fn map_value_raw_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..300), key in arb_leaf()) {
            match map_value_raw(&bytes, &key) {
                Ok(Some(raw)) => prop_assert!(decode(raw).is_ok()),
                Ok(None) => {}
                Err(e) => prop_assert_eq!(Err(e), decode(&bytes).map(|_| ())),
            }
        }

        #[test]
        fn decode_never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..2100)) {
            assert_passes_agree(&bytes)?;
            if let Ok(v) = decode(&bytes) {
                prop_assert_eq!(decode(&encode(&v)), Ok(canonicalize(v)));
            }
        }
    }
}
