//! CTAPHID framing and reassembly (CTAP 2.1 §11.2, USB HID transport).
//!
//! Pure and synchronous: no I/O, no clocks. The caller passes the current time in
//! milliseconds and turns every [`Action`] into reports with [`fragment`],
//! [`error_report`] and [`keepalive_report`].
//!
//! Verified with Verus: [`Assembler`] keeps `wf()` (a transaction in progress
//! always has `buf.len() < total <= MAX_MSG`), a completed message always has the
//! length announced in its init packet, and a continuation packet is accepted only
//! for the channel in progress and with the expected sequence number.

use vstd::prelude::*;

verus! {

/// HID report size, both directions.
pub const REPORT_LEN: usize = 64;
/// Payload bytes carried by an init packet.
pub const INIT_DATA_LEN: usize = 57;
/// Payload bytes carried by a continuation packet.
pub const CONT_DATA_LEN: usize = 59;
/// Offset of the payload in an init packet.
pub const INIT_DATA_OFFSET: usize = 7;
/// Offset of the payload in a continuation packet.
pub const CONT_DATA_OFFSET: usize = 5;
/// Broadcast channel, used by CTAPHID_INIT to allocate a channel.
pub const BROADCAST_CID: u32 = 0xffff_ffff;
/// Largest message we accept or send (the maxMsgSize we advertise).
pub const MAX_MSG: usize = 2048;
/// Time allowed between two packets of the same message.
pub const CONT_TIMEOUT_MS: u64 = 750;

/// CTAPHID command bytes (bit 7 set, as they appear on the wire).
pub const CMD_PING: u8 = 0x81;
pub const CMD_MSG: u8 = 0x83;
pub const CMD_LOCK: u8 = 0x84;
pub const CMD_INIT: u8 = 0x86;
pub const CMD_WINK: u8 = 0x88;
pub const CMD_CBOR: u8 = 0x90;
pub const CMD_CANCEL: u8 = 0x91;
pub const CMD_KEEPALIVE: u8 = 0xBB;
pub const CMD_ERROR: u8 = 0xBF;

/// CTAPHID_ERROR codes.
pub const ERR_INVALID_CMD: u8 = 0x01;
pub const ERR_INVALID_PAR: u8 = 0x02;
pub const ERR_INVALID_LEN: u8 = 0x03;
pub const ERR_INVALID_SEQ: u8 = 0x04;
pub const ERR_MSG_TIMEOUT: u8 = 0x05;
pub const ERR_CHANNEL_BUSY: u8 = 0x06;
pub const ERR_INVALID_CHANNEL: u8 = 0x0B;
pub const ERR_OTHER: u8 = 0x7F;

/// CTAPHID_KEEPALIVE status bytes.
pub const STATUS_PROCESSING: u8 = 1;
pub const STATUS_UPNEEDED: u8 = 2;

/// CTAPHID protocol version reported in the INIT response.
pub const PROTOCOL_VERSION: u8 = 2;

// ---------------------------------------------------------------------------
// Report layout (spec)
// ---------------------------------------------------------------------------

/// Big-endian channel id in bytes 0..4.
pub open spec fn spec_report_cid(r: [u8; 64]) -> u32 {
    (r@[0] as int * 0x100_0000 + r@[1] as int * 0x1_0000 + r@[2] as int * 0x100
        + r@[3] as int) as u32
}

/// Init packets have bit 7 of byte 4 set.
pub open spec fn spec_is_init(r: [u8; 64]) -> bool {
    r@[4] >= 0x80
}

/// Big-endian payload length of an init packet (bytes 5..7).
pub open spec fn spec_bcnt(r: [u8; 64]) -> u16 {
    (r@[5] as int * 0x100 + r@[6] as int) as u16
}

/// A parsed report header. The payload stays in the report, at
/// [`INIT_DATA_OFFSET`] or [`CONT_DATA_OFFSET`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packet {
    /// First packet of a message. `cmd` keeps bit 7 (compare with `CMD_*`).
    Init { cid: u32, cmd: u8, bcnt: u16 },
    /// Continuation packet, `seq` in `0..=0x7f`.
    Cont { cid: u32, seq: u8 },
}

/// Parses the header of a 64-byte report.
pub fn parse(report: &[u8; 64]) -> (p: Packet)
    ensures
        match p {
            Packet::Init { cid, cmd, bcnt } => spec_is_init(*report) && cid == spec_report_cid(
                *report,
            ) && cmd == report@[4] && bcnt == spec_bcnt(*report),
            Packet::Cont { cid, seq } => !spec_is_init(*report) && cid == spec_report_cid(*report)
                && seq == report@[4],
        },
{
    let cid = u32::from(report[0]) * 0x100_0000 + u32::from(report[1]) * 0x1_0000 + u32::from(
        report[2],
    ) * 0x100 + u32::from(report[3]);
    let b4 = report[4];
    if b4 >= 0x80 {
        let bcnt = u16::from(report[5]) * 0x100 + u16::from(report[6]);
        Packet::Init { cid, cmd: b4, bcnt }
    } else {
        Packet::Cont { cid, seq: b4 }
    }
}

// ---------------------------------------------------------------------------
// Assembler
// ---------------------------------------------------------------------------

/// What the transport must do after feeding a report or a tick.
#[verifier::allow(autoderive_clone_without_spec)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Nothing to send.
    None,
    /// A whole message arrived on `cid`.
    Complete { cid: u32, cmd: u8, payload: Vec<u8> },
    /// Send `error_report(cid, code)`.
    Error { cid: u32, code: u8 },
}

/// Every completed payload fits in [`MAX_MSG`].
pub open spec fn spec_action_ok(a: Action) -> bool {
    match a {
        Action::Complete { payload, .. } => payload@.len() <= MAX_MSG,
        _ => true,
    }
}

#[derive(Debug)]
enum State {
    Idle,
    Receiving { cid: u32, cmd: u8, total: u16, buf: Vec<u8>, next_seq: u8, deadline_ms: u64 },
}

/// CTAPHID message reassembly for one transport (one transaction at a time).
///
/// Call [`Assembler::on_tick`] regularly (and before [`Assembler::on_report`]) so
/// stalled transactions time out.
#[derive(Debug)]
pub struct Assembler {
    state: State,
}

fn deadline_after(now_ms: u64) -> (d: u64) {
    if now_ms > u64::MAX - CONT_TIMEOUT_MS {
        u64::MAX
    } else {
        now_ms + CONT_TIMEOUT_MS
    }
}

/// Appends `report[from..from + n]` to `buf`.
#[allow(clippy::indexing_slicing)] // Verus proves bounds
fn append_from(buf: &mut Vec<u8>, report: &[u8; 64], from: usize, n: usize)
    requires
        from + n <= 64,
        old(buf)@.len() + n <= MAX_MSG,
    ensures
        final(buf)@.len() == old(buf)@.len() + n,
{
    let end = from + n;
    let mut i = from;
    while i < end
        invariant
            from <= i <= end,
            end <= 64,
            buf@.len() == old(buf)@.len() + (i - from),
            old(buf)@.len() + n <= MAX_MSG,
            end == from + n,
        decreases end - i,
    {
        buf.push(report[i]);
        i += 1;
    }
}

impl Assembler {
    /// Invariant: an open transaction is a multi-packet message that is not yet
    /// complete, and its buffer length matches the packets accepted so far.
    pub closed spec fn wf(self) -> bool {
        match self.state {
            State::Idle => true,
            State::Receiving { total, buf, next_seq, .. } => {
                &&& INIT_DATA_LEN < total
                &&& total <= MAX_MSG
                &&& buf@.len() < total
                &&& buf@.len() == INIT_DATA_LEN + CONT_DATA_LEN * next_seq
                &&& next_seq <= 128
            },
        }
    }

    pub closed spec fn spec_is_receiving(self) -> bool {
        self.state is Receiving
    }

    pub closed spec fn spec_cid(self) -> u32 {
        match self.state {
            State::Receiving { cid, .. } => cid,
            State::Idle => 0,
        }
    }

    pub closed spec fn spec_total(self) -> nat {
        match self.state {
            State::Receiving { total, .. } => total as nat,
            State::Idle => 0,
        }
    }

    pub closed spec fn spec_next_seq(self) -> u8 {
        match self.state {
            State::Receiving { next_seq, .. } => next_seq,
            State::Idle => 0,
        }
    }

    pub closed spec fn spec_buf_len(self) -> nat {
        match self.state {
            State::Receiving { buf, .. } => buf@.len(),
            State::Idle => 0,
        }
    }

    pub fn new() -> (a: Self)
        ensures
            a.wf(),
            !a.spec_is_receiving(),
    {
        Assembler { state: State::Idle }
    }

    /// Channel of the transaction in progress, if any.
    pub fn busy_cid(&self) -> (c: Option<u32>)
        ensures
            c is Some <==> self.spec_is_receiving(),
            c is Some ==> c->0 == self.spec_cid(),
    {
        match &self.state {
            State::Idle => None,
            State::Receiving { cid, .. } => Some(*cid),
        }
    }

    /// Aborts the transaction in progress (if any).
    pub fn reset(&mut self)
        ensures
            final(self).wf(),
            !final(self).spec_is_receiving(),
    {
        self.state = State::Idle;
    }

    /// Init packet with no transaction open (or after an INIT resync).
    fn start(&mut self, report: &[u8; 64], cid: u32, cmd: u8, bcnt: u16, now_ms: u64) -> (a:
        Action)
        requires
            cid == spec_report_cid(*report),
            bcnt == spec_bcnt(*report),
        ensures
            final(self).wf(),
            spec_action_ok(a),
            a matches Action::Complete { cid: c, cmd: m, payload } ==> c == cid && m == cmd
                && payload@.len() == bcnt,
            final(self).spec_is_receiving() ==> final(self).spec_cid() == cid
                && final(self).spec_total() == bcnt,
    {
        let total = usize::from(bcnt);
        if total > MAX_MSG {
            self.state = State::Idle;
            Action::Error { cid, code: ERR_INVALID_LEN }
        } else if total <= INIT_DATA_LEN {
            self.state = State::Idle;
            let mut payload = Vec::with_capacity(total);
            append_from(&mut payload, report, INIT_DATA_OFFSET, total);
            Action::Complete { cid, cmd, payload }
        } else {
            let mut buf = Vec::with_capacity(total);
            append_from(&mut buf, report, INIT_DATA_OFFSET, INIT_DATA_LEN);
            self.state = State::Receiving {
                cid,
                cmd,
                total: bcnt,
                buf,
                next_seq: 0,
                deadline_ms: deadline_after(now_ms),
            };
            Action::None
        }
    }

    /// Feeds one HID output report received at `now_ms`.
    pub fn on_report(&mut self, report: &[u8; 64], now_ms: u64) -> (a: Action)
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            spec_action_ok(a),
            // A message completed by an init packet has the length it announced.
            spec_is_init(*report) ==> (a matches Action::Complete { cid, cmd, payload } ==> cid
                == spec_report_cid(*report) && cmd == report@[4] && payload@.len() == spec_bcnt(
                *report)),
            // A message completed by a continuation packet has the length announced by
            // its init packet, and the packet matched the open channel and sequence.
            !spec_is_init(*report) ==> (a matches Action::Complete { cid, payload, .. } ==> {
                &&& old(self).spec_is_receiving()
                &&& cid == old(self).spec_cid()
                &&& spec_report_cid(*report) == old(self).spec_cid()
                &&& report@[4] == old(self).spec_next_seq()
                &&& payload@.len() == old(self).spec_total()
            }),
            // A continuation packet is accepted only for the open channel and the
            // expected sequence number.
            !spec_is_init(*report) && final(self).spec_is_receiving() ==> {
                &&& old(self).spec_is_receiving()
                &&& final(self).spec_cid() == old(self).spec_cid()
                &&& final(self).spec_total() == old(self).spec_total()
                &&& (final(self).spec_buf_len() != old(self).spec_buf_len() ==> spec_report_cid(
                    *report,
                ) == old(self).spec_cid() && report@[4] == old(self).spec_next_seq())
            },
            // Another channel cannot disturb an open transaction.
            old(self).spec_is_receiving() && spec_report_cid(*report) != old(self).spec_cid()
                ==> *final(self) == *old(self),
    {
        let packet = parse(report);
        let mut st = State::Idle;
        core::mem::swap(&mut self.state, &mut st);
        match st {
            State::Idle => match packet {
                Packet::Init { cid, cmd, bcnt } => self.start(report, cid, cmd, bcnt, now_ms),
                Packet::Cont { .. } => Action::None,
            },
            State::Receiving { cid, cmd, total, buf, next_seq, deadline_ms } => {
                match packet {
                    Packet::Init { cid: pcid, cmd: pcmd, bcnt } => {
                        if pcid != cid {
                            self.state = State::Receiving {
                                cid,
                                cmd,
                                total,
                                buf,
                                next_seq,
                                deadline_ms,
                            };
                            Action::Error { cid: pcid, code: ERR_CHANNEL_BUSY }
                        } else if pcmd == CMD_INIT {
                            // INIT on the busy channel aborts its transaction (§11.2.9.1.3).
                            self.start(report, pcid, pcmd, bcnt, now_ms)
                        } else {
                            Action::Error { cid, code: ERR_INVALID_SEQ }
                        }
                    },
                    Packet::Cont { cid: pcid, seq } => {
                        if pcid != cid {
                            self.state = State::Receiving {
                                cid,
                                cmd,
                                total,
                                buf,
                                next_seq,
                                deadline_ms,
                            };
                            Action::None
                        } else if seq != next_seq {
                            Action::Error { cid, code: ERR_INVALID_SEQ }
                        } else {
                            let mut buf = buf;
                            let remaining = usize::from(total) - buf.len();
                            if remaining <= CONT_DATA_LEN {
                                append_from(&mut buf, report, CONT_DATA_OFFSET, remaining);
                                Action::Complete { cid, cmd, payload: buf }
                            } else {
                                append_from(&mut buf, report, CONT_DATA_OFFSET, CONT_DATA_LEN);
                                self.state = State::Receiving {
                                    cid,
                                    cmd,
                                    total,
                                    buf,
                                    next_seq: next_seq + 1,
                                    deadline_ms: deadline_after(now_ms),
                                };
                                Action::None
                            }
                        }
                    },
                }
            },
        }
    }

    /// Times out a transaction whose next packet is overdue at `now_ms`.
    pub fn on_tick(&mut self, now_ms: u64) -> (a: Action)
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            a is None || a is Error,
            a is Error ==> old(self).spec_is_receiving() && !final(self).spec_is_receiving()
                && a == (Action::Error { cid: old(self).spec_cid(), code: ERR_MSG_TIMEOUT }),
            a is None ==> *final(self) == *old(self),
    {
        let expired = match &self.state {
            State::Idle => None,
            State::Receiving { cid, deadline_ms, .. } => {
                if now_ms > *deadline_ms {
                    Some(*cid)
                } else {
                    None
                }
            },
        };
        match expired {
            Some(cid) => {
                self.state = State::Idle;
                Action::Error { cid, code: ERR_MSG_TIMEOUT }
            },
            None => Action::None,
        }
    }
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

#[allow(clippy::cast_possible_truncation)]  // Verus proves x < 256
fn byte_u32(x: u32) -> (b: u8)
    requires
        x < 256,
    ensures
        b == x,
{
    x as u8
}

#[allow(clippy::cast_possible_truncation)]  // Verus proves x < 256
fn byte_usize(x: usize) -> (b: u8)
    requires
        x < 256,
    ensures
        b == x,
{
    x as u8
}

/// Writes `cid` big-endian into bytes 0..4.
fn put_cid(pkt: &mut [u8; 64], cid: u32) {
    pkt[0] = byte_u32(cid / 0x100_0000);
    pkt[1] = byte_u32(cid / 0x1_0000 % 0x100);
    pkt[2] = byte_u32(cid / 0x100 % 0x100);
    pkt[3] = byte_u32(cid % 0x100);
}

/// An init report header with `bcnt` and no payload.
fn init_header(cid: u32, cmd: u8, bcnt: usize) -> (pkt: [u8; 64])
    requires
        bcnt <= MAX_MSG,
{
    let mut pkt = [0u8; 64];
    put_cid(&mut pkt, cid);
    pkt[4] = cmd;
    pkt[5] = byte_usize(bcnt / 0x100);
    pkt[6] = byte_usize(bcnt % 0x100);
    pkt
}

/// Copies `payload[off..off + n]` into `pkt[at..at + n]`.
#[allow(clippy::indexing_slicing)] // Verus proves bounds
fn copy_into(pkt: &mut [u8; 64], at: usize, payload: &[u8], off: usize, n: usize)
    requires
        at + n <= 64,
        off + n <= payload@.len(),
        off + n <= MAX_MSG,
{
    let mut j: usize = 0;
    while j < n
        invariant
            j <= n,
            at + n <= 64,
            off + n <= payload@.len(),
            off + n <= MAX_MSG,
        decreases n - j,
    {
        pkt[at + j] = payload[off + j];
        j += 1;
    }
}

/// Splits a message into zero-padded reports (`None` if longer than [`MAX_MSG`]).
/// `cmd` keeps bit 7 (`CMD_*`).
pub fn fragment(cid: u32, cmd: u8, payload: &[u8]) -> (r: Option<Vec<[u8; 64]>>)
    ensures
        r is None <==> payload@.len() > MAX_MSG,
        r is Some ==> r->0@.len() >= 1,
{
    let len = payload.len();
    if len > MAX_MSG {
        return None;
    }
    let mut out: Vec<[u8; 64]> = Vec::new();
    let mut pkt = init_header(cid, cmd, len);
    let first = if len < INIT_DATA_LEN {
        len
    } else {
        INIT_DATA_LEN
    };
    copy_into(&mut pkt, INIT_DATA_OFFSET, payload, 0, first);
    out.push(pkt);
    let mut off = first;
    let mut seq: u8 = 0;
    while off < len
        invariant
            len == payload@.len(),
            len <= MAX_MSG,
            off <= len,
            off < len ==> off == INIT_DATA_LEN + CONT_DATA_LEN * seq,
            seq <= 34,
            out@.len() == 1 + seq,
        decreases len - off,
    {
        let rest = len - off;
        let n = if rest < CONT_DATA_LEN {
            rest
        } else {
            CONT_DATA_LEN
        };
        let mut pkt = [0u8; 64];
        put_cid(&mut pkt, cid);
        pkt[4] = seq;
        copy_into(&mut pkt, CONT_DATA_OFFSET, payload, off, n);
        out.push(pkt);
        off += n;
        seq += 1;
    }
    Some(out)
}

/// A CTAPHID_ERROR report.
pub fn error_report(cid: u32, code: u8) -> (pkt: [u8; 64]) {
    let mut pkt = init_header(cid, CMD_ERROR, 1);
    pkt[INIT_DATA_OFFSET] = code;
    pkt
}

/// A CTAPHID_KEEPALIVE report (`STATUS_PROCESSING` or `STATUS_UPNEEDED`).
pub fn keepalive_report(cid: u32, status: u8) -> (pkt: [u8; 64]) {
    let mut pkt = init_header(cid, CMD_KEEPALIVE, 1);
    pkt[INIT_DATA_OFFSET] = status;
    pkt
}

/// CTAPHID_INIT response payload: nonce, new channel id (big-endian), protocol
/// version 2, device version 0.1.0, capability flags.
#[allow(clippy::indexing_slicing)] // Verus proves bounds
pub fn init_response(nonce: &[u8; 8], new_cid: u32, caps: u8) -> (r: Vec<u8>)
    ensures
        r@.len() == 17,
{
    let mut r = Vec::with_capacity(17);
    let mut i: usize = 0;
    while i < 8
        invariant
            i <= 8,
            r@.len() == i,
        decreases 8 - i,
    {
        r.push(nonce[i]);
        i += 1;
    }
    r.push(byte_u32(new_cid / 0x100_0000));
    r.push(byte_u32(new_cid / 0x1_0000 % 0x100));
    r.push(byte_u32(new_cid / 0x100 % 0x100));
    r.push(byte_u32(new_cid % 0x100));
    r.push(PROTOCOL_VERSION);
    r.push(0);
    r.push(1);
    r.push(0);
    r.push(caps);
    r
}

} // verus!

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;

    fn init_pkt(cid: u32, cmd: u8, bcnt: u16, data: &[u8]) -> [u8; 64] {
        let mut p = [0u8; 64];
        p[..4].copy_from_slice(&cid.to_be_bytes());
        p[4] = cmd;
        p[5..7].copy_from_slice(&bcnt.to_be_bytes());
        p[7..7 + data.len()].copy_from_slice(data);
        p
    }

    fn cont_pkt(cid: u32, seq: u8, data: &[u8]) -> [u8; 64] {
        let mut p = [0u8; 64];
        p[..4].copy_from_slice(&cid.to_be_bytes());
        p[4] = seq;
        p[5..5 + data.len()].copy_from_slice(data);
        p
    }

    fn assemble(a: &mut Assembler, pkts: &[[u8; 64]]) -> Action {
        let mut last = Action::None;
        for (i, p) in pkts.iter().enumerate() {
            last = a.on_report(p, i as u64);
            if i + 1 < pkts.len() {
                assert_eq!(last, Action::None);
            }
        }
        last
    }

    #[test]
    fn parses_headers() {
        let p = init_pkt(0x0102_0304, CMD_CBOR, 0x0123, &[]);
        assert_eq!(
            parse(&p),
            Packet::Init {
                cid: 0x0102_0304,
                cmd: CMD_CBOR,
                bcnt: 0x0123
            }
        );
        let c = cont_pkt(0xdead_beef, 5, &[]);
        assert_eq!(
            parse(&c),
            Packet::Cont {
                cid: 0xdead_beef,
                seq: 5
            }
        );
    }

    #[test]
    fn single_packet_message() {
        let mut a = Assembler::new();
        let p = init_pkt(7, CMD_PING, 3, &[1, 2, 3, 9, 9]);
        assert_eq!(
            a.on_report(&p, 0),
            Action::Complete {
                cid: 7,
                cmd: CMD_PING,
                payload: vec![1, 2, 3]
            }
        );
        assert_eq!(a.busy_cid(), None);
    }

    #[test]
    fn empty_message() {
        let mut a = Assembler::new();
        let p = init_pkt(7, CMD_WINK, 0, &[]);
        assert_eq!(
            a.on_report(&p, 0),
            Action::Complete {
                cid: 7,
                cmd: CMD_WINK,
                payload: vec![]
            }
        );
    }

    #[test]
    fn multi_packet_max_message() {
        let payload: Vec<u8> = (0..MAX_MSG).map(|i| (i % 251) as u8).collect();
        let pkts = fragment(0x1234_5678, CMD_CBOR, &payload).unwrap();
        // 57 + 34 * 59 = 2063 >= 2048 > 57 + 33 * 59
        assert_eq!(pkts.len(), 35);
        let mut a = Assembler::new();
        assert_eq!(
            assemble(&mut a, &pkts),
            Action::Complete {
                cid: 0x1234_5678,
                cmd: CMD_CBOR,
                payload
            }
        );
        assert_eq!(a.busy_cid(), None);
    }

    #[test]
    fn wrong_seq_resets() {
        let mut a = Assembler::new();
        assert_eq!(
            a.on_report(&init_pkt(1, CMD_CBOR, 200, &[0; 57]), 0),
            Action::None
        );
        assert_eq!(a.busy_cid(), Some(1));
        assert_eq!(
            a.on_report(&cont_pkt(1, 1, &[0; 59]), 1),
            Action::Error {
                cid: 1,
                code: ERR_INVALID_SEQ
            }
        );
        assert_eq!(a.busy_cid(), None);
        // Stray continuation while idle is ignored.
        assert_eq!(a.on_report(&cont_pkt(1, 0, &[0; 59]), 2), Action::None);
    }

    #[test]
    fn busy_channel() {
        let mut a = Assembler::new();
        assert_eq!(
            a.on_report(&init_pkt(1, CMD_CBOR, 100, &[5; 57]), 0),
            Action::None
        );
        assert_eq!(
            a.on_report(&init_pkt(2, CMD_CBOR, 3, &[1, 2, 3]), 1),
            Action::Error {
                cid: 2,
                code: ERR_CHANNEL_BUSY
            }
        );
        // Continuations from other channels are ignored.
        assert_eq!(a.on_report(&cont_pkt(2, 0, &[0; 59]), 2), Action::None);
        // Original transaction still completes.
        let r = a.on_report(&cont_pkt(1, 0, &[6; 59]), 3);
        let mut want = vec![5u8; 57];
        want.extend_from_slice(&[6; 43]);
        assert_eq!(
            r,
            Action::Complete {
                cid: 1,
                cmd: CMD_CBOR,
                payload: want
            }
        );
    }

    #[test]
    fn same_channel_new_init_is_invalid_seq() {
        let mut a = Assembler::new();
        assert_eq!(
            a.on_report(&init_pkt(1, CMD_CBOR, 100, &[0; 57]), 0),
            Action::None
        );
        assert_eq!(
            a.on_report(&init_pkt(1, CMD_PING, 1, &[0]), 1),
            Action::Error {
                cid: 1,
                code: ERR_INVALID_SEQ
            }
        );
        assert_eq!(a.busy_cid(), None);
    }

    #[test]
    fn timeout() {
        let mut a = Assembler::new();
        assert_eq!(
            a.on_report(&init_pkt(1, CMD_CBOR, 100, &[0; 57]), 1000),
            Action::None
        );
        assert_eq!(a.on_tick(1000 + CONT_TIMEOUT_MS), Action::None);
        assert_eq!(a.busy_cid(), Some(1));
        assert_eq!(
            a.on_tick(1001 + CONT_TIMEOUT_MS),
            Action::Error {
                cid: 1,
                code: ERR_MSG_TIMEOUT
            }
        );
        assert_eq!(a.busy_cid(), None);
        assert_eq!(a.on_tick(u64::MAX), Action::None);
    }

    #[test]
    fn deadline_saturates() {
        let mut a = Assembler::new();
        assert_eq!(
            a.on_report(&init_pkt(1, CMD_CBOR, 100, &[0; 57]), u64::MAX - 1),
            Action::None
        );
        assert_eq!(a.on_tick(u64::MAX), Action::None);
    }

    #[test]
    fn init_resync() {
        let mut a = Assembler::new();
        assert_eq!(
            a.on_report(&init_pkt(9, CMD_CBOR, 300, &[0; 57]), 0),
            Action::None
        );
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(
            a.on_report(&init_pkt(9, CMD_INIT, 8, &nonce), 1),
            Action::Complete {
                cid: 9,
                cmd: CMD_INIT,
                payload: nonce.to_vec()
            }
        );
        assert_eq!(a.busy_cid(), None);
    }

    #[test]
    fn oversize_bcnt() {
        let mut a = Assembler::new();
        assert_eq!(
            a.on_report(&init_pkt(3, CMD_CBOR, MAX_MSG as u16 + 1, &[]), 0),
            Action::Error {
                cid: 3,
                code: ERR_INVALID_LEN
            }
        );
        assert_eq!(a.busy_cid(), None);
        assert!(fragment(3, CMD_CBOR, &vec![0; MAX_MSG + 1]).is_none());
    }

    #[test]
    fn encoders() {
        let e = error_report(0xaabb_ccdd, ERR_CHANNEL_BUSY);
        assert_eq!(
            &e[..8],
            &[0xaa, 0xbb, 0xcc, 0xdd, CMD_ERROR, 0, 1, ERR_CHANNEL_BUSY]
        );
        assert!(e[8..].iter().all(|&b| b == 0));
        let k = keepalive_report(1, STATUS_UPNEEDED);
        assert_eq!(&k[..8], &[0, 0, 0, 1, CMD_KEEPALIVE, 0, 1, STATUS_UPNEEDED]);
        let r = init_response(&[9; 8], 0x0102_0304, 0x0c);
        assert_eq!(
            r,
            vec![
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                1,
                2,
                3,
                4,
                PROTOCOL_VERSION,
                0,
                1,
                0,
                0x0c
            ]
        );
    }

    #[test]
    fn fragment_round_trip_all_lengths() {
        // Exhaustive over every length 0..=MAX_MSG with pseudo-random cids and bytes
        // (xorshift64; the crate has no proptest dev-dependency).
        let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for len in 0..=MAX_MSG {
            let cid = next() as u32;
            let payload: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let pkts = fragment(cid, CMD_MSG, &payload).unwrap();
            let want_pkts = if len <= INIT_DATA_LEN {
                1
            } else {
                1 + (len - INIT_DATA_LEN).div_ceil(CONT_DATA_LEN)
            };
            assert_eq!(pkts.len(), want_pkts, "len {len}");
            let mut a = Assembler::new();
            assert_eq!(
                assemble(&mut a, &pkts),
                Action::Complete {
                    cid,
                    cmd: CMD_MSG,
                    payload
                },
                "len {len}"
            );
        }
    }
}
