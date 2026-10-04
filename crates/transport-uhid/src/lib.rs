//! Virtual FIDO HID transport over the Linux `uhid` interface.
//!
//! This crate creates a virtual HID device through `/dev/uhid` and exchanges
//! `struct uhid_event` messages with the kernel. The wire layout is encoded and
//! decoded by hand from byte buffers, so the crate needs no `unsafe` code and no
//! FFI bindings.
//!
//! The authoritative ABI is `include/uapi/linux/uhid.h` (all structs are
//! `__attribute__((packed))`, fields are host-endian) together with
//! `drivers/hid/uhid.c`, which:
//!
//! * accepts writes shorter than `sizeof(struct uhid_event)` and zero-extends
//!   them (`memset` + `copy_from_user(min(count, sizeof))`), so only the used
//!   prefix of each event is written;
//! * returns exactly one event per `read()`, truncated to the buffer length, and
//!   requires a buffer of at least 4 bytes.
//!
//! Typical use: [`UhidDevice::create`] with [`fido_device_params`], then read
//! events in a blocking thread with [`UhidDevice::read_event`] (the first one is
//! normally [`UhidEvent::Start`]) while another thread sends input reports
//! through a [`UhidWriter`] obtained from [`UhidDevice::try_clone_writer`].
#![forbid(unsafe_code)]
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

/// Path of the uhid character device.
pub const UHID_PATH: &str = "/dev/uhid";

/// Linux bus type for USB devices (`BUS_USB` in `linux/input.h`).
pub const BUS_USB: u16 = 0x03;

/// Maximum payload of input/output reports (`UHID_DATA_MAX`).
pub const UHID_DATA_MAX: usize = 4096;

/// Maximum report descriptor size (`HID_MAX_DESCRIPTOR_SIZE` in `linux/hid.h`).
pub const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;

/// Event type numbers from `enum uhid_event_type`.
pub mod event_type {
    /// `UHID_DESTROY` (user space to kernel).
    pub const DESTROY: u32 = 1;
    /// `UHID_START` (kernel to user space).
    pub const START: u32 = 2;
    /// `UHID_STOP` (kernel to user space).
    pub const STOP: u32 = 3;
    /// `UHID_OPEN` (kernel to user space).
    pub const OPEN: u32 = 4;
    /// `UHID_CLOSE` (kernel to user space).
    pub const CLOSE: u32 = 5;
    /// `UHID_OUTPUT` (kernel to user space).
    pub const OUTPUT: u32 = 6;
    /// `UHID_GET_REPORT` (kernel to user space).
    pub const GET_REPORT: u32 = 9;
    /// `UHID_GET_REPORT_REPLY` (user space to kernel).
    pub const GET_REPORT_REPLY: u32 = 10;
    /// `UHID_CREATE2` (user space to kernel).
    pub const CREATE2: u32 = 11;
    /// `UHID_INPUT2` (user space to kernel).
    pub const INPUT2: u32 = 12;
    /// `UHID_SET_REPORT` (kernel to user space).
    pub const SET_REPORT: u32 = 13;
    /// `UHID_SET_REPORT_REPLY` (user space to kernel).
    pub const SET_REPORT_REPLY: u32 = 14;
}

/// Report type numbers from `enum uhid_report_type`.
pub mod report_type {
    /// `UHID_FEATURE_REPORT`.
    pub const FEATURE: u8 = 0;
    /// `UHID_OUTPUT_REPORT`.
    pub const OUTPUT: u8 = 1;
    /// `UHID_INPUT_REPORT`.
    pub const INPUT: u8 = 2;
}

/// Byte offsets of `struct uhid_event` fields, measured from the start of the
/// event (the `__u32 type` field occupies bytes 0..4; the union starts at 4).
pub mod layout {
    use super::{HID_MAX_DESCRIPTOR_SIZE, UHID_DATA_MAX};

    /// Offset of `type`.
    pub const TYPE: usize = 0;
    /// Offset of the payload union `u`.
    pub const PAYLOAD: usize = 4;

    /// `uhid_create2_req.name` (`__u8[128]`).
    pub const CREATE2_NAME: usize = PAYLOAD;
    /// Length of `uhid_create2_req.name`.
    pub const CREATE2_NAME_LEN: usize = 128;
    /// `uhid_create2_req.phys` (`__u8[64]`).
    pub const CREATE2_PHYS: usize = CREATE2_NAME + CREATE2_NAME_LEN;
    /// Length of `uhid_create2_req.phys`.
    pub const CREATE2_PHYS_LEN: usize = 64;
    /// `uhid_create2_req.uniq` (`__u8[64]`).
    pub const CREATE2_UNIQ: usize = CREATE2_PHYS + CREATE2_PHYS_LEN;
    /// Length of `uhid_create2_req.uniq`.
    pub const CREATE2_UNIQ_LEN: usize = 64;
    /// `uhid_create2_req.rd_size` (`__u16`).
    pub const CREATE2_RD_SIZE: usize = CREATE2_UNIQ + CREATE2_UNIQ_LEN;
    /// `uhid_create2_req.bus` (`__u16`).
    pub const CREATE2_BUS: usize = CREATE2_RD_SIZE + 2;
    /// `uhid_create2_req.vendor` (`__u32`).
    pub const CREATE2_VENDOR: usize = CREATE2_BUS + 2;
    /// `uhid_create2_req.product` (`__u32`).
    pub const CREATE2_PRODUCT: usize = CREATE2_VENDOR + 4;
    /// `uhid_create2_req.version` (`__u32`).
    pub const CREATE2_VERSION: usize = CREATE2_PRODUCT + 4;
    /// `uhid_create2_req.country` (`__u32`).
    pub const CREATE2_COUNTRY: usize = CREATE2_VERSION + 4;
    /// `uhid_create2_req.rd_data` (`__u8[HID_MAX_DESCRIPTOR_SIZE]`).
    pub const CREATE2_RD_DATA: usize = CREATE2_COUNTRY + 4;
    /// End of a full `UHID_CREATE2` event.
    pub const CREATE2_END: usize = CREATE2_RD_DATA + HID_MAX_DESCRIPTOR_SIZE;

    /// `uhid_input2_req.size` (`__u16`).
    pub const INPUT2_SIZE: usize = PAYLOAD;
    /// `uhid_input2_req.data` (`__u8[UHID_DATA_MAX]`).
    pub const INPUT2_DATA: usize = INPUT2_SIZE + 2;
    /// End of a full `UHID_INPUT2` event.
    pub const INPUT2_END: usize = INPUT2_DATA + UHID_DATA_MAX;

    /// `uhid_output_req.data` (`__u8[UHID_DATA_MAX]`).
    pub const OUTPUT_DATA: usize = PAYLOAD;
    /// `uhid_output_req.size` (`__u16`).
    pub const OUTPUT_SIZE: usize = OUTPUT_DATA + UHID_DATA_MAX;
    /// `uhid_output_req.rtype` (`__u8`).
    pub const OUTPUT_RTYPE: usize = OUTPUT_SIZE + 2;
    /// End of a full `UHID_OUTPUT` event.
    pub const OUTPUT_END: usize = OUTPUT_RTYPE + 1;

    /// `uhid_get_report_req.id` / `uhid_set_report_req.id` (`__u32`).
    pub const REPORT_ID: usize = PAYLOAD;
    /// `rnum` (`__u8`) of get/set report requests.
    pub const REPORT_RNUM: usize = REPORT_ID + 4;
    /// `rtype` (`__u8`) of get/set report requests.
    pub const REPORT_RTYPE: usize = REPORT_RNUM + 1;
    /// End of a `UHID_GET_REPORT` event.
    pub const GET_REPORT_END: usize = REPORT_RTYPE + 1;
    /// `uhid_set_report_req.size` (`__u16`).
    pub const SET_REPORT_SIZE: usize = REPORT_RTYPE + 1;
    /// `uhid_set_report_req.data` (`__u8[UHID_DATA_MAX]`).
    pub const SET_REPORT_DATA: usize = SET_REPORT_SIZE + 2;
    /// End of a full `UHID_SET_REPORT` event.
    pub const SET_REPORT_END: usize = SET_REPORT_DATA + UHID_DATA_MAX;

    /// `uhid_*_report_reply_req.id` (`__u32`).
    pub const REPLY_ID: usize = PAYLOAD;
    /// `uhid_*_report_reply_req.err` (`__u16`).
    pub const REPLY_ERR: usize = REPLY_ID + 4;
    /// End of a `UHID_SET_REPORT_REPLY` event.
    pub const SET_REPORT_REPLY_END: usize = REPLY_ERR + 2;
    /// `uhid_get_report_reply_req.size` (`__u16`).
    pub const GET_REPORT_REPLY_SIZE: usize = REPLY_ERR + 2;
    /// End of a `UHID_GET_REPORT_REPLY` event carrying no data.
    pub const GET_REPORT_REPLY_HEADER_END: usize = GET_REPORT_REPLY_SIZE + 2;

    /// `sizeof(struct uhid_event)`: `type` plus the largest union member
    /// (`uhid_create2_req`, 276 + 4096 bytes).
    pub const EVENT_SIZE: usize = CREATE2_END;
}

/// Errno sent back to the kernel for unsupported GET/SET_REPORT requests
/// (`EIO`, which is 5 on every Linux architecture).
const EIO: u16 = 5;

/// Parameters of the virtual HID device (the `UHID_CREATE2` request).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceParams {
    /// Device name (`name[128]`); at most 127 bytes, no NUL.
    pub name: String,
    /// Physical location (`phys[64]`); at most 63 bytes, no NUL.
    pub phys: String,
    /// Unique identifier (`uniq[64]`); at most 63 bytes, no NUL.
    pub uniq: String,
    /// USB vendor ID.
    pub vendor: u32,
    /// USB product ID.
    pub product: u32,
    /// Device version.
    pub version: u32,
    /// Bus type, for example [`BUS_USB`].
    pub bus: u16,
    /// HID report descriptor (1 to 4096 bytes).
    pub report_descriptor: Vec<u8>,
}

/// Standard FIDO HID report descriptor (CTAP 2.x §11.2.8.1 / FIDO U2F HID
/// protocol): usage page 0xF1D0, usage 0x01 (CTAPHID), one 64-byte input report
/// (usage 0x20) and one 64-byte output report (usage 0x21), no report IDs.
pub const FIDO_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance 0xF1D0)
    0x09, 0x01, // Usage (CTAPHID)
    0xA1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x81, 0x02, //   Input (Data, Variable, Absolute)
    0x09, 0x21, //   Usage (Output Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x91, 0x02, //   Output (Data, Variable, Absolute)
    0xC0, // End Collection
];

/// Device name announced to the kernel.
pub const FIDO_DEVICE_NAME: &str = "passkey-tpm";
/// pid.codes open-source vendor ID.
pub const FIDO_VENDOR_ID: u32 = 0x1209;
/// Placeholder product ID.
// TODO(pid.codes): request a dedicated product ID from pid.codes; 0xF1D0 is a
// commonly used test PID and must not ship in a stable release.
pub const FIDO_PRODUCT_ID: u32 = 0xF1D0;

/// Parameters for the passkey-tpm virtual FIDO authenticator.
#[must_use]
pub fn fido_device_params() -> DeviceParams {
    DeviceParams {
        name: FIDO_DEVICE_NAME.to_owned(),
        phys: String::new(),
        uniq: String::new(),
        vendor: FIDO_VENDOR_ID,
        product: FIDO_PRODUCT_ID,
        version: 0,
        bus: BUS_USB,
        report_descriptor: FIDO_REPORT_DESCRIPTOR.to_vec(),
    }
}

/// An event read from the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UhidEvent {
    /// `UHID_START`: the HID driver bound to the device.
    Start,
    /// `UHID_STOP`: the HID driver unbound from the device.
    Stop,
    /// `UHID_OPEN`: a client opened the device (for example hidraw).
    Open,
    /// `UHID_CLOSE`: the last client closed the device.
    Close,
    /// `UHID_OUTPUT`: an output report written by a client.
    Output(Vec<u8>),
    /// `UHID_GET_REPORT`; already answered with `EIO` by [`UhidDevice::read_event`].
    GetReport {
        /// Request identifier.
        id: u32,
        /// Report number.
        rnum: u8,
        /// Report type (see [`report_type`]).
        rtype: u8,
    },
    /// `UHID_SET_REPORT`; already answered with `EIO` by [`UhidDevice::read_event`].
    SetReport {
        /// Request identifier.
        id: u32,
        /// Report number.
        rnum: u8,
        /// Report type (see [`report_type`]).
        rtype: u8,
        /// Report payload.
        data: Vec<u8>,
    },
    /// Any other event type (the raw type number).
    Other(u32),
}

fn invalid_input(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

fn invalid_data(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn put(buf: &mut [u8], offset: usize, bytes: &[u8]) -> io::Result<()> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or_else(|| invalid_input("uhid field offset overflow"))?;
    buf.get_mut(offset..end)
        .ok_or_else(|| invalid_input("uhid field out of bounds"))?
        .copy_from_slice(bytes);
    Ok(())
}

fn get<const N: usize>(buf: &[u8], offset: usize) -> io::Result<[u8; N]> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| invalid_data("uhid field offset overflow"))?;
    buf.get(offset..end)
        .and_then(|s| <[u8; N]>::try_from(s).ok())
        .ok_or_else(|| invalid_data("truncated uhid event"))
}

fn get_u8(buf: &[u8], offset: usize) -> io::Result<u8> {
    get::<1>(buf, offset).map(|[b]| b)
}

fn get_u16(buf: &[u8], offset: usize) -> io::Result<u16> {
    get(buf, offset).map(u16::from_ne_bytes)
}

fn get_u32(buf: &[u8], offset: usize) -> io::Result<u32> {
    get(buf, offset).map(u32::from_ne_bytes)
}

fn check_string(field: &str, value: &str, capacity: usize) -> io::Result<()> {
    if value.len() >= capacity || value.contains('\0') {
        return Err(invalid_input(format!(
            "uhid {field} must be at most {} bytes without NUL",
            capacity.saturating_sub(1)
        )));
    }
    Ok(())
}

/// Encodes a `UHID_CREATE2` event, truncated after the used descriptor bytes.
///
/// # Errors
///
/// Returns [`io::ErrorKind::InvalidInput`] if a string is too long or contains
/// NUL, or if the descriptor is empty or longer than 4096 bytes.
pub fn encode_create2(params: &DeviceParams) -> io::Result<Vec<u8>> {
    use layout::*;
    check_string("name", &params.name, CREATE2_NAME_LEN)?;
    check_string("phys", &params.phys, CREATE2_PHYS_LEN)?;
    check_string("uniq", &params.uniq, CREATE2_UNIQ_LEN)?;
    let rd = &params.report_descriptor;
    if rd.is_empty() || rd.len() > HID_MAX_DESCRIPTOR_SIZE {
        return Err(invalid_input(format!(
            "invalid HID report descriptor length: {}",
            rd.len()
        )));
    }
    let rd_size =
        u16::try_from(rd.len()).map_err(|_| invalid_input("report descriptor too long"))?;
    let mut buf = vec![0u8; CREATE2_RD_DATA + rd.len()];
    put(&mut buf, TYPE, &event_type::CREATE2.to_ne_bytes())?;
    put(&mut buf, CREATE2_NAME, params.name.as_bytes())?;
    put(&mut buf, CREATE2_PHYS, params.phys.as_bytes())?;
    put(&mut buf, CREATE2_UNIQ, params.uniq.as_bytes())?;
    put(&mut buf, CREATE2_RD_SIZE, &rd_size.to_ne_bytes())?;
    put(&mut buf, CREATE2_BUS, &params.bus.to_ne_bytes())?;
    put(&mut buf, CREATE2_VENDOR, &params.vendor.to_ne_bytes())?;
    put(&mut buf, CREATE2_PRODUCT, &params.product.to_ne_bytes())?;
    put(&mut buf, CREATE2_VERSION, &params.version.to_ne_bytes())?;
    put(&mut buf, CREATE2_COUNTRY, &0u32.to_ne_bytes())?;
    put(&mut buf, CREATE2_RD_DATA, rd)?;
    Ok(buf)
}

/// Encodes a `UHID_INPUT2` event, truncated after the used data bytes.
///
/// # Errors
///
/// Returns [`io::ErrorKind::InvalidInput`] if `data` exceeds 4096 bytes.
pub fn encode_input2(data: &[u8]) -> io::Result<Vec<u8>> {
    use layout::*;
    if data.len() > UHID_DATA_MAX {
        return Err(invalid_input(format!(
            "uhid input report too large: {} bytes",
            data.len()
        )));
    }
    let size = u16::try_from(data.len()).map_err(|_| invalid_input("input report too large"))?;
    let mut buf = vec![0u8; INPUT2_DATA + data.len()];
    put(&mut buf, TYPE, &event_type::INPUT2.to_ne_bytes())?;
    put(&mut buf, INPUT2_SIZE, &size.to_ne_bytes())?;
    put(&mut buf, INPUT2_DATA, data)?;
    Ok(buf)
}

/// Encodes a `UHID_DESTROY` event (type only; the kernel zero-extends it).
#[must_use]
pub fn encode_destroy() -> [u8; 4] {
    event_type::DESTROY.to_ne_bytes()
}

/// Builds a fixed-size reply `[type, id, err]`; the remaining bytes stay zero.
fn encode_reply<const N: usize>(kind: u32, id: u32, err: u16) -> [u8; N] {
    let mut buf = [0u8; N];
    let fields: [(usize, &[u8]); 3] = [
        (layout::TYPE, &kind.to_ne_bytes()),
        (layout::REPLY_ID, &id.to_ne_bytes()),
        (layout::REPLY_ERR, &err.to_ne_bytes()),
    ];
    for (offset, bytes) in fields {
        // Cannot fail: N >= REPLY_ERR + 2 for both callers (checked in tests).
        let _ = put(&mut buf, offset, bytes);
    }
    buf
}

/// Encodes a `UHID_GET_REPORT_REPLY` with an error code and no data.
#[must_use]
pub fn encode_get_report_reply(id: u32, err: u16) -> [u8; layout::GET_REPORT_REPLY_HEADER_END] {
    encode_reply(event_type::GET_REPORT_REPLY, id, err)
}

/// Encodes a `UHID_SET_REPORT_REPLY` with an error code.
#[must_use]
pub fn encode_set_report_reply(id: u32, err: u16) -> [u8; layout::SET_REPORT_REPLY_END] {
    encode_reply(event_type::SET_REPORT_REPLY, id, err)
}

fn sized_payload(buf: &[u8], offset: usize, size: u16, what: &str) -> io::Result<Vec<u8>> {
    let size = usize::from(size);
    if size > UHID_DATA_MAX {
        return Err(invalid_data(format!(
            "{what} size {size} exceeds UHID_DATA_MAX"
        )));
    }
    let end = offset
        .checked_add(size)
        .ok_or_else(|| invalid_data("uhid payload offset overflow"))?;
    buf.get(offset..end)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| invalid_data(format!("truncated {what}")))
}

/// Decodes one event read from the kernel.
///
/// Short events are zero-extended to `sizeof(struct uhid_event)` first, as the
/// ABI requires.
///
/// # Errors
///
/// Returns [`io::ErrorKind::InvalidData`] if the event is shorter than 4 bytes,
/// if a size field exceeds 4096, or if a `UHID_OUTPUT` event carries a report
/// type other than [`report_type::OUTPUT`].
pub fn decode_event(raw: &[u8]) -> io::Result<UhidEvent> {
    use layout::*;
    if raw.len() < PAYLOAD {
        return Err(invalid_data(format!(
            "short uhid event: {} bytes",
            raw.len()
        )));
    }
    let mut buf = vec![0u8; EVENT_SIZE];
    let n = raw.len().min(EVENT_SIZE);
    put(&mut buf, 0, raw.get(..n).unwrap_or_default())?;

    let event = match get_u32(&buf, TYPE)? {
        event_type::START => UhidEvent::Start,
        event_type::STOP => UhidEvent::Stop,
        event_type::OPEN => UhidEvent::Open,
        event_type::CLOSE => UhidEvent::Close,
        event_type::OUTPUT => {
            let rtype = get_u8(&buf, OUTPUT_RTYPE)?;
            if rtype != report_type::OUTPUT {
                return Err(invalid_data(format!(
                    "unexpected uhid output report type {rtype}"
                )));
            }
            let size = get_u16(&buf, OUTPUT_SIZE)?;
            UhidEvent::Output(sized_payload(&buf, OUTPUT_DATA, size, "uhid output")?)
        }
        event_type::GET_REPORT => UhidEvent::GetReport {
            id: get_u32(&buf, REPORT_ID)?,
            rnum: get_u8(&buf, REPORT_RNUM)?,
            rtype: get_u8(&buf, REPORT_RTYPE)?,
        },
        event_type::SET_REPORT => {
            let size = get_u16(&buf, SET_REPORT_SIZE)?;
            UhidEvent::SetReport {
                id: get_u32(&buf, REPORT_ID)?,
                rnum: get_u8(&buf, REPORT_RNUM)?,
                rtype: get_u8(&buf, REPORT_RTYPE)?,
                data: sized_payload(&buf, SET_REPORT_DATA, size, "uhid set_report")?,
            }
        }
        other => UhidEvent::Other(other),
    };
    Ok(event)
}

/// Writes one complete event; a partial write would corrupt the stream, so it
/// is reported as an error instead of being retried.
fn write_event(mut file: &File, buf: &[u8]) -> io::Result<()> {
    loop {
        match file.write(buf) {
            Ok(n) if n == buf.len() => return Ok(()),
            Ok(n) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!("short uhid write: {n} of {} bytes", buf.len()),
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// A virtual HID device backed by `/dev/uhid`.
///
/// The kernel destroys the device when it receives `UHID_DESTROY` or when the
/// last file descriptor (including clones held by [`UhidWriter`]s) is closed.
#[derive(Debug)]
pub struct UhidDevice {
    file: File,
    destroyed: bool,
}

impl UhidDevice {
    /// Opens `/dev/uhid` and creates a device with `UHID_CREATE2`.
    ///
    /// The kernel acknowledges with [`UhidEvent::Start`], which the caller reads
    /// with [`UhidDevice::read_event`]; input reports are rejected (`EINVAL`)
    /// until then.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] for invalid parameters, or the
    /// error from opening or writing `/dev/uhid` (typically `PermissionDenied`
    /// without the udev `uaccess` rule).
    pub fn create(params: &DeviceParams) -> io::Result<Self> {
        Self::create_at(Path::new(UHID_PATH), params)
    }

    /// Like [`UhidDevice::create`], but opens the character device at `path`.
    ///
    /// # Errors
    ///
    /// Same as [`UhidDevice::create`].
    pub fn create_at(path: &Path, params: &DeviceParams) -> io::Result<Self> {
        let request = encode_create2(params)?;
        // std opens files with O_CLOEXEC.
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        write_event(&file, &request)?;
        Ok(Self {
            file,
            destroyed: false,
        })
    }

    /// Blocks until the kernel delivers the next event.
    ///
    /// `UHID_GET_REPORT` and `UHID_SET_REPORT` requests are answered with `EIO`
    /// before being returned, so the requesting client never waits for the
    /// kernel timeout. Interrupted reads are retried.
    ///
    /// # Errors
    ///
    /// Returns read/write errors from the device, or
    /// [`io::ErrorKind::InvalidData`] for malformed events (see
    /// [`decode_event`]).
    pub fn read_event(&mut self) -> io::Result<UhidEvent> {
        let mut buf = vec![0u8; layout::EVENT_SIZE];
        let n = loop {
            match self.file.read(&mut buf) {
                Ok(n) => break n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        };
        let event = decode_event(buf.get(..n).unwrap_or_default())?;
        match &event {
            UhidEvent::GetReport { id, .. } => {
                write_event(&self.file, &encode_get_report_reply(*id, EIO))?;
            }
            UhidEvent::SetReport { id, .. } => {
                write_event(&self.file, &encode_set_report_reply(*id, EIO))?;
            }
            _ => {}
        }
        Ok(event)
    }

    /// Sends an input report (`UHID_INPUT2`) to the kernel.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if `data` exceeds 4096 bytes, or
    /// the write error (the kernel answers `EINVAL` before `UHID_START`).
    pub fn write_input(&self, data: &[u8]) -> io::Result<()> {
        write_event(&self.file, &encode_input2(data)?)
    }

    /// Returns a writer sharing the same open file description, so input
    /// reports can be sent from another thread while this handle blocks in
    /// [`UhidDevice::read_event`]. Each event is a single `write()`, which the
    /// kernel processes under its device lock, so concurrent writers never
    /// interleave.
    ///
    /// # Errors
    ///
    /// Returns the error from duplicating the file descriptor.
    pub fn try_clone_writer(&self) -> io::Result<UhidWriter> {
        Ok(UhidWriter {
            file: self.file.try_clone()?,
        })
    }

    /// Sends `UHID_DESTROY` and closes this handle.
    ///
    /// # Errors
    ///
    /// Returns the write error, for example `EINVAL` if the device was already
    /// destroyed.
    pub fn destroy(mut self) -> io::Result<()> {
        self.destroyed = true;
        write_event(&self.file, &encode_destroy())
    }
}

impl Drop for UhidDevice {
    fn drop(&mut self) {
        if !self.destroyed {
            // Best effort: closing the last descriptor destroys the device anyway.
            let _ = write_event(&self.file, &encode_destroy());
        }
    }
}

/// Write half of a [`UhidDevice`], created by [`UhidDevice::try_clone_writer`].
///
/// Writes fail with `EINVAL` once the device has been destroyed.
#[derive(Debug)]
pub struct UhidWriter {
    file: File,
}

impl UhidWriter {
    /// Sends an input report (`UHID_INPUT2`) to the kernel.
    ///
    /// # Errors
    ///
    /// Same as [`UhidDevice::write_input`].
    pub fn write_input(&self, data: &[u8]) -> io::Result<()> {
        write_event(&self.file, &encode_input2(data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::layout::*;
    use super::*;

    fn u16_at(buf: &[u8], off: usize) -> u16 {
        u16::from_ne_bytes(buf[off..off + 2].try_into().unwrap())
    }

    fn u32_at(buf: &[u8], off: usize) -> u32 {
        u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap())
    }

    #[test]
    fn layout_matches_uhid_h() {
        // Offsets derived by hand from the packed structs in include/uapi/linux/uhid.h.
        assert_eq!(PAYLOAD, 4);
        assert_eq!(CREATE2_NAME, 4);
        assert_eq!(CREATE2_PHYS, 132);
        assert_eq!(CREATE2_UNIQ, 196);
        assert_eq!(CREATE2_RD_SIZE, 260);
        assert_eq!(CREATE2_BUS, 262);
        assert_eq!(CREATE2_VENDOR, 264);
        assert_eq!(CREATE2_PRODUCT, 268);
        assert_eq!(CREATE2_VERSION, 272);
        assert_eq!(CREATE2_COUNTRY, 276);
        assert_eq!(CREATE2_RD_DATA, 280);
        assert_eq!(INPUT2_SIZE, 4);
        assert_eq!(INPUT2_DATA, 6);
        assert_eq!(INPUT2_END, 4102);
        assert_eq!(OUTPUT_DATA, 4);
        assert_eq!(OUTPUT_SIZE, 4100);
        assert_eq!(OUTPUT_RTYPE, 4102);
        assert_eq!(OUTPUT_END, 4103);
        assert_eq!(REPORT_ID, 4);
        assert_eq!(REPORT_RNUM, 8);
        assert_eq!(REPORT_RTYPE, 9);
        assert_eq!(GET_REPORT_END, 10);
        assert_eq!(SET_REPORT_SIZE, 10);
        assert_eq!(SET_REPORT_DATA, 12);
        assert_eq!(SET_REPORT_END, 4108);
        assert_eq!(REPLY_ERR, 8);
        assert_eq!(SET_REPORT_REPLY_END, 10);
        assert_eq!(GET_REPORT_REPLY_SIZE, 10);
        assert_eq!(GET_REPORT_REPLY_HEADER_END, 12);
        // sizeof(uhid_create2_req) = 256 + 2 + 2 + 4 * 4 + 4096 = 4372.
        assert_eq!(CREATE2_END - PAYLOAD, 4372);
        assert_eq!(EVENT_SIZE, 4376);
        const { assert!(EVENT_SIZE >= SET_REPORT_END && EVENT_SIZE >= OUTPUT_END) };
    }

    #[test]
    fn event_type_numbers_match_enum() {
        use event_type::*;
        assert_eq!(
            [DESTROY, START, STOP, OPEN, CLOSE, OUTPUT],
            [1, 2, 3, 4, 5, 6]
        );
        assert_eq!(
            [
                GET_REPORT,
                GET_REPORT_REPLY,
                CREATE2,
                INPUT2,
                SET_REPORT,
                SET_REPORT_REPLY
            ],
            [9, 10, 11, 12, 13, 14]
        );
        assert_eq!(
            [
                report_type::FEATURE,
                report_type::OUTPUT,
                report_type::INPUT
            ],
            [0, 1, 2]
        );
    }

    #[test]
    fn create2_encoding() {
        let params = DeviceParams {
            name: "dev".into(),
            phys: "ph".into(),
            uniq: "u".into(),
            vendor: 0x1209,
            product: 0xF1D0,
            version: 7,
            bus: BUS_USB,
            report_descriptor: vec![0xAA, 0xBB, 0xCC],
        };
        let buf = encode_create2(&params).unwrap();
        assert_eq!(buf.len(), 283);
        assert_eq!(u32_at(&buf, 0), 11);
        assert_eq!(&buf[4..7], b"dev");
        assert!(buf[7..132].iter().all(|&b| b == 0));
        assert_eq!(&buf[132..134], b"ph");
        assert!(buf[134..196].iter().all(|&b| b == 0));
        assert_eq!(&buf[196..197], b"u");
        assert_eq!(u16_at(&buf, 260), 3);
        assert_eq!(u16_at(&buf, 262), 0x03);
        assert_eq!(u32_at(&buf, 264), 0x1209);
        assert_eq!(u32_at(&buf, 268), 0xF1D0);
        assert_eq!(u32_at(&buf, 272), 7);
        assert_eq!(u32_at(&buf, 276), 0);
        assert_eq!(&buf[280..], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn create2_validation() {
        let mut p = fido_device_params();
        p.name = "x".repeat(127);
        assert!(encode_create2(&p).is_ok());
        p.name = "x".repeat(128);
        assert!(encode_create2(&p).is_err());
        p.name = "a\0b".into();
        assert!(encode_create2(&p).is_err());
        p = fido_device_params();
        p.phys = "p".repeat(64);
        assert!(encode_create2(&p).is_err());
        p = fido_device_params();
        p.uniq = "u".repeat(64);
        assert!(encode_create2(&p).is_err());
        p = fido_device_params();
        p.report_descriptor.clear();
        assert!(encode_create2(&p).is_err());
        p.report_descriptor = vec![0; 4097];
        assert!(encode_create2(&p).is_err());
        p.report_descriptor = vec![0; 4096];
        let buf = encode_create2(&p).unwrap();
        assert_eq!(buf.len(), EVENT_SIZE);
        assert_eq!(u16_at(&buf, 260), 4096);
    }

    #[test]
    fn input2_encoding() {
        let data: Vec<u8> = (0..64).collect();
        let buf = encode_input2(&data).unwrap();
        assert_eq!(buf.len(), 70);
        assert_eq!(u32_at(&buf, 0), 12);
        assert_eq!(u16_at(&buf, 4), 64);
        assert_eq!(&buf[6..], &data[..]);
        assert_eq!(encode_input2(&[0; 4096]).unwrap().len(), INPUT2_END);
        assert!(encode_input2(&[0; 4097]).is_err());
        assert_eq!(encode_input2(&[]).unwrap().len(), 6);
    }

    #[test]
    fn destroy_and_reply_encoding() {
        assert_eq!(encode_destroy(), 1u32.to_ne_bytes());

        let get = encode_get_report_reply(0xDEAD_BEEF, 5);
        assert_eq!(get.len(), 12);
        assert_eq!(u32_at(&get, 0), 10);
        assert_eq!(u32_at(&get, 4), 0xDEAD_BEEF);
        assert_eq!(u16_at(&get, 8), 5);
        assert_eq!(u16_at(&get, 10), 0);

        let set = encode_set_report_reply(42, 5);
        assert_eq!(set.len(), 10);
        assert_eq!(u32_at(&set, 0), 14);
        assert_eq!(u32_at(&set, 4), 42);
        assert_eq!(u16_at(&set, 8), 5);
    }

    fn event(kind: u32) -> Vec<u8> {
        let mut buf = vec![0u8; EVENT_SIZE];
        buf[..4].copy_from_slice(&kind.to_ne_bytes());
        buf
    }

    #[test]
    fn decode_simple_events() {
        assert_eq!(decode_event(&event(2)).unwrap(), UhidEvent::Start);
        assert_eq!(decode_event(&event(3)).unwrap(), UhidEvent::Stop);
        assert_eq!(decode_event(&event(4)).unwrap(), UhidEvent::Open);
        assert_eq!(decode_event(&event(5)).unwrap(), UhidEvent::Close);
        assert_eq!(decode_event(&event(99)).unwrap(), UhidEvent::Other(99));
        // Short kernel events are zero-extended.
        assert_eq!(decode_event(&2u32.to_ne_bytes()).unwrap(), UhidEvent::Start);
        assert!(decode_event(&[2, 0, 0]).is_err());
        assert!(decode_event(&[]).is_err());
        // Oversized input is truncated to one event.
        let mut long = event(4);
        long.extend_from_slice(&[0xFF; 16]);
        assert_eq!(decode_event(&long).unwrap(), UhidEvent::Open);
    }

    #[test]
    fn decode_output() {
        let mut buf = event(6);
        let report: Vec<u8> = (0..64).map(|i| i ^ 0x5A).collect();
        buf[4..68].copy_from_slice(&report);
        buf[4100..4102].copy_from_slice(&64u16.to_ne_bytes());
        buf[4102] = report_type::OUTPUT;
        assert_eq!(
            decode_event(&buf).unwrap(),
            UhidEvent::Output(report.clone())
        );

        // A read containing only the used prefix of the event still decodes.
        assert_eq!(
            decode_event(&buf[..OUTPUT_END]).unwrap(),
            UhidEvent::Output(report)
        );

        let mut bad = buf.clone();
        bad[4102] = report_type::FEATURE;
        assert!(decode_event(&bad).is_err());

        let mut big = buf;
        big[4100..4102].copy_from_slice(&4097u16.to_ne_bytes());
        assert!(decode_event(&big).is_err());
    }

    #[test]
    fn decode_get_and_set_report() {
        let mut buf = event(9);
        buf[4..8].copy_from_slice(&0x0102_0304u32.to_ne_bytes());
        buf[8] = 3;
        buf[9] = report_type::FEATURE;
        assert_eq!(
            decode_event(&buf).unwrap(),
            UhidEvent::GetReport {
                id: 0x0102_0304,
                rnum: 3,
                rtype: 0
            }
        );

        let mut buf = event(13);
        buf[4..8].copy_from_slice(&77u32.to_ne_bytes());
        buf[8] = 1;
        buf[9] = report_type::OUTPUT;
        buf[10..12].copy_from_slice(&2u16.to_ne_bytes());
        buf[12..14].copy_from_slice(&[0xAB, 0xCD]);
        assert_eq!(
            decode_event(&buf).unwrap(),
            UhidEvent::SetReport {
                id: 77,
                rnum: 1,
                rtype: 1,
                data: vec![0xAB, 0xCD]
            }
        );

        let mut big = buf;
        big[10..12].copy_from_slice(&4097u16.to_ne_bytes());
        assert!(decode_event(&big).is_err());
    }

    #[test]
    fn fido_descriptor_sanity() {
        let d = FIDO_REPORT_DESCRIPTOR;
        assert_eq!(&d[..3], &[0x06, 0xD0, 0xF1], "usage page 0xF1D0");
        assert_eq!(&d[3..5], &[0x09, 0x01], "usage CTAPHID");
        assert_eq!(&d[5..7], &[0xA1, 0x01], "application collection");
        assert_eq!(*d.last().unwrap(), 0xC0, "end collection");
        assert_eq!(d.len(), 34);
        // Both reports are 64 fields of 8 bits.
        let count_64 = d.windows(2).filter(|w| w == &[0x95, 0x40]).count();
        let size_8 = d.windows(2).filter(|w| w == &[0x75, 0x08]).count();
        assert_eq!((count_64, size_8), (2, 2));
        assert!(d.windows(2).any(|w| w == [0x09, 0x20]));
        assert!(d.windows(2).any(|w| w == [0x09, 0x21]));
        assert!(d.windows(2).any(|w| w == [0x81, 0x02]));
        assert!(d.windows(2).any(|w| w == [0x91, 0x02]));
    }

    #[test]
    fn fido_params() {
        let p = fido_device_params();
        assert_eq!(p.name, "passkey-tpm");
        assert_eq!((p.vendor, p.product, p.bus), (0x1209, 0xF1D0, 0x03));
        assert_eq!(p.report_descriptor, FIDO_REPORT_DESCRIPTOR);
        assert!(encode_create2(&p).is_ok());
    }

    #[test]
    fn create_at_missing_path_fails() {
        let err = UhidDevice::create_at(
            Path::new("/nonexistent/passkey-tpm-uhid"),
            &fido_device_params(),
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn create_rejects_invalid_params_before_open() {
        let mut p = fido_device_params();
        p.report_descriptor.clear();
        let err = UhidDevice::create_at(Path::new("/nonexistent"), &p).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
