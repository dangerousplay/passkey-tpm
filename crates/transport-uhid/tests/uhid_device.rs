//! Integration test against the real `/dev/uhid` (ignored by default).

use std::fs;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use passkey_tpm_transport_uhid::{fido_device_params, UhidDevice, UhidEvent};

/// Finds `/sys/class/hidraw/hidrawN` whose HID device carries `name`.
fn find_hidraw(name: &str) -> Option<PathBuf> {
    let entries = fs::read_dir("/sys/class/hidraw").ok()?;
    entries.flatten().map(|e| e.path()).find(|path| {
        fs::read_to_string(path.join("device/uevent"))
            .map(|uevent| uevent.lines().any(|l| l == format!("HID_NAME={name}")))
            .unwrap_or(false)
    })
}

fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    cond()
}

#[test]
#[ignore = "needs write access to /dev/uhid"]
fn create_start_hidraw_destroy() {
    let mut params = fido_device_params();
    params.name = format!("passkey-tpm-test-{}", std::process::id());
    let name = params.name.clone();

    let mut device = UhidDevice::create(&params).expect("create uhid device");

    // The first event must be UHID_START; read it in a thread to bound the wait.
    let (tx, rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let event = device.read_event();
        tx.send(event).expect("send event");
        device
    });
    let event = rx
        .recv_timeout(Duration::from_secs(3))
        .expect("UHID_START within 3s")
        .expect("read event");
    assert_eq!(event, UhidEvent::Start);
    let device = reader.join().expect("reader thread");

    // Input reports are accepted once started.
    let writer = device.try_clone_writer().expect("clone writer");
    writer.write_input(&[0u8; 64]).expect("write input report");

    let hidraw = wait_until(Duration::from_secs(3), || find_hidraw(&name).is_some())
        .then(|| find_hidraw(&name))
        .flatten()
        .expect("hidraw node for the uhid device");
    let uevent = fs::read_to_string(hidraw.join("device/uevent")).expect("read uevent");
    assert!(
        uevent.contains("HID_ID=0003:00001209:0000F1D0"),
        "unexpected uevent: {uevent}"
    );
    let rd = fs::read(hidraw.join("device/report_descriptor")).expect("read descriptor");
    assert_eq!(
        rd.get(..3),
        Some(&[0x06, 0xD0, 0xF1][..]),
        "FIDO usage page"
    );

    drop(writer);
    device.destroy().expect("destroy");
    assert!(
        wait_until(Duration::from_secs(3), || find_hidraw(&name).is_none()),
        "hidraw node still present after destroy"
    );
}

#[test]
#[ignore = "needs write access to /dev/uhid"]
fn remove_and_recreate_on_the_same_handle() {
    let mut params = fido_device_params();
    params.name = format!("passkey-tpm-test-re-{}", std::process::id());
    let name = params.name.clone();

    let mut device = UhidDevice::create(&params).expect("create uhid device");
    let writer = device.try_clone_writer().expect("clone writer");
    let (tx, rx) = mpsc::channel();
    let reader = thread::spawn(move || loop {
        match device.read_event() {
            Ok(event) => {
                if tx.send(event).is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    });
    let next = |want: UhidEvent| loop {
        let event = rx.recv_timeout(Duration::from_secs(3)).expect("uhid event");
        if event == want {
            break;
        }
    };

    next(UhidEvent::Start);
    let first = wait_until(Duration::from_secs(3), || find_hidraw(&name).is_some())
        .then(|| find_hidraw(&name))
        .flatten()
        .expect("hidraw node");
    let dev_node = PathBuf::from("/dev").join(first.file_name().expect("node name"));
    let stale = fs::OpenOptions::new().write(true).open(&dev_node).ok();

    writer.remove_device().expect("remove");
    assert!(
        wait_until(Duration::from_secs(3), || find_hidraw(&name).is_none()),
        "hidraw node still present after remove"
    );
    if let Some(mut stale) = stale {
        use std::io::Write;
        assert!(
            stale.write_all(&[0u8; 65]).is_err(),
            "a descriptor opened before removal must stop working"
        );
    }

    writer.recreate(&params).expect("recreate");
    next(UhidEvent::Start);
    assert!(
        wait_until(Duration::from_secs(3), || find_hidraw(&name).is_some()),
        "no hidraw node after recreate"
    );
    writer.remove_device().expect("final remove");
    drop(writer);
    drop(rx);
    // The reader blocks until the handle closes; it is detached with the test process.
    drop(reader);
}
