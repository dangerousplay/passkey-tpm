#!/usr/bin/env bash
# End-to-end test on this machine without installing anything:
#   private D-Bus daemon + broker on the real TPM + mock fprintd (auto-match) + agent on
#   /dev/uhid, then libfido2's tools against the virtual device (scripts/e2e-fido2.sh).
# Needs sudo only for temporary ACLs on /dev/uhid, /dev/tpmrm0 and the hidraw node; they are
# removed on exit, and the test user's TPM gates are deleted.
set -euo pipefail
cd "$(dirname "$0")/.."

TCTI=${PASSKEY_TPM_TCTI:-device:/dev/tpmrm0}
me=$(id -un)
work=$(mktemp -d)
pids=()
acls=()

cleanup() {
    set +e
    for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    if [[ -f "$work/state/$(id -u)/gates.v1" ]]; then
        PASSKEY_TPM_TCTI=$TCTI target/release/passkey-tpm-cli user remove --uid "$(id -u)" --state-dir "$work/state"
    fi
    for node in "${acls[@]}"; do sudo -n setfacl -x "u:$me" "$node" 2>/dev/null; done
    rm -rf "$work"
}
trap cleanup EXIT INT TERM HUP

grant() {
    if [[ ! -r "$1" || ! -w "$1" ]]; then
        sudo -n setfacl -m "u:$me:rw" "$1"
        acls+=("$1")
    fi
}

echo "== build"
cargo build --release -q -p passkey-tpm-uvd -p passkey-tpm-agent -p passkey-tpm-cli
cargo build --release -q -p passkey-tpm-uv --example mock-fprintd --features mock

echo "== private bus"
cat > "$work/bus.conf" <<CONF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:dir=$work</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
CONF
dbus-daemon --config-file="$work/bus.conf" --nofork --print-address=1 > "$work/bus.addr" &
pids+=($!)
for _ in $(seq 50); do [[ -s "$work/bus.addr" ]] && break; sleep 0.1; done
export DBUS_SYSTEM_BUS_ADDRESS
DBUS_SYSTEM_BUS_ADDRESS=$(head -n1 "$work/bus.addr")

echo "== services"
grant /dev/tpmrm0
grant /dev/uhid
target/release/examples/mock-fprintd &
pids+=($!)
mkdir -p "$work/state"
STATE_DIRECTORY="$work/state" PASSKEY_TPM_TCTI=$TCTI target/release/passkey-tpm-uvd &
pids+=($!)
sleep 1
target/release/passkey-tpm-agent &
pids+=($!)

hidraw=""
for _ in $(seq 50); do
    for d in /sys/class/hidraw/hidraw*; do
        if grep -q "HID_NAME=passkey-tpm" "$d/device/uevent" 2>/dev/null; then hidraw=/dev/$(basename "$d"); fi
    done
    [[ -n "$hidraw" ]] && break
    sleep 0.1
done
[[ -n "$hidraw" ]] || { echo "virtual device did not appear" >&2; exit 1; }
echo "virtual device: $hidraw"
grant "$hidraw"

echo "== libfido2 (CTAP 2.0 flows)"
scripts/e2e-fido2.sh

if [[ -x "${E2E_PYTHON:-/tmp/pkt-venv/bin/python}" ]]; then
    echo "== python-fido2 (CTAP 2.1 suite)"
    "${E2E_PYTHON:-/tmp/pkt-venv/bin/python}" scripts/e2e_ctap21.py
else
    echo "skipping CTAP 2.1 suite: create a venv with 'pip install fido2' and set E2E_PYTHON"
fi
