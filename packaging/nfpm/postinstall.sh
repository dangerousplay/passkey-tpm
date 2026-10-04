#!/bin/sh
# Shared post-install steps for the GoReleaser/nfpm binary packages.
set -e
systemd-sysusers /usr/lib/sysusers.d/passkey-tpm.conf || true
modprobe uhid 2>/dev/null || true
udevadm control --reload-rules 2>/dev/null || true
udevadm trigger --subsystem-match=misc --sysname-match=uhid 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true
systemctl reload dbus.service 2>/dev/null || true
cat <<'MSG'
passkey-tpm installed. Next steps:
  1. Enroll a fingerprint if you haven't:   fprintd-enroll
  2. Start the virtual security key:        systemctl --user enable --now passkey-tpm-agent
  3. Check the TPM:                          passkey-tpm-cli tpm status
MSG
