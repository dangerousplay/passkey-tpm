#!/bin/sh
systemctl daemon-reload 2>/dev/null || true
udevadm control --reload-rules 2>/dev/null || true
# Broker state (/var/lib/passkey-tpm) and the passkeys' TPM gates are kept on purpose:
# removing them destroys every passkey. Use `passkey-tpm user remove` to delete them.
exit 0
