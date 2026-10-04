#!/bin/sh
# Stop the broker before its files go away. Per-user agents stop with the session.
systemctl stop passkey-tpm-uvd.service 2>/dev/null || true
exit 0
