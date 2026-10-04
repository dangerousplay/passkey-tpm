#!/usr/bin/env bash
# End-to-end check of a running passkey-tpm (broker + agent) with libfido2's tools.
# Requires: fido2-token, fido2-cred, fido2-assert, openssl; the agent's virtual device present.
# Each operation asks for a fingerprint.
set -euo pipefail

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The hidraw node can lag the uhid device by a moment (udev); retry for up to 10 s and
# match by name or by our vendor/product IDs.
dev=""
for _ in $(seq 50); do
    dev=$(fido2-token -L 2>/dev/null | awk -F: '/passkey-tpm|vendor=0x1209, product=0xf1d0/ { print $1; exit }')
    [[ -n "$dev" ]] && break
    sleep 0.2
done
if [[ -z "${dev:-}" ]]; then
    echo "passkey-tpm device not found (is passkey-tpm-agent running?)" >&2
    exit 1
fi
echo "device: $dev"
fido2-token -I "$dev"

# No UV flag on -M/-G: libfido2 versions differ (`-v` may prompt for a PIN, `-t uv=true`
# is 1.15+), and passkey-tpm verifies the fingerprint on every operation anyway. The -V -v
# verifications below require the UV bit in the signed authenticator data.

rp=e2e.passkey-tpm.test
cdh=$(head -c32 /dev/urandom | base64)
uid=$(head -c16 /dev/urandom | base64)

echo "== makeCredential (touch the fingerprint reader)"
printf '%s\n%s\n%s\n%s\n' "$cdh" "$rp" "e2e user" "$uid" > "$work/cred.in"
fido2-cred -M -i "$work/cred.in" -o "$work/cred.out" "$dev" es256
fido2-cred -V -v -i "$work/cred.out" -o "$work/cred.pub" es256   # verifies attestation and the UV flag
cred_id=$(sed -n 5p "$work/cred.out")

echo "== getAssertion (touch the fingerprint reader)"
cdh2=$(head -c32 /dev/urandom | base64)
printf '%s\n%s\n%s\n' "$cdh2" "$rp" "$cred_id" > "$work/assert.in"
fido2-assert -G -i "$work/assert.in" -o "$work/assert.out" "$dev"
fido2-assert -V -v -i "$work/assert.out" "$work/cred.pub" es256

echo "OK: registration and UV assertion verified"
