# passkey-tpm

Passkeys (FIDO2/WebAuthn) for Linux, stored in your computer's TPM 2.0 chip and unlocked with
your fingerprint. passkey-tpm appears to browsers and other apps as a security key built into
the laptop: no USB key to carry, and the private keys never leave the TPM.

> **Status: pre-alpha.** It works end to end on test machines, but it hasn't had a security
> review and the on-disk format may still change. Don't use it as the only way into an
> important account yet; keep a backup method (another security key, recovery codes).

## Features

- Sign in with passkeys on websites (Firefox, Chrome/Chromium and other browsers that support
  USB security keys), with `pam_u2f`, `systemd-cryptenroll`, SSH (`sk-` keys) and anything
  else that uses libfido2.
- Touch the fingerprint reader to approve. The fingerprint is checked by `fprintd`, the same
  service your login screen uses.
- Optional security-key PIN, protected by the TPM's brute-force lockout.
- Passkeys are bound to this machine and this user. They can't be copied to another computer,
  and other users on the same machine can't use them.
- Discoverable passkeys ("sign in without typing a username"), passkey management from the
  browser, and `hmac-secret` (used by disk unlocking and password managers).

## Requirements

- Linux with a TPM 2.0 (any firmware TPM — AMD fTPM, Intel PTT — or discrete chip). Check
  with `ls /dev/tpmrm0`.
- A fingerprint reader supported by [libfprint](https://fprint.freedesktop.org/supported-devices.html),
  with at least one finger enrolled.
- systemd, D-Bus, polkit, fprintd and tpm2-tss (installed automatically by the packages).

## Install

Download the package for your distribution from the
[releases page](https://github.com/dangerousplay/passkey-tpm/releases), then:

| Distribution | Command |
|---|---|
| Ubuntu 24.04+, Debian 13+ | `sudo apt install ./passkey-tpm_<version>_amd64.deb` |
| Fedora | `sudo dnf install ./passkey-tpm_<version>_amd64.rpm` |
| Arch Linux | `sudo pacman -U ./passkey-tpm_<version>_amd64.pkg.tar.zst` |

Each release also has `checksums.txt` and a source tarball. Distribution repositories
(Debian/Ubuntu, Fedora COPR, AUR) are planned.

## Set up

1. Enroll a fingerprint, if you haven't already. Use your desktop's settings (GNOME: *Settings
   → Users → Fingerprint Login*) or:

   ```sh
   fprintd-enroll
   ```

2. Turn on the virtual security key for your user:

   ```sh
   systemctl --user enable --now passkey-tpm-agent
   ```

3. Check that it found the TPM (optional):

   ```sh
   passkey-tpm-cli tpm status
   ```

The background service (`passkey-tpm-uvd`) starts on demand; there is nothing else to enable.

## Use

**Websites.** Register a passkey as usual and choose *security key* / *USB security key* when
the browser asks where to save it. When asked to verify, touch the fingerprint reader; a
desktop notification shows which site is asking. Try it on <https://webauthn.io>.

**Setting a PIN.** Some sites require a security-key PIN. The browser offers to create one the
first time (Chrome: *Settings → Privacy and security → Security → Manage security keys*), or:

```sh
fido2-token -L                 # find the passkey-tpm device, e.g. /dev/hidraw5
fido2-token -S /dev/hidraw5    # set the PIN
```

After 8 wrong PINs the PIN is blocked; the TPM's lockout also slows down guessing.

**Logging in and sudo with `pam_u2f`.**

```sh
mkdir -p ~/.config/Yubico
pamu2fcfg > ~/.config/Yubico/u2f_keys   # touch the reader when asked
```

Then add `auth sufficient pam_u2f.so cue` to the PAM service you want (see `man pam_u2f`).
Keep a terminal with root open while testing PAM changes.

**Unlocking a LUKS disk.**

```sh
sudo systemd-cryptenroll --fido2-device=auto /dev/nvme0n1p3
```

Disk unlocking at boot needs the agent in the initramfs, which isn't supported yet; this
works for disks unlocked after you log in.

**Managing passkeys.** List and delete passkeys from the browser's security-key settings or
with `fido2-token -L -r /dev/hidrawN`. Resetting the security key (`fido2-token -R`) deletes
all of *your* passkeys and your PIN; it doesn't affect other users.

## Troubleshooting

| Symptom | Check |
|---|---|
| Browser says no security key found | `systemctl --user status passkey-tpm-agent`; `ls -l /dev/uhid` (the package loads the `uhid` module; reboot once after installing if it's missing) |
| Fingerprint never accepted | `fprintd-verify` works? Enroll again with `fprintd-enroll` |
| "TPM not available" | `passkey-tpm-cli tpm status`; enable the TPM / fTPM / PTT in the firmware settings |
| PIN locked or TPM lockout | wait for the TPM lockout to expire (usually minutes to hours), or reset the security key |

Logs: `journalctl -u passkey-tpm-uvd` (system service) and
`journalctl --user -u passkey-tpm-agent` (your session).

## How it works and security

Each passkey is a key pair created inside the TPM. The TPM only signs with it after the
background service proves that you verified (fingerprint or PIN) through a per-user secret
that the TPM itself checks, so a bug or compromise in your session can't use your keys
without you. The core protocol logic is formally verified with
[Verus](https://github.com/verus-lang/verus).

Limitations you should know about:

- A program running as you could show a fake notification and trick you into touching the
  reader for a different site. This is the same as with a USB security key.
- `root` and kernel compromise are out of scope, as are physical attacks on the TPM.
- Passkeys can't be backed up or moved. If the TPM is cleared or the motherboard replaced,
  they're gone, so always register a second sign-in method.

Details: [threat model](docs/threat-model.md) and [TPM policy design](docs/adr/0003-tpm-policy-model.md).

## Uninstall

```sh
systemctl --user disable --now passkey-tpm-agent
sudo apt remove passkey-tpm      # or: dnf remove / pacman -R
```

Your passkeys stay in the TPM and in `/var/lib/passkey-tpm` so a reinstall keeps them. To
delete them permanently (this can't be undone):

```sh
sudo passkey-tpm-cli user remove --uid "$(id -u)"
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [changelog](CHANGELOG.md). Bug reports and
hardware test results (laptop model, TPM vendor, fingerprint reader) are very welcome.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
