# State

**Last Updated:** 2026-10-03
**Current Work:** VM test bed green on Ubuntu 24.04 (38 pytest scenarios, real fprintd via libfprint's virtual device, swtpm); next: more scenarios (browser over uhid, pam_u2f, cryptenroll, SRK variants) and the distro matrix.

---

## Recent Decisions (Last 60 days)

### AD-001: Rewrite in Rust in a new repository; freeze Go (2026-10-03)

**Decision:** Start a new Rust repo under a new name. The Go repo `tpm-fido2-thinkpad-linux` gets no further changes and will be archived with a pointer.
**Reason:** Secret hygiene (zeroize, no GC copies), formal verification tooling (Verus/Kani), and alignment with the Rust Linux passkey ecosystem (credentialsd, libwebauthn, zbus, tss-esapi).
**Trade-off:** Current Go users keep the known CRITICAL/HIGH issues (CONCERNS.md) until the Rust M1 ships. We give up pure-Go static builds, since tss-esapi links tpm2-tss.
**Impact:** All of M1 is greenfield. The Go code is a behavioural reference only.

### AD-002: Architecture = standalone provider with two front-ends (2026-10-03)

**Decision:** One daemon: a verified CTAP core, the TPM backend and pluggable UV. Front-ends: (1) a uhid CTAPHID virtual key, (2) a credentialsd provider D-Bus API co-designed with linux-credentials.
**Reason:** uhid works today with browsers, pam_u2f and systemd-cryptenroll. The portal is the long-term sandbox-safe path. credentialsd has a TPM platform authenticator on its roadmap but no provider API yet (#8, #26).
**Trade-off:** Two transports to maintain. The provider API may change upstream.
**Impact:** Transport-agnostic core API; the provider front-end stays swappable.

### AD-003: Own verified core, reuse ecosystem types (2026-10-03)

**Decision:** Write our own sync, no-unsafe CTAP core and verify it with Verus/Kani. Reuse `ctap-types` or `passkey-types` (ADR-004 pending), `coset`, `ciborium` and RustCrypto.
**Reason:** passkey-rs `Authenticator` would limit verification to our glue code. The state machines are small and high-value to prove.
**Trade-off:** More code to write than plugging into passkey-rs.
**Impact:** The core crate is designed for verification: pure `step` functions and UV evidence tokens.

### AD-004: License MIT OR Apache-2.0 (2026-10-03)

**Decision:** Dual-license the new project; credit psanford/tpm-fido (MIT) in NOTICE.
**Reason:** Rust norm, distro-friendly, compatible with the MIT origin.
**Impact:** Code from GPL competitors (passkeyd, Passless) can't be copied. LGPL credentialsd code can only be used across a process/API boundary.

### AD-005: Name `passkey-tpm` (2026-10-03)

**Decision:** The project, repository, crate prefix and distro package are all named `passkey-tpm`.
**Reason:** Descriptive and distro-friendly; free on crates.io as of 2026-10-03.
**Impact:** Crates `passkey-tpm-core`, `passkey-tpm-tpm` and so on; D-Bus/polkit IDs need a reverse-DNS prefix (pending a domain/org choice).

### AD-006: `cargo xtask` + clippy + cargo-deny as mandatory gates (2026-10-03)

**Decision:** All dev and CI tasks run through `cargo xtask`. Clippy runs with `-D warnings` and workspace lints, with stricter panic and indexing lints on `core`. cargo-deny checks licenses, advisories, bans and sources. The CI pipeline only invokes xtask tasks.
**Reason:** Local and CI runs stay identical, there's no shell-script drift, and supply-chain policy is enforced, which distro packagers and security reviewers check.
**Impact:** `xtask` crate in the workspace from M0; every task's gate check in tasks.md uses `cargo xtask ci` or a subtask.

### AD-007: ADR-003 TPM policy model — ACCEPTED (2026-10-03)

**Decision:** Privileged broker `passkey-tpm-uvd` is the only holder of gate secrets. Each credential key's authPolicy is `PolicyOR` over per-user `PolicySecret` gates (PIN = NV index with DA; UV/UP = keyedHash with noDA), with policyRef = SHA-256(tag ‖ rpIdHash). hmac-secret uses two TPM HMAC keys. Counter is 0. Details: `.specs/features/tpm-policy-model/design.md`.
**Reason:** It is the only option that stops T1, T2 (gesture required), T4 and T5 under TPM enforcement. PolicySigned adds cost and nothing more once there is a sole broker.
**Trade-off:** Needs a system service, polkit rules and some tss-esapi-sys FFI (DA, NV_ChangeAuth). DA lockout is global.
**Impact:** Supersedes the "per-user daemon" wording in AD-002: the verified core moves into the broker, and the agent becomes transport + UI.

### AD-008: Split verified code into `core` (Verus) and `wire` (Kani) crates (2026-10-03)

**Decision:** Parsers and codecs (CBOR, CTAPHID packets, credential ID, state files) live in `passkey-tpm-wire`, which has no `vstd` dependency and is checked with Kani + fuzzing. State machines and policy logic live in `passkey-tpm-core`, which is verified with Verus.
**Reason:** Verus 0.2026.09.27 requires Rust 1.98.1 and `vstd`. Kani 0.64 ships its own nightly (1.90, 2025-07-02), which may not compile `vstd`. Keeping them in separate crates means each tool only sees code it supports.
**Trade-off:** One more crate; the core depends on wire types.
**Impact:** Tasks that put codecs in `passkey-tpm-core` (tpm-policy-model T2, T3) target `passkey-tpm-wire` instead.

### AD-009: Toolchain pins (2026-10-03)

**Decision:** Rust 1.98.1 (rust-toolchain.toml); Verus `release/0.2026.09.27.3cf1832` (x86-linux zip sha256 `43814031e10df043221d83c7fa842e3ebd662cb7b0090fc1eb4d7a8673226978`) with `vstd = "=0.0.0-2026-09-20-0158"` (the version `cargo verus new` generates for this release); Kani 0.64.0; cargo-deny 0.20.x.
**Impact:** Upgrades happen through a single PR that bumps `tools/*.toml` and rust-toolchain.toml together.

### AD-010: CTAP spec decisions from T0 (2026-10-03)

**Decision:** Packed self-attestation (zero AAGUID, no x5c) instead of `none`. Advertise `maxMsgSize` ≥ 2048 and `maxCredentialIdLength`. Reaching 0 PIN retries also disables fingerprint UV until reset. The persisted retry counter is decremented before every PIN check. TPM DA maxTries must be > 8.
**Reason:** CTAP 2.1/2.2 and WebAuthn L3 text (see the tpm-policy-model research.md T0 section).
**Impact:** Verified-core feature (PIN state machine, getInfo) and the attestation builder.

### AD-011: PIN change by NV undefine + redefine, no FFI (2026-10-03)

**Decision:** `pin_gate::rotate` checks the old PIN with a trial-session PolicySecret (DA-counted), then undefines the NV index and defines it again with the same public area and the new authValue.
**Reason:** tss-esapi 7.7 keeps its raw ESYS context private, so `NV_ChangeAuth` would need a second raw context and a hand-built policy session over FFI. Verified on swtpm: the Name is byte-identical, the old PIN fails with `TPM_RC_AUTH_FAIL`, and the policy digest is unchanged.
**Trade-off:** The index doesn't exist for a moment during rotation. The broker must persist the new auth first and re-define on startup if the index is missing. Requires Owner hierarchy authorisation (empty by default), the same as provisioning.
**Impact:** The `passkey-tpm-tpm` crate has no `unsafe`. tpm-policy-model T7 is replaced; T13 uses `pin_gate::rotate`.

### AD-012: MVP-1 protocol cut (2026-10-03)

**Decision:** Advertise `FIDO_2_0` only. Every operation requires a fingerprint match (UP+UV, UV gate). Credentials are created at credProtect level 3. A credential ID tag (HMAC with per-user K_uid) identifies own credentials before any gesture. Silent probes (`up=false`) get NO_CREDENTIALS, or UNSUPPORTED_OPTION when a matching credential exists. pinAuth means touch, then PIN_NOT_SET.
**Reason:** Browsers send `uv` as a plain option to 2.0 authenticators (no pinUvAuthToken needed), and hmac-secret isn't mandatory. Smallest secure cut.
**Impact:** MVP-2 adds `FIDO_2_1`: clientPIN, getPinUvAuthTokenUsingUv, hmac-secret on the wire, credMgmt, and a presence-only gate.

### AD-013: ADR-003 amendment — NV-index gates, single-branch policies, bus-aware sessions (2026-10-03)

**Decision:**
1. UV and UP gates are NV indexes (`noDA`), like the PIN gate. `PolicySecret` uses them without `TPM2_Load`.
2. Key branches are `PolicySecret(gate, policyRef)` only. There is no `PolicyCommandCode`: admin-role commands stay blocked by `adminWithPolicy`, and USER-role use still requires the gate.
3. The PIN is not a policy branch. The broker verifies it against the DA-protected PIN gate (the TPM compares), then uses the UV gate. credProtect=3 keys have a single branch (no PolicyOR).
4. Sessions follow `BusProtection`: firmware TPMs (AMD/INTC/MSFT manufacturer IDs) use password authorisation and unsalted sessions; discrete TPMs use salted, parameter-encrypted sessions. `PASSKEY_TPM_BUS_PROTECTION` overrides.
5. Command order: build the policy first, load the key last.
6. Any TCG SRK at 0x81000001 is reused (RSA-2048 or ECC P-256); the ECC one is created only if the slot is empty.
**Reason:** Real AMD fTPM measurements: 2521 ms → 577 ms per assertion. Each live context costs ~60 ms per command through the kernel resource manager; gate object Load alone was ~600 ms. The machine already had an RSA SRK (Windows/systemd), which our ECC-only check refused.
**Trade-off:** The PIN no longer cryptographically binds credentials on its own. A broker compromise exposes the UV gate secret either way, so the security against T1–T5 is unchanged (threat model updated). Firmware TPMs carry authValues in clear inside the SoC (no external bus).
**Impact:** gates.v1 holds three NV gates; `nvgate` replaces `pin_gate`; `TpmOps::verify_pin`/`pin_is_set` added.

### AD-014: VM test bed = mkosi + QEMU/KVM + swtpm + libfprint virtual driver (2026-10-03)

**Decision:** Scenarios that can't run on a developer machine (real fprintd + polkit + D-Bus activation, package install, systemd hardening, discrete-TPM encrypted sessions, SRK variants, two-user isolation, wrong-PIN/DA tests, browsers over uhid, pam_u2f, systemd-cryptenroll) run in mkosi-built VMs. Each VM gets a throwaway swtpm TPM (`QemuSwtpm=`), and fprintd uses libfprint's virtual device driver so the harness can "touch" the sensor. `cargo xtask vm` drives it locally and in a nightly CI job. First target: **Ubuntu 24.04 (noble)**; other distros follow as mkosi profiles.
**Reason:** One config builds images for every target distro; systemd uses mkosi in its own CI; it boots with a TPM out of the box and runs the same way locally and on GitHub runners (KVM). Vagrant (vagrant-libvirt `tpm_*` options, or VirtualBox 7) stays an optional local path: slower, awkward in CI, one distro per box.
**Trade-off:** Image builds need network access and minutes, so this runs in the slow tier, never in the fast gates (AD-006, the fast-validation preference).
**Impact:** `tests/vm/` mkosi config; `cargo xtask vm`; nightly workflow job.

### AD-015: Portability policy for FreeBSD/NetBSD (2026-10-03)

**Decision:** Linux remains the only supported platform. `passkey-tpm-core` and `passkey-tpm-wire` must stay OS-independent; `cargo xtask portability` (part of the fast gates) checks them for `x86_64-unknown-freebsd`. OS-specific pieces (uhid, systemd, udev, fprintd, the kernel TPM resource manager) stay behind the existing traits.
**Reason:** The verified CTAP core is the most reusable asset and ports for free. The blocker on BSD is the transport: there is no userspace HID-device creation like Linux uhid (CUSE on FreeBSD is unverified). FreeBSD also has no in-kernel TPM resource manager (tpm2-abrmd needed); NetBSD's TPM 2.0 and tpm2-tss support are uncertain. BSD desktop users are a small share of the audience.
**Impact:** One extra fast CI step (a few seconds). A BSD port is a deferred idea.

### AD-016: Upstream release artifacts with GoReleaser + git-cliff (2026-10-04)

**Decision:** A `v*` tag runs `.github/workflows/release.yml`: the fast gate, `cargo xtask changelog --latest` (git-cliff, GitHub-linked notes from Conventional Commits) and `cargo xtask release --publish` (GoReleaser OSS: Rust builder for the CLI, nfpm `.deb`/`.rpm`/Arch packages of the `cargo xtask dist` tree, checksums, source tarball, draft GitHub release). Both tools are pinned and checksum-verified in `tools/` like the other tools. CI builds a snapshot on every PR (`release` gate step). `CHANGELOG.md` is generated, never hand-edited.
**Reason:** One declarative file replaces per-format packaging scripts in CI; the same commands run locally. `cargo xtask dist` stays the single install layout, so GoReleaser packages and distro recipes (debian/, spec, PKGBUILD) can't drift. The `prebuilt` builder is Pro-only, hence a real Rust build of the CLI to give nfpm an architecture.
**Trade-off:** Binary packages target Ubuntu 24.04 library names (deb) and glibc ≥ 2.39; they're a convenience channel, not a replacement for distro packaging (M3). git-cliff runs `--offline` without `GITHUB_TOKEN`.
**Impact:** `.goreleaser.yaml`, `cliff.toml`, `packaging/nfpm/`, `xtask` tasks `changelog` and `release`; end-user `README.md`, developer docs in `CONTRIBUTING.md`.

---

## Active Blockers

### B-001: credentialsd provider API not yet designed

**Discovered:** 2026-10-03
**Impact:** Medium. Blocks M4 only.
**Workaround:** Ship uhid first and draft our own D-Bus interface.
**Resolution:** Engage linux-credentials (Matrix `#credentials-for-linux:matrix.org`, issues #8/#26) during M0.

### B-002: tss-esapi 7.7.0 API gaps — PARTIALLY RESOLVED (2026-10-03)

**Update:** `NV_ChangeAuth` is no longer needed. PIN changes undefine and redefine the NV index with the same public area; the Name doesn't cover authValue, so it stays identical (AD-011). Still missing: setting DA parameters (admin-only; use `tpm2_dictionarylockout` or add FFI later). Reading the DA state works through the safe `get_capability`.

**Discovered:** 2026-10-03
**Impact:** Medium. No DictionaryAttackLockReset/Parameters, `NV_ChangeAuth` or `tr_sess_get_nonce_tpm` (the last two exist in 8.0.0-alpha.3).
**Workaround:** A small audited `tss-esapi-sys` FFI module (the only `unsafe` in the TPM crate).
**Resolution:** Move to tss-esapi 8.0 once it is stable and packaged; consider upstreaming the DA bindings.

### B-003: `vstd` is a build dependency of the core

**Discovered:** 2026-10-03
**Impact:** Medium for distro packaging (G4). `vstd` and `verus_builtin*` are not in Debian or Fedora.
**Workaround:** None yet.
**Resolution:** Investigate making `vstd` optional, with ghost code erased via a cfg (`verus_only`) and exec code compiled without the macro. Otherwise package `vstd` for Debian. Decide before M3.

---

## Lessons Learned

### L-004: Gates must be per user, resolved from caller credentials

**Context:** The first draft of the M4 model had global UV/UP gates.
**Problem:** User B, given user A's credential ID (any RP returns it in allowCredentials), could pass B's own fingerprint check and sign as A.
**Solution:** One gate set per uid, with the uid taken from D-Bus caller credentials and never from the payload (TPM-05).
**Prevents:** Cross-user credential use on shared machines.


### L-001: User verification in software only is not user verification

**Context:** In the Go implementation, the TPM child keys have empty auth and no policy (`tpm/tpm.go:94-115`). The fingerprint check is an `if` in the daemon.
**Problem:** Any process with `/dev/tpmrm0` access (the `tss` group) plus a credential ID can sign without a fingerprint.
**Solution:** Bind keys to a TPM policy whose satisfaction depends on UV (ADR-003, M1).
**Prevents:** Same-host bypass of the UV gate.

### L-002: Never put derivation secrets in the credential ID

**Context:** The hmac-secret CredRandom is `HMAC(seed, "credential-random")`, and the seed is stored in plaintext in the credential ID (`tpm/tpm.go:189,194-219`).
**Problem:** The RP, or anyone who has seen the credential ID, can compute the PRF outputs offline.
**Solution:** Keep CredRandom inside the TPM (a sealed object or a TPM HMAC key).
**Prevents:** PRF/E2EE key compromise.

### L-003: Every peer-controlled length must be validated before crypto primitives

**Context:** `cipher.CryptBlocks` panics when `saltEnc` is not a multiple of 16 bytes (`ctap2/hmacsecret.go:101`). The attacker controls the ECDH, so the `saltAuth` check doesn't stop it. There is also no `recover` and no on-curve check on the platform key.
**Solution:** Validate lengths up front; panic-free parsers proven with Kani.

### L-005: Check TPM constants against a real TPM, never only against memory

**Context:** The software policy calculator had `TPM_CC_NV_ChangeAuth = 0x13C`; the correct value is `0x13B`.
**Problem:** The PIN gate's change policy would have been unsatisfiable: PIN changes would fail at runtime on real hardware.
**Solution:** The `policy_kat` integration tests compare every policy function with an swtpm trial session.
**Prevents:** Silent policy-digest mismatches, which surface only as "policy fail" on users' machines.

### L-006: Simulators hide the cost model that matters; benchmark on real TPMs early

**Context:** swtpm ran every operation in ~15 ms. The AMD fTPM took 2.5 s per assertion.
**Problem:** The kernel resource manager (`/dev/tpmrm0`) reloads every live context of a connection before each command and saves it after; on the AMD fTPM that costs ~60 ms per context per command. Sealed-object gates needed a 600 ms Load. Real machines also come with an RSA SRK already provisioned.
**Solution:** Hardware benchmark plus a per-command breakdown; NV-index gates; policy before key load; reuse any TCG SRK.
**Prevents:** Designs that pass CI but are unusable on real laptops.

### L-007: Every test that touches a real TPM must clean up on every exit path

**Context:** An interrupted E2E run left three passkey-tpm NV gates on the real TPM; its state dir (with their secrets) was already deleted. The NV scan also showed indexes from other software (systemd/OEM) inside our then-broad allocation range.
**Solution:** The harness traps EXIT/INT/TERM/HUP; `passkey-tpm tpm status` lists our NV indexes; orphans were verified against our exact template before deletion; the allocation range is narrowed to 0x01500000–0x0150FFFF.
**Prevents:** Leaking NV space on users' TPMs and touching other software's indexes.

### L-008: The VM test bed found three packaging bugs no host test could see

**Context:** First runs of the Ubuntu 24.04 mkosi VM (AD-014).
**Problems:**
1. `uhid` wasn't loaded on a fresh system, and the package shipped no `modules-load.d` entry (the Go version had one).
2. `xtask dist` copied binaries from `<workspace>/target` and ignored `CARGO_TARGET_DIR`, so the image silently got stale binaries built on the host.
3. libfido2 CLI flags differ across versions (`-t uv=true` is 1.15+; `-v` prompts for a PIN on assertions).
**Solution:** Ship `/usr/lib/modules-load.d/passkey-tpm.conf`; `dist` resolves built artefacts through Cargo's target dir (unit-tested); the libfido2 checks rely on `-V -v` (UV bit in signed data) instead of version-specific request flags.
**Prevents:** Broken installs and false-positive tests.

### L-009: Shell-based multi-process test harnesses lie; use a real test framework

**Context:** The bash runner's two-user test killed a `runuser`/subshell wrapper instead of alice's agent, so bob was routed through alice's device and the test reported a cross-user leak that wasn't there.
**Solution:** pytest + pytest-testinfra (`tests/vm/e2e`, dependencies locked with uv): agents started with `subprocess.Popen(user=...)` (real PIDs), devices identified by diffing hidraw nodes, tests open a specific agent's device, and the broker's `request uid=` audit line proves which user each request ran as. JUnit + HTML reports come back over virtiofs.
**Prevents:** False security findings, and missed ones.

---

## Quick Tasks Completed

| # | Description | Date | Commit | Status |
| - | ----------- | ---- | ------ | ------ |

---

## Deferred Ideas

- [ ] TPM-less software fallback keystore — Captured during: init
- [ ] FreeBSD/NetBSD port: transport (CUSE-based hidraw? libfido2-level integration? xdg-desktop-portal), tpm2-abrmd on FreeBSD, NetBSD TPM 2.0 support, rc.d/devd/pkgsrc packaging; publish core/wire as standalone crates for other authenticators — Captured during: portability review (AD-015)
- [ ] Native PAM module with authd/SSSD broker re-validation — Captured during: init
- [ ] Face UV provider once a production-grade stack exists (Howdy 3 still beta) — Captured during: init
- [ ] Upstream the verified CTAPHID/CBOR crates to credentialsd/libwebauthn — Captured during: init

---

## Todos

- [ ] Pick a reverse-DNS prefix for D-Bus/polkit IDs (e.g. `io.github.<org>.PasskeyTpm`)
- [ ] Add a notice to the Go repo README: frozen, known security issues, link to the new repo
- [x] Approve ADR-003 and break it into tasks (2026-10-03)
- [x] Verify CTAP 2.1/2.2 text (T0, 2026-10-03)
- [ ] Decide: skip the CredRandomWithoutUV key for credProtect=3 (measured ID 736 B with both hmac keys; saves ~180 B)
- [x] Hardware bench on AMD fTPM (2026-10-03): 577 ms p50 / 599 ms p95 assertion, 221 ms makeCredential
- [ ] Overlap TPM preparation (session, PolicySecret, key Load) with the fingerprint wait to hide ~300 ms
- [ ] Benchmark an Intel PTT and a discrete TPM (Infineon/Nuvoton) with encrypted sessions
- [x] Local hardware E2E (2026-10-03): `scripts/e2e-local.sh` — libfido2 → kernel HID → agent → D-Bus → broker → AMD fTPM, registration + UV assertion verified (mock fprintd)
- [ ] Verify the NV allocation range 0x01500000–0x0150FFFF against the TCG "Registry of Reserved TPM 2.0 Handles and Localities"
- [x] credMgmt RP-bound tokens may delete/update that RP's credentials (2026-10-03)
- [x] Deleted discoverable credentials are revoked (revoked.v1 tag list, fail-closed) (2026-10-03)
- [ ] Build packages in clean chroots (makepkg, mock/COPR, sbuild/PPA)
- [ ] Hardware E2E with real fprintd: install packaging/udev rule (uaccess on /dev/uhid) + fprintd, run broker+agent, `scripts/e2e-fido2.sh`, then webauthn.io in Chromium and Firefox
- [ ] Kani: the CBOR `build` loop is not proven (CBMC blow-up on recursive drop); consider an iterative builder or a Verus proof
- [ ] CLI: `passkey-tpm tpm status` (DA warning, SRK state) using `health::da_status`
- [ ] Broker startup: re-define the PIN NV index from the persisted new auth if missing (crash during `pin_gate::rotate`)
- [ ] Trusted-prompt feasibility (broker-driven prompt vs credentialsd-ui)
- [ ] ADR-004: ctap-types vs passkey-types (check Debian packaging status and canonical CBOR handling)
- [ ] Contact linux-credentials maintainers
- [ ] Re-check UNVERIFIED items in the research docs before design

---

## Preferences

**Model Guidance Shown:** never
