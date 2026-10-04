# Changelog

All notable changes to passkey-tpm are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Features

- **wire:** panic-free wire formats for untrusted input ([9931967](https://github.com/dangerousplay/passkey-tpm/commit/99319675e74c9aba719ca3595f854987a7a15019))
- **core:** verified CTAP 2.1 authenticator core ([14e9b58](https://github.com/dangerousplay/passkey-tpm/commit/14e9b58963617c967fd9dc1e25bee58cedb20145))
- **tpm:** policy-bound credentials behind per-user TPM gates ([7185664](https://github.com/dangerousplay/passkey-tpm/commit/71856640bad77fd3eeb97d2f545b5483770fd3ff))
- **uv:** fprintd verification client and mock ([953b3d3](https://github.com/dangerousplay/passkey-tpm/commit/953b3d3a2d085c7d521ac2874f6c5df590e42a1c))
- **uhid:** virtual FIDO HID device without unsafe code ([dc824d8](https://github.com/dangerousplay/passkey-tpm/commit/dc824d8e09ea56a61c85d8c42b80bba290009c6d))
- broker, session agent and admin CLI ([beccadd](https://github.com/dangerousplay/passkey-tpm/commit/beccaddbd411d62cc1750a3515853a0d1741c269))
- **uvd:** log the calling uid and CTAP command of each request ([7cbdb4f](https://github.com/dangerousplay/passkey-tpm/commit/7cbdb4feac0aa09995fe7405b249b7de73eea3c8))

### Bug fixes

- **packaging:** load uhid at boot and install the binaries cargo built ([951cfd3](https://github.com/dangerousplay/passkey-tpm/commit/951cfd314b039543ae9d1b6aaf959ce2ffb73191))

### Documentation

- specs, threat model and ADRs 0001-0003 ([ac2508d](https://github.com/dangerousplay/passkey-tpm/commit/ac2508dd02de12875ad59848025ba7ff948416db))
- record the VM test bed, BSD portability policy and lessons ([818526a](https://github.com/dangerousplay/passkey-tpm/commit/818526a76a0703b65d4d92050ff10f20743cd23c))

### Testing

- **e2e:** make the libfido2 checks portable across versions ([f02f3bd](https://github.com/dangerousplay/passkey-tpm/commit/f02f3bd5c45cf9ecd3c21e00bf36f9532e276553))
- **vm:** mkosi VM test bed with swtpm and a virtual fingerprint sensor ([3e17d63](https://github.com/dangerousplay/passkey-tpm/commit/3e17d6378e7c2cdf0e3e3ad4a04be3019bb989f7))

### Build and CI

- distro packaging and end-to-end scripts ([152f6f0](https://github.com/dangerousplay/passkey-tpm/commit/152f6f00384467d1890831c633c7a0e591ec460c))

### Miscellaneous

- bootstrap passkey-tpm workspace, xtask and CI ([abe8f21](https://github.com/dangerousplay/passkey-tpm/commit/abe8f21f03efd8a55355f075f5b6b8c83932d108))

