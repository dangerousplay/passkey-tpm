Name:           passkey-tpm
Version:        0.1.0
Release:        1%{?dist}
Summary:        TPM-backed passkeys (FIDO2/WebAuthn) for Linux
License:        MIT OR Apache-2.0
URL:            https://github.com/dangerousplay/passkey-tpm
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz
# COPR builds vendor crates (rust2rpm -V); a Fedora review would use system crates instead.
Source1:        %{name}-%{version}-vendor.tar.xz
Source2:        passkey-tpm.sysusers

BuildRequires:  cargo-rpm-macros >= 24
BuildRequires:  pkgconfig(tss2-esys)
BuildRequires:  systemd-rpm-macros
Requires:       fprintd
Requires:       polkit
Requires:       dbus
%{?sysusers_requires_compat}

%description
passkey-tpm is a FIDO2/WebAuthn authenticator whose credentials are bound to the
machine's TPM 2.0 and unlocked with fingerprint or PIN. A privileged broker holds the
TPM policy secrets; a per-user agent exposes a virtual security key.

%prep
%autosetup -n %{name}-%{version} -a1
%cargo_prep -v vendor

%build
%cargo_build -- -p passkey-tpm-uvd -p passkey-tpm-agent -p passkey-tpm-cli

%install
cargo run --offline -q -p xtask -- dist --no-build --destdir %{buildroot} --prefix %{_prefix} --libexecdir %{_libexecdir}

%check
%cargo_test -- -p passkey-tpm-core -p passkey-tpm-wire -p passkey-tpm-agent

%pre
%sysusers_create_compat %{SOURCE2}

%post
%systemd_post passkey-tpm-uvd.service
%systemd_user_post passkey-tpm-agent.service
%udev_rules_update

%preun
%systemd_preun passkey-tpm-uvd.service
%systemd_user_preun passkey-tpm-agent.service

%postun
%systemd_postun_with_restart passkey-tpm-uvd.service
%udev_rules_update

%files
%license LICENSE-MIT LICENSE-APACHE
%doc README.md SECURITY.md docs/threat-model.md
%{_bindir}/passkey-tpm-cli
%{_libexecdir}/passkey-tpm/
%{_unitdir}/passkey-tpm-uvd.service
%{_userunitdir}/passkey-tpm-agent.service
%{_datadir}/dbus-1/system.d/io.github.dangerousplay.PasskeyTpm1.conf
%{_datadir}/dbus-1/system-services/io.github.dangerousplay.PasskeyTpm1.service
%{_datadir}/polkit-1/rules.d/50-passkey-tpm-fprintd.rules
%{_udevrulesdir}/70-passkey-tpm-uhid.rules
%{_sysusersdir}/passkey-tpm.conf

%changelog
* Sat Oct 03 2026 Davi Henrique <dangerousplay715@gmail.com> - 0.1.0-1
- Initial package
