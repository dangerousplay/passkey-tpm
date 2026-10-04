mod support;

use passkey_tpm_tpm::srk::BusProtection;
use passkey_tpm_tpm::{session, srk};
use support::swtpm::Swtpm;

#[test]
fn secret_responses_are_encrypted_on_a_discrete_bus_only() {
    let tpm = Swtpm::start();
    let mut ctx = tpm.context();
    let mut srk = srk::ensure(&mut ctx).expect("SRK");
    for (bus, secret, expect_encrypt) in [
        (BusProtection::Encrypted, true, true),
        (BusProtection::Encrypted, false, false),
        (BusProtection::Firmware, true, false),
    ] {
        srk.bus = bus;
        session::with_policy(&mut ctx, &srk, secret, |ctx, s, _| {
            let attrs = ctx.tr_sess_get_attributes(s).expect("attributes");
            assert_eq!(attrs.encrypt(), expect_encrypt, "{bus:?} secret={secret}");
            assert_eq!(attrs.decrypt(), expect_encrypt, "{bus:?} secret={secret}");
            Ok(())
        })
        .expect("session");
    }
}

#[test]
fn sessions_are_always_flushed() {
    let tpm = Swtpm::start();
    let mut ctx = tpm.context();
    let mut srk = srk::ensure(&mut ctx).expect("SRK");
    srk.bus = BusProtection::Encrypted;
    // The TPM allows only a few dozen active sessions; a leak would fail well before 200.
    for i in 0..200 {
        let r: passkey_tpm_tpm::Result<()> =
            session::with_policy(&mut ctx, &srk, i % 3 == 0, |_, _, _| {
                if i % 2 == 0 {
                    Ok(())
                } else {
                    Err(passkey_tpm_tpm::Error::Corrupt("simulated failure"))
                }
            });
        assert_eq!(r.is_ok(), i % 2 == 0);
        let a: passkey_tpm_tpm::Result<()> = session::with_auth(&mut ctx, &srk, |_| Ok(()));
        a.expect("auth session");
    }
}
