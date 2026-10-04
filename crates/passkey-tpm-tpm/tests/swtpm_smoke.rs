mod support;

use support::swtpm::Swtpm;

#[test]
fn swtpm_returns_random_bytes() {
    let tpm = Swtpm::start();
    let mut ctx = tpm.context();
    let random = ctx.get_random(32).expect("TPM2_GetRandom");
    assert_eq!(random.value().len(), 32);
}

#[test]
fn parallel_instances_are_isolated() {
    let handles: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(|| {
                let tpm = Swtpm::start();
                let mut ctx = tpm.context();
                ctx.get_random(8).expect("TPM2_GetRandom").value().to_vec()
            })
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().expect("thread").len(), 8);
    }
}
