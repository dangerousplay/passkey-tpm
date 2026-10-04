//! Task registry. Each task lives in its own module and registers one entry in `TASKS`.

mod bench_tpm;
mod build;
mod ci;
mod clippy;
mod deny;
mod dist;
mod fmt;
mod fuzz;
mod kani;
mod portability;
mod test;
mod verus;
mod vm;

use crate::runner::Result;

pub struct Task {
    pub name: &'static str,
    pub about: &'static str,
    pub run: fn(&[String]) -> Result,
}

pub const TASKS: &[Task] = &[
    Task {
        name: "fmt",
        about: "rustfmt the workspace (--check to only verify)",
        run: fmt::run,
    },
    Task {
        name: "clippy",
        about: "clippy on all targets with -D warnings",
        run: clippy::run,
    },
    Task {
        name: "test",
        about: "run the test suite and report the pass count",
        run: test::run,
    },
    Task {
        name: "deny",
        about: "cargo-deny: licenses, advisories, bans, sources",
        run: deny::run,
    },
    Task {
        name: "verus",
        about: "verify passkey-tpm-core with the pinned Verus release",
        run: verus::run,
    },
    Task {
        name: "kani",
        about: "prove panic-freedom of passkey-tpm-wire with the pinned Kani",
        run: kani::run,
    },
    Task {
        name: "fuzz",
        about: "run cargo-fuzz targets: [--time SECONDS] [TARGET]",
        run: fuzz::run,
    },
    Task {
        name: "ci",
        about: "fast gates (fmt, clippy, deny, test, verus); --full adds kani + fuzz",
        run: ci::run,
    },
    Task {
        name: "bench-tpm",
        about: "TPM assertion latency: [--device /dev/tpmrm0] (default: swtpm)",
        run: bench_tpm::run,
    },
    Task {
        name: "dist",
        about: "release build + FHS tree: [--destdir DIR] [--prefix /usr] [--libexecdir DIR] [--no-build]",
        run: dist::run,
    },
    Task {
        name: "portability",
        about: "check the portable crates (core, wire) build for FreeBSD",
        run: portability::run,
    },
    Task {
        name: "vm",
        about: "E2E scenarios in an mkosi VM (swtpm + virtual fingerprint): [--no-build] [--timeout S]",
        run: vm::run,
    },
    Task {
        name: "build",
        about: "build the workspace",
        run: build::run,
    },
];

pub fn find(name: &str) -> Option<&'static Task> {
    TASKS.iter().find(|t| t.name == name)
}

pub fn print_help() {
    println!("usage: cargo xtask <task> [args]\n\ntasks:");
    for task in TASKS {
        println!("  {:<10} {}", task.name, task.about);
    }
}
