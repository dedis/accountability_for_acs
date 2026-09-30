#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn legacy_environment_options() -> anyhow::Result<()> {
    let root = std::env::temp_dir().join(format!("zk-friendly-cli-{}", std::process::id()));
    fs::create_dir(&root)?;
    let compiler = root.join("circom");
    // Stop at the external compiler. This checks argument handling without
    // compiling circuits or requiring a trusted setup.
    fs::write(
        &compiler,
        "#!/bin/sh\necho 'fixture compiler reached' >&2\nexit 1\n",
    )?;
    fs::set_permissions(&compiler, fs::Permissions::from_mode(0o755))?;
    let command = |binary| {
        let mut cmd = Command::new(binary);
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&root)
            .env("BENCH_WORK_DIR", &root)
            .env("CIRCOM_BIN", &compiler)
            .env("RAPIDSNARK_BIN", &compiler);
        cmd
    };
    for binary in [
        env!("CARGO_BIN_EXE_zkfriendly_prove_verify"),
        env!("CARGO_BIN_EXE_zkfriendly_prove_verify_no_cft"),
    ] {
        for keep in ["0", "1"] {
            let output = command(binary).env("KEEP_ARTIFACTS", keep).output()?;
            assert!(!output.status.success());
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("fixture compiler reached"),
                "{binary}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    // A sweep with k > n has no points. It still applies cleanup and writes
    // its summary, so both true and false flag values have observable effects.
    let artifacts = root.join("zk-friendly/artifacts/merkle_vs_flat");
    let summary = root.join("zk-friendly/out/merkle_vs_flat/summary.json");
    for (clean, keep, remains) in [("1", "1", false), ("0", "1", true), ("0", "0", false)] {
        fs::create_dir_all(&artifacts)?;
        let marker = artifacts.join("old-artifact");
        fs::write(&marker, "old")?;
        let output = command(env!("CARGO_BIN_EXE_zkfriendly_merkle_vs_flat"))
            .env("TOTAL_ATTRS", "2")
            .env("USED_ATTRS", "4")
            .env("CLEAN", clean)
            .env("KEEP_ARTIFACTS", keep)
            .args(["--quiet", "--compact"])
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(marker.exists(), remains);
        assert!(summary.is_file());
    }

    for mode in 0..3 {
        let mut cmd = command(env!("CARGO_BIN_EXE_zkfriendly_prove_verify_revocation"));
        cmd.env("REVOC_LOG2", "12");
        if mode > 0 {
            cmd.env("REVOC_LOG2_LIST", "16,20");
        }
        if mode == 2 {
            cmd.args(["--revoc-log2", "24"]);
        }
        let output = cmd.output()?;
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("fixture compiler reached"));
        let scales = ["2^12", "2^16, 2^20", "2^24"][mode];
        assert!(String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line == format!("  scales: {scales}")));
    }

    let communication = env!("CARGO_BIN_EXE_zkfriendly_communication_size");
    let output = command(communication)
        .env("REVOC_LOG2", "invalid")
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--revoc-log2"));
    for override_with_cli in [false, true] {
        let mut cmd = command(communication);
        cmd.env("REVOC_LOG2", "invalid").env(
            "REVOC_LOG2_LIST",
            if override_with_cli { "invalid" } else { "12" },
        );
        if override_with_cli {
            cmd.args(["--revoc-log2", "12"]);
        }
        let output = cmd.output()?;
        assert!(!output.status.success());
        // The communication driver sets KEEP_ARTIFACTS=1 for its child.
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("fixture compiler reached"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fs::remove_dir_all(root)?;
    Ok(())
}
