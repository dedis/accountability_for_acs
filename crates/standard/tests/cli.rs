#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

// Exercise the real drivers with a deterministic Google Benchmark report.
// Each child gets its own environment, working directory and work root.
#[test]
fn environment_options_and_output_paths() -> anyhow::Result<()> {
    let root = std::env::temp_dir().join(format!("standard-cli-{}", std::process::id()));
    fs::create_dir(&root)?;
    let cwd = root.join("cwd");
    let work = root.join("work");
    fs::create_dir(&cwd)?;
    let fixture = root.join("gbench");
    let log = root.join("args");
    fs::write(
        &fixture,
        r#"#!/bin/sh
set -eu
out=''
for arg do
    case "$arg" in --benchmark_out=*) out=${arg#*=} ;; esac
done
[ -n "$out" ] || exit 0
printf '%s\n' "$@" > "$ARGS_LOG"
cat > "$out" <<'JSON'
{"benchmarks":[
{"name":"BM_AttrSigCombined_Flat/8/1","prove_ns":1000000,"verify_ns":100000},
{"name":"BM_ProveVerifyRevocationCombined_Packed_P256/12","prove_ns":1000000,"verify_ns":100000}
]}
JSON
"#,
    )?;
    fs::set_permissions(&fixture, fs::Permissions::from_mode(0o755))?;

    for (index, (binary, bench)) in [
        (env!("CARGO_BIN_EXE_standard_prove_verify"), "prove_verify"),
        (
            env!("CARGO_BIN_EXE_standard_prove_verify_no_cft"),
            "prove_verify_no_cft",
        ),
        (
            env!("CARGO_BIN_EXE_standard_merkle_vs_flat"),
            "merkle_vs_flat",
        ),
        (
            env!("CARGO_BIN_EXE_standard_prove_verify_revocation"),
            "prove_verify_revocation",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        // 0: default under the work root, 1: BENCH_OUT, 2: --out relative to cwd.
        for mode in 0..3 {
            let relative = format!("out-{index}-{mode}");
            let expected = match mode {
                0 => work.join("standard/out").join(bench),
                1 => root.join(&relative),
                _ => cwd.join(&relative),
            };
            fs::create_dir_all(&expected)?;
            let marker = expected.join("old-artifact");
            fs::write(&marker, "old")?;
            let mut command = Command::new(binary);
            command
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .current_dir(&cwd)
                .env("BENCH_WORK_DIR", &work)
                .env("BENCH_WARMUP", "0")
                .env("BENCH_REPETITIONS", "3")
                .env("REVOC_LOG2", "12")
                .env("ARGS_LOG", &log)
                .args(["--bin"])
                .arg(&fixture);
            if index != 3 {
                command
                    .arg("--quiet")
                    .env("CLEAN", if mode == 0 { "1" } else { "0" });
            }
            if mode == 1 {
                command.env("BENCH_OUT", &expected);
            }
            if mode > 0 {
                command.env("BENCH_N", "5").env("REVOC_LOG2_LIST", "16,20");
            }
            if mode == 2 {
                command.args(["--out", &relative, "--n", "7"]);
                if index == 3 {
                    command.args(["--revoc-log2", "24"]);
                }
            }
            let output = command.output()?;
            assert!(
                output.status.success(),
                "{binary}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                expected.join("summary.json").is_file(),
                "{binary} mode {mode}"
            );
            let args = fs::read_to_string(&log)?;
            let repetitions = [3, 5, 7][mode];
            assert!(args
                .lines()
                .any(|arg| arg == format!("--benchmark_repetitions={repetitions}")));
            if index == 3 {
                let scales = ["12", "16|20", "24"][mode];
                assert!(args.contains(&format!(
                    "--benchmark_filter=BM_ProveVerifyRevocationCombined_Packed_P256/({scales})"
                )));
            } else {
                // --clean empties the output folder before the run.
                assert_eq!(marker.exists(), mode != 0);
            }
        }
    }
    fs::remove_dir_all(root)?;
    Ok(())
}
