#!/usr/bin/env python3
"""Measures the post-quantum signature and credential proofs and prints one table.

For each signature (ML-DSA-65/87, SLH-DSA-SHAKE-192s/192f/256s/256f) it runs
three Longfellow proofs: the signature proof alone (ml_dsa_{65,87}_zk_test,
slh_dsa_zk[_5]_test) and the credential proof without and with CFT
(pq_credential[_5]_test). Each proof gets a new, empty PQ_CIRCUIT_CACHE: one
warm-up repetition compiles its circuits into it, then the measured
repetitions run in a new process that loads them, as with circuits compiled
in advance and distributed. standard_sign times native signing (pqc::sig) of
a C4-size message.

Columns:
  Proof (MB)          mean serialized proof size, 10^6 bytes, over all runs
  Sign (ms)           median native signing time (signature rows only)
  Prove, Verify       mean over the measured repetitions (s)
  Peak (MiB)          peak memory of the measured process (circuits loaded)
  Compile peak (MiB)  peak memory of the warm-up process: it compiles and
                      stores the circuits, then proves and verifies once

Peak memory is the peak memory footprint on macOS (/usr/bin/time -l) and the
maximum resident set size on Linux and in Docker (ru_maxrss). The resident
set also counts the mapped circuit files; the footprint does not.

--where local builds (CMake, Cargo) and runs natively. --where docker builds
the standard-bench-rs image (crates/standard/Dockerfile) and runs every proof
in its own container under each profile:

  mobile  --cpus 2 --memory 4g
  server  --cpus 8 --memory 16g

Before each run it waits until the 1-minute load average is 10 or less (at
most 20 min, then it stops).

  python3 tools/benchmark_pq_table.py
  python3 tools/benchmark_pq_table.py --where docker --profile mobile
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

import benchmark  # tools/benchmark.py: the Docker image
from benchmark_pq_credential import PROFILES, wait_for_load

ROOT = Path(__file__).resolve().parents[1]  # the workspace root
BUILD_DIR = Path(os.environ.get("LONGFELLOW_BUILD_DIR")
                 or ROOT / ".work" / "standard" / "longfellow-build")
FOOTPRINT = "peak memory footprint"  # the /usr/bin/time -l line on macOS
SIGN_BIN = ROOT / "target" / "release" / "standard_sign"
IMAGE = benchmark.IMAGES["standard"]
IMAGE_FEATURES = ["--features", "pq"]  # tools/benchmark.py's default pq build

# (name, category, signature proof program, its filter, credential tag)
SCHEMES = (
    ("ML-DSA-65", 3, "ml_dsa/ml_dsa_65_zk_test", "^BM_MLDSA65ZK_Combined$", "MLDSA"),
    ("SLH-DSA-SHAKE-192s", 3, "slh_dsa/slh_dsa_zk_test", "/SLHDSA_SHAKE_192s$", "SLHs"),
    ("SLH-DSA-SHAKE-192f", 3, "slh_dsa/slh_dsa_zk_test", "/SLHDSA_SHAKE_192f$", "SLHf"),
    ("ML-DSA-87", 5, "ml_dsa/ml_dsa_87_zk_test", "^BM_MLDSA87ZK_Combined$", "MLDSA"),
    ("SLH-DSA-SHAKE-256s", 5, "slh_dsa/slh_dsa_zk_5_test", "/SLHDSA_SHAKE_256s$", "SLHs"),
    ("SLH-DSA-SHAKE-256f", 5, "slh_dsa/slh_dsa_zk_5_test", "/SLHDSA_SHAKE_256f$", "SLHf"),
)
VARIANTS = ("signature", "no CFT", "CFT")
TARGETS = ("ml_dsa_65_zk_test", "ml_dsa_87_zk_test", "slh_dsa_zk_test", "slh_dsa_zk_5_test",
           "pq_credential_test", "pq_credential_5_test")


def proofs(name: str, category: int, sig_program: str, sig_filter: str, tag: str,
           ) -> dict[str, tuple[str, str]]:
    """Program and benchmark filter of each variant of one scheme."""
    credential = "credential/pq_credential" + ("_5" if category == 5 else "") + "_test"
    return {
        "signature": (sig_program, sig_filter),
        "no CFT": (credential, f"^BM_Combined_PQCred_{tag}_NoCft$"),
        "CFT": (credential, f"^BM_Combined_PQCred_{tag}_Cft$"),
    }


def check(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    print("$ " + " ".join(cmd), file=sys.stderr, flush=True)
    done = subprocess.run(cmd, check=False, **kwargs)
    if done.returncode != 0:
        sys.exit(f"Failed ({done.returncode}): {' '.join(cmd)}")
    return done


def peak_measure() -> str:
    return FOOTPRINT if sys.platform == "darwin" else "maximum resident set size"


def gbench(args: list[str], env: dict[str, str]) -> tuple[list[dict], int]:
    """Runs one Google Benchmark process; its rows and peak memory (bytes)."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.json"
        timing = Path(tmp) / "time.txt"
        argv = [*args, f"--benchmark_out={out}", "--benchmark_out_format=json"]
        if sys.platform == "darwin":
            argv = ["/usr/bin/time", "-l", "-o", str(timing), *argv]
        print("$ " + " ".join(argv), file=sys.stderr, flush=True)
        # Console output to stderr: stdout carries the result in a container.
        pid = os.posix_spawn(argv[0], argv, env,
                             file_actions=[(os.POSIX_SPAWN_DUP2, 2, 1)])
        _, status, usage = os.wait4(pid, 0)
        code = os.waitstatus_to_exitcode(status)
        if code != 0:
            sys.exit(f"Failed ({code}): {' '.join(argv)}")
        rows = json.loads(out.read_text())["benchmarks"]
        if sys.platform == "darwin":
            peaks = [line.split()[0] for line in timing.read_text().splitlines()
                     if line.strip().endswith(FOOTPRINT)]
            if len(peaks) != 1:
                sys.exit(f"No {FOOTPRINT} in the /usr/bin/time report of {argv[4]}")
            peak = int(peaks[0])
        else:
            peak = usage.ru_maxrss * 1024  # KiB on Linux
    return [r for r in rows if "aggregate_name" not in r], peak


def measure(program: str, filter_: str, reps: int) -> dict:
    """Warm-up, then `reps` measured repetitions of one proof, in this process's host."""
    base = [str(BUILD_DIR / "circuits" / "tests" / "pq" / program),
            f"--benchmark_filter={filter_}", "--benchmark_iterations=1"]
    # An empty cache (mode 0700, as circuit_cache.h requires): the warm-up compiles.
    with tempfile.TemporaryDirectory() as cache:
        env = {**os.environ, "PQ_CIRCUIT_CACHE": cache}
        _, compile_peak = gbench([*base, "--benchmark_repetitions=1"], env)
        rows, peak = gbench([*base, f"--benchmark_repetitions={reps}"], env)
    if len(rows) != reps:
        sys.exit(f"{program} {filter_}: {len(rows)} rows, expected {reps}")
    return {
        "prove_s": [r["prove_ns"] / 1e9 for r in rows],
        "verify_s": [r["verify_ns"] / 1e9 for r in rows],
        "proof_bytes": [r["proof_bytes"] for r in rows],
        "peak_bytes": peak,
        "compile_peak_bytes": compile_peak,
        "peak_measure": peak_measure(),
    }


def build_local() -> None:
    check(["cmake", "-S", str(ROOT / "third_party/longfellow-zk/lib"), "-B", str(BUILD_DIR),
           "-DCMAKE_BUILD_TYPE=Release"])
    check(["cmake", "--build", str(BUILD_DIR), "-j", str(os.cpu_count()),
           "--target", *TARGETS])
    check(["cargo", "build", "--release", "--locked", "-p", "standard", "--bin",
           "standard_sign"], cwd=ROOT)


def run_local(reps: int) -> dict:
    """{scheme: {variant: measurement}} plus the signing times, natively."""
    results = {}
    for scheme in SCHEMES:
        results[scheme[0]] = {}
        for variant, (program, filter_) in proofs(*scheme).items():
            wait_for_load()
            results[scheme[0]][variant] = measure(program, filter_, reps)
    wait_for_load()
    sign = check([str(SIGN_BIN), "--repetitions", str(reps)], stdout=subprocess.PIPE, text=True)
    return {"proofs": results, "sign_ms": json.loads(sign.stdout)}


def run_docker(reps: int, profile: str) -> dict:
    """As run_local, each proof in its own container with the profile's limits."""
    cpus, memory = PROFILES[profile]
    docker = ["docker", "run", "--rm", "--cpus", cpus, "--memory", memory,
              "--memory-swap", memory, "-v", f"{ROOT / 'tools'}:/bench/tools:ro", IMAGE]
    results = {}
    for scheme in SCHEMES:
        results[scheme[0]] = {}
        for variant, (program, filter_) in proofs(*scheme).items():
            wait_for_load()
            done = check([*docker, "python3", "tools/benchmark_pq_table.py", "--repetitions",
                          str(reps), "--inner", program, filter_],
                         stdout=subprocess.PIPE, text=True)
            results[scheme[0]][variant] = json.loads(done.stdout)
    wait_for_load()
    sign = check([*docker, "./target/release/standard_sign", "--repetitions", str(reps)],
                 stdout=subprocess.PIPE, text=True)
    return {"proofs": results, "sign_ms": json.loads(sign.stdout)}


def table(runs: dict[str, dict]) -> str:
    """The Markdown table, one column group per environment, and the memory measures."""
    prefix = (lambda env: f"{env} ") if len(runs) > 1 else (lambda env: "")
    head = ["Scheme", "Category", "Variant", "Proof (MB)"]
    for env in runs:
        head += [f"{prefix(env)}{col}" for col in ("Sign (ms)", "Prove (s)", "Verify (s)",
                                                   "Peak (MiB)", "Compile peak (MiB)")]
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for name, category, *_ in SCHEMES:
        for variant in VARIANTS:
            sizes = [b for run in runs.values()
                     for b in run["proofs"][name][variant]["proof_bytes"]]
            row = [name, str(category), variant, f"{statistics.mean(sizes) / 1e6:.2f}"]
            for run in runs.values():
                m = run["proofs"][name][variant]
                sign = (f"{statistics.median(run['sign_ms'][name]):.2f}"
                        if variant == "signature" else "")
                row += [sign, f"{statistics.mean(m['prove_s']):.2f}",
                        f"{statistics.mean(m['verify_s']):.2f}",
                        f"{m['peak_bytes'] / 2**20:.0f}",
                        f"{m['compile_peak_bytes'] / 2**20:.0f}"]
            lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    for env, run in runs.items():
        measures = {m["peak_measure"] for v in run["proofs"].values() for m in v.values()}
        lines.append(f"{env}: peak memory is the {', '.join(sorted(measures))}.")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("\n", 2)[2])
    parser.add_argument("--where", choices=("local", "docker"), default="local",
                        help="run natively (default) or in Docker on this machine")
    parser.add_argument("--profile", action="append", choices=PROFILES,
                        help="Docker profile (repeatable; default both)")
    parser.add_argument("--repetitions", type=int, default=10,
                        help="measured repetitions per proof and timed signatures (default 10)")
    parser.add_argument("--skip-build", action="store_true",
                        help="reuse the existing build or Docker image")
    # Inside a container: measure one proof and print it as JSON.
    parser.add_argument("--inner", nargs=2, metavar=("PROGRAM", "FILTER"),
                        help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.repetitions < 1:
        sys.exit("--repetitions must be at least 1")
    if args.inner:
        print(json.dumps(measure(*args.inner, args.repetitions)))
        return
    if args.profile and args.where != "docker":
        sys.exit("--profile applies to --where docker only")
    # stdout carries only the table: all other output, also of child processes, goes to stderr.
    table_out = os.fdopen(os.dup(1), "w")
    os.dup2(2, 1)

    if args.where == "local":
        if not args.skip_build:
            build_local()
        runs = {"local": run_local(args.repetitions)}
    else:
        profiles = args.profile or list(PROFILES)
        need = max(benchmark.parse_memory(PROFILES[p][1]) for p in profiles)
        if benchmark.docker_memory_bytes() < need:
            sys.exit("Docker VM has less memory than the largest profile; raise it in "
                     "Docker Desktop (Settings -> Resources).")
        if args.skip_build:
            benchmark.check_images(["standard"], IMAGE_FEATURES)
        else:
            benchmark.build_images(["standard"], IMAGE_FEATURES)
        runs = {p: run_docker(args.repetitions, p) for p in profiles}
    print(table(runs), file=table_out, flush=True)


if __name__ == "__main__":
    main()
