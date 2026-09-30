#!/usr/bin/env python3
"""Runs every benchmark, collects the results and draws the plots.

  1. Fetches the pinned downloads (tools/fetch.py) and builds the Docker images.
  2. Runs the five standard (Longfellow) and five zk-friendly benchmarks in
     Docker with --cpus/--memory; results go to results/<stack>/local-<N>cpu/.
  3. Reruns the three zk-friendly prove benchmarks with --cpus-full, to show
     how rapidsnark scales with cores (results/zk-friendly/local-<M>cpu/).
  4. Runs the revocation CFT experiments natively (results/revocation/local/),
     plus the MPC sweep when MP_SPDZ_PATH is set.
  5. Writes environment.json next to each result set, then runs tools/plot.py.

  python3 rust/tools/benchmark.py                      # everything, ~3.5 h on 2 CPUs
  python3 rust/tools/benchmark.py --only zk-friendly --skip-build
  BENCH_N=3 python3 rust/tools/benchmark.py            # BENCH_* and friends pass through

Every binary writes <out>/summary.json (its --out contract); this script copies
it to results/<stack>/<env>/<benchmark>.json. Logs go to .work/logs/. Needs
Docker (VM memory >= --memory), cargo, and matplotlib + numpy for the plots.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]  # rust/, the workspace root
TOOLS = ROOT / "tools"
DEFAULT_RESULTS = ROOT / "results"
WORK = Path(os.environ.get("BENCH_WORK_DIR") or ROOT / ".work")

STACKS = ("standard", "zk-friendly", "revocation")
IMAGES = {"standard": "standard-bench-rs", "zk-friendly": "zk-friendly-bench-rs"}
# Binary name prefix per stack.
PREFIX = {"standard": "standard", "zk-friendly": "zkfriendly", "revocation": "revocation"}

# Benchmark options forwarded into the containers when set on the host.
PASS_ENV = (
    "BENCH_N", "BENCH_REPETITIONS", "BENCH_WARMUP", "BENCH_VERIFY_WARMUP",
    "BENCH_ITERATIONS", "BENCH_MIN_TIME", "BENCH_FILTER", "REVOC_LOG2_LIST",
    "REVOC_LOG2", "REVOC_BITS_PER_LEAF", "REVOC_SLOT", "TOTAL_ATTRS", "USED_ATTRS",
)

BENCHES = ("prove_verify", "prove_verify_no_cft", "prove_verify_revocation",
           "merkle_vs_flat", "communication_size")
PROVE_BENCHES = BENCHES[:3]


def run(cmd: list[str], **kwargs) -> int:
    print("$ " + " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=False, **kwargs).returncode


def docker_memory_bytes() -> int:
    out = subprocess.run(["docker", "info", "--format", "{{.MemTotal}}"],
                         capture_output=True, text=True, check=False)
    if out.returncode != 0:
        sys.exit("Docker is not reachable; start Docker Desktop (or the daemon) first.")
    return int(out.stdout.strip())


def parse_memory(text: str) -> int:
    units = {"k": 2**10, "m": 2**20, "g": 2**30}
    return int(float(text[:-1]) * units[text[-1].lower()]) if text[-1].isalpha() else int(text)


def build_images(stacks: list[str]) -> None:
    if "zk-friendly" in stacks and run([sys.executable, str(TOOLS / "fetch.py")]) != 0:
        sys.exit("fetch failed")
    for stack in stacks:
        dockerfile = ROOT / "crates" / stack / "Dockerfile"
        if run(["docker", "build", "-t", IMAGES[stack], "-f", str(dockerfile), str(ROOT)]) != 0:
            sys.exit(f"{stack} image build failed")


def docker_suite(stack: str, benches: tuple[str, ...], limits: list[str], dest: Path,
                 ) -> dict[str, bool]:
    """Runs `benches` in one container; each summary lands in `dest`.

    One container per suite keeps the circuit setup cache between benchmarks.
    Returns, per benchmark, whether it exited 0 and wrote its summary.
    """
    dest.mkdir(parents=True, exist_ok=True)
    logs = WORK / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    tag = f"{stack}/{dest.name}"
    lines = ["cd /bench"]
    for bench in benches:
        (dest / f"{bench}.json").unlink(missing_ok=True)  # never leave a stale result
        log = f"/logs/{stack}_{dest.name}_{bench}.log"
        lines += [
            f"echo '=== {tag} {bench}' $(date -u +%T)",
            f"./target/release/{PREFIX[stack]}_{bench} --out /tmp/out/{bench} > {log} 2>&1",
            f"echo {bench} $? >> /out/.status",
            f"cp /tmp/out/{bench}/summary.json /out/{bench}.json 2>/dev/null || true",
        ]
    status = dest / ".status"
    status.unlink(missing_ok=True)

    env = [arg for name in PASS_ENV if name in os.environ for arg in ("-e", name)]
    run(["docker", "run", "--rm", *limits, *env,
         "-v", f"{dest}:/out", "-v", f"{logs}:/logs", IMAGES[stack],
         "bash", "-c", "\n".join(lines)])

    codes = dict.fromkeys(benches, -1)  # -1: never reached (container died)
    if status.is_file():
        for line in status.read_text().split("\n"):
            if line:
                bench, code = line.split()
                codes[bench] = int(code)
        status.unlink()
    return {f"{tag}:{b}": codes[b] == 0 and (dest / f"{b}.json").is_file() for b in benches}


def revocation_native(dest: Path) -> dict[str, bool]:
    """CFT experiments on the host; the CSVs go straight to `dest`."""
    if run(["cargo", "build", "--release", "-p", "revocation"], cwd=ROOT) != 0:
        return {"revocation/local:build": False}
    dest.mkdir(parents=True, exist_ok=True)
    for stale in dest.glob("*.csv"):
        stale.unlink()
    logs = WORK / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    codes = {}
    with open(logs / "revocation_local_run_experiments.log", "w") as log:
        codes["revocation/local:run_experiments"] = run(
            [str(ROOT / "target/release/revocation_run_experiments"), "--out", str(dest)],
            stdout=log, stderr=subprocess.STDOUT) == 0

    if os.environ.get("MP_SPDZ_PATH"):
        with tempfile.TemporaryDirectory(dir=WORK) as sweep:
            codes["revocation/local:mpc"] = run(
                ["bash", str(ROOT / "crates/revocation/mpc/run_sweep.sh")],
                env={**os.environ, "OUTDIR": sweep}) == 0
            if Path(sweep, "results.csv").is_file():
                shutil.copy(Path(sweep, "results.csv"), dest / "mpc_results.csv")
    else:
        print("Skip revocation MPC (MP_SPDZ_PATH not set)")
    return codes


def host_description() -> dict:
    cpu = platform.processor()
    if sys.platform == "darwin":
        cpu = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                             capture_output=True, text=True).stdout.strip() or cpu
    info = subprocess.run(["docker", "info", "--format", "{{.NCPU}} {{.MemTotal}}"],
                          capture_output=True, text=True).stdout.split()
    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
    return {
        "host": {"platform": platform.platform(), "cpu": cpu,
                 "logicalCpus": os.cpu_count()},
        "docker": {"cpus": int(info[0]), "memBytes": int(info[1])} if len(info) == 2 else None,
        "gitCommit": commit,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("\n", 2)[2])
    parser.add_argument("--only", action="append", choices=STACKS,
                        help="run only this stack (repeatable)")
    parser.add_argument("--skip-build", action="store_true", help="reuse the Docker images")
    parser.add_argument("--cpus", default="2", help="Docker CPU limit (default 2)")
    parser.add_argument("--cpus-full", default="12",
                        help="CPU limit of the zk-friendly prove rerun; 0 skips it")
    parser.add_argument("--memory", default="16g",
                        help="Docker memory limit (default 16g; merkle-vs-flat needs > 7g)")
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS,
                        help="results root (default rust/results)")
    parser.add_argument("--no-plots", action="store_true")
    args = parser.parse_args()

    stacks = args.only or list(STACKS)
    results = args.results.resolve()
    docker_stacks = [s for s in stacks if s != "revocation"]

    if docker_stacks:
        if docker_memory_bytes() < parse_memory(args.memory):
            sys.exit(f"Docker VM has less memory than --memory {args.memory}; "
                     f"raise it in Docker Desktop (Settings -> Resources).")
        if not args.skip_build:
            build_images(docker_stacks)

    started = datetime.now(timezone.utc)
    limits = ["--cpus", args.cpus, "--memory", args.memory, "--memory-swap", args.memory]
    # Each result set: its folder and the codes of the benchmarks written there.
    runs: list[tuple[Path, dict[str, bool]]] = []
    for stack in docker_stacks:
        dest = results / stack / f"local-{args.cpus}cpu"
        runs.append((dest, docker_suite(stack, BENCHES, limits, dest)))
    if "zk-friendly" in stacks and args.cpus_full != "0":
        dest = results / "zk-friendly" / f"local-{args.cpus_full}cpu"
        full = ["--cpus", args.cpus_full, *limits[2:]]
        runs.append((dest, docker_suite("zk-friendly", PROVE_BENCHES, full, dest)))
    if "revocation" in stacks:
        dest = results / "revocation" / "local"
        runs.append((dest, revocation_native(dest)))

    finished = datetime.now(timezone.utc)
    host = host_description()
    for dest, codes in runs:
        environment = {
            **host,
            "started": started.isoformat(timespec="seconds"),
            "finished": finished.isoformat(timespec="seconds"),
            "limits": {"cpus": args.cpus, "cpusFull": args.cpus_full, "memory": args.memory},
            "succeeded": codes,
        }
        (dest / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")

    codes = {k: ok for _, c in runs for k, ok in c.items()}
    if not args.no_plots:
        codes["plots"] = run([sys.executable, str(TOOLS / "plot.py"),
                              "--results", str(results)]) == 0

    failed = [name for name, ok in codes.items() if not ok]
    print(f"\nResults: {results}  (logs in {WORK / 'logs'})")
    if failed:
        sys.exit(f"Failed: {', '.join(failed)}")
    print("All benchmarks succeeded.")


if __name__ == "__main__":
    main()
