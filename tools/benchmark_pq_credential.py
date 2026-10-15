#!/usr/bin/env python3
"""Runs the post-quantum credential benchmarks for every scheme and profile.

For each of the six signatures (ML-DSA-65/87, SLH-DSA-SHAKE-192s/256s,
192f/256f), builds the standard image once with its Cargo features, then
runs standard_pq_prove_verify and standard_pq_prove_verify_no_cft through
tools/benchmark.py (10 repetitions plus one warm-up) under each profile:

  mobile  --cpus 2 --memory 4g   -> results/standard/local-2cpu-pq[-<scheme>]/
  server  --cpus 8 --memory 16g  -> results/standard/local-8cpu-pq[-<scheme>]/

Before each run it waits until the 1-minute load average is 10 or less
(at most 20 min, then it stops). A failed run (e.g. out of memory on
mobile) does not stop the others. At the end it prints the mean prove and
verify times of every summary and the failed runs.

  python3 tools/benchmark_pq_credential.py
  python3 tools/benchmark_pq_credential.py --profile server
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]  # the workspace root
RESULTS = ROOT / "results" / "standard"

# (--algorithm, --nist-level, name)
SCHEMES = (
    ("ml-dsa", "3", "ML-DSA-65"),
    ("slh-dsa-s", "3", "SLH-DSA-SHAKE-192s"),
    ("slh-dsa-f", "3", "SLH-DSA-SHAKE-192f"),
    ("ml-dsa", "5", "ML-DSA-87"),
    ("slh-dsa-s", "5", "SLH-DSA-SHAKE-256s"),
    ("slh-dsa-f", "5", "SLH-DSA-SHAKE-256f"),
)
PROFILES = {"mobile": ("2", "4g"), "server": ("8", "16g")}
BENCHES = ("pq_prove_verify", "pq_prove_verify_no_cft")
MAX_LOAD = 10.0
LOAD_WAIT_S = 20 * 60


def wait_for_load() -> None:
    deadline = time.monotonic() + LOAD_WAIT_S
    while os.getloadavg()[0] > MAX_LOAD:
        if time.monotonic() > deadline:
            sys.exit(f"Load average above {MAX_LOAD:g} for {LOAD_WAIT_S // 60} min; "
                     "stop the other programs and run again.")
        print(f"Load {os.getloadavg()[0]:.1f} > {MAX_LOAD:g}; waiting", flush=True)
        time.sleep(30)


def result_dir(algorithm: str, level: str, cpus: str) -> Path:
    """The folder tools/benchmark.py writes to (its suffix rule)."""
    suffix = "-pq" if (algorithm, level) == ("ml-dsa", "3") else f"-pq-{algorithm}-{level}"
    return RESULTS / f"local-{cpus}cpu{suffix}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("\n", 2)[2])
    parser.add_argument("--profile", action="append", choices=PROFILES,
                        help="run only this profile (repeatable; default both)")
    args = parser.parse_args()
    profiles = args.profile or list(PROFILES)

    failed = []
    for algorithm, level, name in SCHEMES:
        for i, profile in enumerate(profiles):
            cpus, memory = PROFILES[profile]
            wait_for_load()
            cmd = [sys.executable, str(ROOT / "tools" / "benchmark.py"), "--only", "standard",
                   *(arg for b in BENCHES for arg in ("--bench", b)),
                   "--algorithm", algorithm, "--nist-level", level,
                   "--cpus", cpus, "--memory", memory, "--no-plots"]
            if i > 0:
                cmd.append("--skip-build")  # the image of this scheme is built
            print(f"\n=== {name} {profile}\n$ " + " ".join(cmd), flush=True)
            if subprocess.run(cmd, cwd=ROOT, check=False).returncode != 0:
                failed.append(f"{name} {profile}")

    print(f"\n{'Scheme':<20} {'Profile':<8} {'Variant':<7} {'Prove s':>8} {'Verify s':>9}")
    for algorithm, level, name in SCHEMES:
        for profile in profiles:
            dest = result_dir(algorithm, level, PROFILES[profile][0])
            for bench, variant in zip(BENCHES, ("CFT", "No CFT")):
                path = dest / f"{bench}.json"
                if not path.is_file():
                    print(f"{name:<20} {profile:<8} {variant:<7} {'missing':>8}")
                    continue
                avg = json.loads(path.read_text())["avgMs"]
                print(f"{name:<20} {profile:<8} {variant:<7} "
                      f"{avg['proverTotal'] / 1e3:>8.2f} {avg['verify'] / 1e3:>9.2f}")
    if failed:
        sys.exit(f"Failed: {', '.join(failed)} (logs in .work/logs/)")
    print("All runs succeeded.")


if __name__ == "__main__":
    main()
