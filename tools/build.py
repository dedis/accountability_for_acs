#!/usr/bin/env python3
"""Builds the workspace with the post-quantum signature chosen at compile time.

  python3 tools/build.py                                  # ML-DSA, NIST level 3
  python3 tools/build.py --nist-level=5 --algorithm=slh-dsa-f
  python3 tools/build.py --algorithm=slh-dsa-s -- --bin standard_signature

The signature is C4 in revocation, the issuer and C4 signatures of the
post-quantum credential model of zk-friendly, and the proof of
standard_signature:

  --algorithm  ml-dsa (default) | slh-dsa-s (small signatures) | slh-dsa-f (fast signing)
  --nist-level 3 (default) | 5

| Algorithm | Level 3            | Level 5            |
|-----------|--------------------|--------------------|
| ml-dsa    | ML-DSA-65          | ML-DSA-87          |
| slh-dsa-s | SLH-DSA-SHAKE-192s | SLH-DSA-SHAKE-256s |
| slh-dsa-f | SLH-DSA-SHAKE-192f | SLH-DSA-SHAKE-256f |

The choice maps to the Cargo features pq, slh-dsa, slh-dsa-f and level-5 of
revocation, standard and zk-friendly. Arguments after -- go to
`cargo build --release`.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]  # the workspace root
# Every choice enables pq itself, so --no-default-features after -- cannot
# turn the build classical.
ALGORITHMS = {"ml-dsa": ["pq"], "slh-dsa-s": ["slh-dsa"], "slh-dsa-f": ["slh-dsa-f"]}
LEVELS = {"3": [], "5": ["level-5"]}
# The crates whose signature the features choose.
CRATES = ("revocation", "standard", "zk-friendly")


def features(algorithm: str, level: str) -> list[str]:
    """Cargo features of one crate for ALGORITHM at NIST LEVEL."""
    return ALGORITHMS[algorithm] + LEVELS[level]


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--algorithm", choices=ALGORITHMS, default="ml-dsa",
                        help="post-quantum signature (default ml-dsa)")
    parser.add_argument("--nist-level", choices=LEVELS, default="3",
                        help="NIST security level (default 3)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_arguments(parser)
    parser.add_argument("cargo_args", nargs="*",
                        help="arguments for cargo build, after --")
    args = parser.parse_args()
    chosen = features(args.algorithm, args.nist_level)
    cmd = ["cargo", "build", "--release"]
    if chosen:
        cmd += ["--features", ",".join(f"{c}/{f}" for c in CRATES for f in chosen)]
    cmd += args.cargo_args
    print("$ " + " ".join(cmd), flush=True)
    return subprocess.run(cmd, cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
