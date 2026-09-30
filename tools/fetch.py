#!/usr/bin/env python3
"""Downloads the entries of third_party.toml into .work/downloads/.

  python3 tools/fetch.py              # everything
  python3 tools/fetch.py circomlib    # one entry

Each file is checked against its SHA-256 and kept only when it matches; an
entry with `extract` is also unpacked (npm tarballs: the `package/` prefix is
dropped). Existing files are re-hashed, not re-downloaded. BENCH_WORK_DIR moves
.work/, as it does for the benchmark binaries.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tarfile
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "third_party.toml"
CHUNK = 1 << 20


def downloads() -> Path:
    work = os.environ.get("BENCH_WORK_DIR") or str(ROOT / ".work")
    return Path(work) / "downloads"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, dest: Path, expected: str) -> None:
    part = dest.with_name(dest.name + ".part")
    digest = hashlib.sha256()
    print(f"Downloading {url}", flush=True)
    with urllib.request.urlopen(url) as response, part.open("wb") as out:
        while chunk := response.read(CHUNK):
            digest.update(chunk)
            out.write(chunk)
    if digest.hexdigest() != expected:
        part.unlink()
        sys.exit(f"{dest.name}: SHA-256 {digest.hexdigest()} does not match {expected}")
    part.rename(dest)


def extract(archive: Path, target: Path) -> None:
    tmp = target.with_name(target.name + ".part")
    shutil.rmtree(tmp, ignore_errors=True)
    with tarfile.open(archive) as tar:
        members = []
        for member in tar.getmembers():
            name = member.name.removeprefix("package/")
            if name == member.name or not name:
                continue
            member.name = name
            members.append(member)
        tar.extractall(tmp, members=members, filter="data")
    shutil.rmtree(target, ignore_errors=True)
    tmp.rename(target)


def fetch(name: str, entry: dict) -> None:
    dest = downloads() / entry["file"]
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_file() and sha256(dest) == entry["sha256"]:
        print(f"{name}: {dest} (verified)")
    else:
        dest.unlink(missing_ok=True)
        download(entry["url"], dest, entry["sha256"])
        print(f"{name}: {dest} (downloaded, verified)")
    if "extract" in entry:
        target = downloads() / entry["extract"]
        if not target.is_dir():
            extract(dest, target)
        print(f"{name}: {target}")


def main() -> None:
    manifest = tomllib.loads(MANIFEST.read_text())
    names = sys.argv[1:] or list(manifest)
    unknown = [n for n in names if n not in manifest]
    if unknown:
        sys.exit(f"unknown entries {unknown}; known: {', '.join(manifest)}")
    for name in names:
        fetch(name, manifest[name])


if __name__ == "__main__":
    main()
