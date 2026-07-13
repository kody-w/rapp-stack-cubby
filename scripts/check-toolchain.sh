#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON_COMMAND=${PYTHON:-python3}

PYTHONDONTWRITEBYTECODE=1 "$PYTHON_COMMAND" - "$ROOT" <<'PY'
import json
import platform
import pathlib
import subprocess
import sys
import zlib

root = pathlib.Path(sys.argv[1])
lock = json.loads((root / "GITHUB_ACTIONS_LOCK.json").read_text())
runner = lock["runner"]
if (
    runner.get("label") != "macos-15"
    or runner.get("architecture") != "arm64"
    or runner.get("label_source")
    != "https://docs.github.com/en/actions/reference/runners/github-hosted-runners#standard-github-hosted-runners-for-public-repositories"
):
    raise SystemExit("error: official macOS 15 ARM64 runner claim is invalid")
expected = runner["toolchain"]["python"]
actual = ".".join(str(value) for value in sys.version_info[:3])
if actual != expected:
    raise SystemExit(f"error: Python {actual} does not match lock {expected}")
if platform.machine() != runner["architecture"]:
    raise SystemExit("error: runner architecture does not match action lock")
print(f"Python {actual}")
print(subprocess.check_output(["git", "--version"], text=True).strip())
print(subprocess.check_output(["gh", "--version"], text=True).splitlines()[0])
print(f"zlib build={zlib.ZLIB_VERSION} runtime={zlib.ZLIB_RUNTIME_VERSION}")
print("runner label=macos-15 architecture=arm64 (official GitHub-hosted table)")
print("reproducibility scope: same locked runner image and toolchain")
PY
