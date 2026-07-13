#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ -n "${PYTHON:-}" ]; then
    PYTHON_COMMAND=$PYTHON
elif command -v python3.11 >/dev/null 2>&1; then
    PYTHON_COMMAND=python3.11
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_COMMAND=python3
else
    echo "error: set PYTHON or install python3.11" >&2
    exit 2
fi

CACHE_ROOT=$ROOT/.check-cache
cleanup() {
    rm -rf "$CACHE_ROOT"
}
trap cleanup EXIT HUP INT TERM

export PYTHONPATH=$ROOT/src
export PYTHONPYCACHEPREFIX=$CACHE_ROOT
export PYTHONDONTWRITEBYTECODE=1

find "$ROOT" \
    \( -path "$ROOT/.git" -o -path "$ROOT/dist" -o -path "$ROOT/build" \
    -o -path "$ROOT/.check-cache" \) -prune \
    -o -type d \( -name '__pycache__' -o -name '*.egg-info' \) \
    -exec rm -rf {} +

"$PYTHON_COMMAND" -c 'import sys; assert sys.version_info[:2] == (3, 11), "Python 3.11 is required"'
PYTHON="$PYTHON_COMMAND" "$ROOT/scripts/context-check.sh"
"$PYTHON_COMMAND" -m rapp_stack_cubby.pages check --root "$ROOT"
"$PYTHON_COMMAND" -m rapp_stack_cubby.catalog --root "$ROOT" --check
"$PYTHON_COMMAND" -m rapp_stack_cubby.agents.source_scan --root "$ROOT"
"$PYTHON_COMMAND" -m rapp_stack_cubby.controller.source_scan --root "$ROOT"
"$PYTHON_COMMAND" -m rapp_stack_cubby.imessage.source_scan --root "$ROOT"
"$PYTHON_COMMAND" -m rapp_stack_cubby.dependencies --root "$ROOT"
"$PYTHON_COMMAND" -m rapp_stack_cubby command-manifest \
    --root "$ROOT" --check --check-docs >/dev/null
"$PYTHON_COMMAND" -m rapp_stack_cubby source-manifest --root "$ROOT" --check >/dev/null
cmp -s \
    "$ROOT/cubbies/kody-w/agents/rapp_stack_cubby_agent.py" \
    "$ROOT/cubbies/kody-w/rapplications/rapp-stack/singleton/rapp_stack_cubby_agent.py" || {
    echo "error: controller singleton is not byte-identical" >&2
    exit 1
}
if find "$ROOT" \
    \( -path "$ROOT/.git" -o -path "$ROOT/dist" -o -path "$ROOT/build" \
    -o -path "$ROOT/.check-cache" \) -prune \
    -o -type f \( -name '*.whl' -o -name '*.egg' -o -name 'imsg-macos.zip' \
    -o -name '*.pyc' \) -print | grep -q .; then
    echo "error: forbidden binary/generated dependency found in source" >&2
    exit 1
fi
"$PYTHON_COMMAND" - "$ROOT" <<'PY'
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
manifest = json.loads(
    (root / "rapp-release-source-manifest.json").read_text(encoding="utf-8")
)
paths = [item["path"] for item in manifest["files"]]
if any(
    path.endswith((".pyc", ".pyo", ".whl", ".egg"))
    or any(part.endswith(".egg-info") for part in pathlib.PurePosixPath(path).parts)
    for path in paths
):
    raise SystemExit("error: generated binary is included in source manifest")
tracked = subprocess.run(
    ["git", "-C", str(root), "ls-files", "-z"],
    check=True,
    stdout=subprocess.PIPE,
).stdout.split(b"\0")
if any(
    path.endswith((b".pyc", b".pyo", b".whl", b".egg"))
    or b".egg-info/" in path
    for path in tracked
    if path
):
    raise SystemExit("error: generated binary is tracked")
PY
"$PYTHON_COMMAND" -m compileall -q \
    "$ROOT/src" \
    "$ROOT/tests" \
    "$ROOT/tools" \
    "$ROOT/cubbies/kody-w/agents" \
    "$ROOT/cubbies/kody-w/rapplications/rapp-stack/twin/agents"
"$PYTHON_COMMAND" -m unittest discover \
    --start-directory "$ROOT/tests" \
    --top-level-directory "$ROOT" \
    --pattern "test*.py" \
    -v
"$PYTHON_COMMAND" -m rapp_stack_cubby verify --root "$ROOT"
