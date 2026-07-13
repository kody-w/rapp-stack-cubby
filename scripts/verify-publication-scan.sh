#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ -n "${PYTHON:-}" ]; then
    PYTHON_COMMAND=$PYTHON
elif command -v python3.11 >/dev/null 2>&1; then
    PYTHON_COMMAND=python3.11
else
    echo "error: set PYTHON to an explicit CPython 3.11 executable" >&2
    exit 2
fi

export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH=$ROOT/src
exec "$PYTHON_COMMAND" -m rapp_stack_cubby verify-publication-scan \
    --policy "$ROOT/PUBLICATION_SCAN_POLICY.json" \
    "$@"
