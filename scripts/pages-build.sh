#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ -n "${PYTHON:-}" ]; then
    PYTHON_COMMAND=$PYTHON
elif command -v python3.11 >/dev/null 2>&1; then
    PYTHON_COMMAND=python3.11
else
    echo "error: set PYTHON or install python3.11" >&2
    exit 2
fi

export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH=$ROOT/src

"$PYTHON_COMMAND" -c 'import sys; assert sys.version_info[:2] == (3, 11), "Python 3.11 is required"'
exec "$PYTHON_COMMAND" -m rapp_stack_cubby.pages build --root "$ROOT" "$@"
