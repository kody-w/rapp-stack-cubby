#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON_COMMAND=${PYTHON:-python3.11}

export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH=$ROOT/src
exec "$PYTHON_COMMAND" -m rapp_stack_cubby.audit --root "$ROOT"
