#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${PYTHON:?set PYTHON to an explicit CPython 3.11 executable}"
: "${RAPP_DEPENDENCY_CACHE:?set RAPP_DEPENDENCY_CACHE to an explicit absolute path outside the repository}"

case "$PYTHON" in
  /*) ;;
  *) echo "error: PYTHON must be absolute" >&2; exit 2 ;;
esac
case "$RAPP_DEPENDENCY_CACHE" in
  /*) ;;
  *) echo "error: RAPP_DEPENDENCY_CACHE must be absolute" >&2; exit 2 ;;
esac

export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH=$ROOT/src
exec "$PYTHON" -m rapp_stack_cubby fetch-dependencies \
  --root "$ROOT" \
  --cache "$RAPP_DEPENDENCY_CACHE"
