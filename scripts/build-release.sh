#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${PYTHON:?set PYTHON to an explicit CPython 3.11 executable}"
: "${RAPP_DEPENDENCY_CACHE:?set RAPP_DEPENDENCY_CACHE to an explicit absolute path}"
: "${SOURCE_DATE_EPOCH:?set SOURCE_DATE_EPOCH explicitly}"
: "${RAPP_SOURCE_REVISION:?set RAPP_SOURCE_REVISION to WORKTREE or an exact commit}"
OUTPUT=${RAPP_BUILD_OUTPUT:-"$ROOT/dist"}

case "$PYTHON:$RAPP_DEPENDENCY_CACHE:$OUTPUT" in
  /*:/*:/*) ;;
  *) echo "error: Python, cache, and output paths must be absolute" >&2; exit 2 ;;
esac

export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH=$ROOT/src
set -- "$PYTHON" -m rapp_stack_cubby build \
  --root "$ROOT" \
  --dependency-cache "$RAPP_DEPENDENCY_CACHE" \
  --output "$OUTPUT" \
  --source-date-epoch "$SOURCE_DATE_EPOCH" \
  --source-revision "$RAPP_SOURCE_REVISION"
if [ -n "${RAPP_RELEASE_SIGNING_KEY:-}" ]; then
  case "$RAPP_RELEASE_SIGNING_KEY" in
    /*) ;;
    *) echo "error: signing key path must be absolute" >&2; exit 2 ;;
  esac
  set -- "$@" --signing-key "$RAPP_RELEASE_SIGNING_KEY"
fi
if [ -n "${RAPP_RELEASE_SIGNING_TRUST:-}" ]; then
  case "$RAPP_RELEASE_SIGNING_TRUST" in
    /*) ;;
    *) echo "error: signing trust path must be absolute" >&2; exit 2 ;;
  esac
  set -- "$@" --signing-trust "$RAPP_RELEASE_SIGNING_TRUST"
fi
exec "$@"
