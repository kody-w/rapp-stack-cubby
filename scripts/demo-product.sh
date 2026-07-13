#!/bin/sh
set -eu
umask 077

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[ "${1:-}" = "--python" ] && [ "$#" -ge 2 ] || {
    echo "usage: demo-product.sh --python /absolute/python [demo options]" >&2
    exit 2
}
PYTHON_PATH=$2
shift 2
case "$PYTHON_PATH" in
    /*) ;;
    *) echo "error: --python must be absolute" >&2; exit 2 ;;
esac

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$ROOT/src" \
    exec "$PYTHON_PATH" -m rapp_stack_cubby demo \
    --root "$ROOT" \
    --python "$PYTHON_PATH" \
    "$@"
