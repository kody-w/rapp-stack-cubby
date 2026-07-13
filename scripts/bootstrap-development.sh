#!/bin/sh
set -eu
umask 077

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON_PATH=
VENV_DIR=
CACHE_DIR=
WORK_DIR=
INSTALL_DIR=
CONTROLLER_DIR=

while [ "$#" -gt 0 ]; do
    case "$1" in
        --python) PYTHON_PATH=${2:?}; shift 2 ;;
        --venv) VENV_DIR=${2:?}; shift 2 ;;
        --dependency-cache) CACHE_DIR=${2:?}; shift 2 ;;
        --work-dir) WORK_DIR=${2:?}; shift 2 ;;
        --install-dir) INSTALL_DIR=${2:?}; shift 2 ;;
        --controller-dir) CONTROLLER_DIR=${2:?}; shift 2 ;;
        *) echo "error: unsupported bootstrap argument: $1" >&2; exit 2 ;;
    esac
done

for VALUE in "$PYTHON_PATH" "$VENV_DIR" "$CACHE_DIR" "$WORK_DIR" \
    "$INSTALL_DIR" "$CONTROLLER_DIR"; do
    case "$VALUE" in
        /*) ;;
        *) echo "error: every bootstrap path must be explicit and absolute" >&2
           exit 2 ;;
    esac
done

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$ROOT/src" "$PYTHON_PATH" - \
    "$ROOT" "$CACHE_DIR" <<'PY'
import sys
from rapp_stack_cubby.packaging.dependencies import verify_dependency_cache

result = verify_dependency_cache(sys.argv[1], sys.argv[2])
if result.get("verified") is not True:
    raise SystemExit("error: dependency cache verification failed")
PY

install -d -m 700 "$WORK_DIR" "$INSTALL_DIR" "$CONTROLLER_DIR"
BOOTSTRAP_HOME="$WORK_DIR/bootstrap-home"
install -d -m 700 "$BOOTSTRAP_HOME"
if [ ! -d "$VENV_DIR" ]; then
    HOME="$BOOTSTRAP_HOME" "$PYTHON_PATH" -m venv "$VENV_DIR"
fi
chmod 700 "$VENV_DIR"
VENV_PYTHON="$VENV_DIR/bin/python"
[ -x "$VENV_PYTHON" ] || {
    echo "error: external virtual environment is invalid" >&2
    exit 2
}

HOME="$BOOTSTRAP_HOME" "$VENV_PYTHON" -m pip install \
    --disable-pip-version-check \
    --no-cache-dir \
    --no-index \
    --find-links "$CACHE_DIR" \
    --require-hashes \
    --only-binary=:all: \
    --no-deps \
    -r "$ROOT/requirements.lock"

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$ROOT/src" "$VENV_PYTHON" \
    -m rapp_stack_cubby doctor \
    --root "$ROOT" \
    --python "$VENV_PYTHON" \
    --work-dir "$WORK_DIR" \
    --dependency-cache "$CACHE_DIR" \
    --install-dir "$INSTALL_DIR" \
    --controller-dir "$CONTROLLER_DIR"
PYTHON="$VENV_PYTHON" "$ROOT/scripts/context-check.sh"
PYTHON="$VENV_PYTHON" "$ROOT/scripts/pages-check.sh"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$ROOT/src" "$VENV_PYTHON" \
    -m rapp_stack_cubby verify --root "$ROOT"

printf 'PASS development bootstrap: %s\n' "$VENV_PYTHON"
