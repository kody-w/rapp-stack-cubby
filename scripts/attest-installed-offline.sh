#!/bin/sh
set -eu
umask 077

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
HOST_PYTHON=${1:?usage: attest-installed-offline.sh HOST_PYTHON INSTALL_ROOT CONTROLLER_ROOT RECEIPT}
INSTALL_ROOT=${2:?usage: attest-installed-offline.sh HOST_PYTHON INSTALL_ROOT CONTROLLER_ROOT RECEIPT}
CONTROLLER_ROOT=${3:?usage: attest-installed-offline.sh HOST_PYTHON INSTALL_ROOT CONTROLLER_ROOT RECEIPT}
RECEIPT=${4:?usage: attest-installed-offline.sh HOST_PYTHON INSTALL_ROOT CONTROLLER_ROOT RECEIPT}

case "$HOST_PYTHON:$INSTALL_ROOT:$CONTROLLER_ROOT:$RECEIPT" in
    /*:/*:/*:/*) ;;
    *) echo "error: offline attestation paths must be absolute" >&2; exit 2 ;;
esac

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$ROOT/src" \
    exec "$HOST_PYTHON" -m rapp_stack_cubby attest-installed \
    --install-root "$INSTALL_ROOT" \
    --host-python "$HOST_PYTHON" \
    --controller-dir "$CONTROLLER_ROOT" \
    --receipt "$RECEIPT"
