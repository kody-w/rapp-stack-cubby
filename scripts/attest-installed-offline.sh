#!/bin/sh
set -eu
umask 077

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON_PATH=${1:?usage: attest-installed-offline.sh PYTHON INSTALL_ROOT CONTROLLER_ROOT RECEIPT}
INSTALL_ROOT=${2:?usage: attest-installed-offline.sh PYTHON INSTALL_ROOT CONTROLLER_ROOT RECEIPT}
CONTROLLER_ROOT=${3:?usage: attest-installed-offline.sh PYTHON INSTALL_ROOT CONTROLLER_ROOT RECEIPT}
RECEIPT=${4:?usage: attest-installed-offline.sh PYTHON INSTALL_ROOT CONTROLLER_ROOT RECEIPT}

case "$PYTHON_PATH:$INSTALL_ROOT:$CONTROLLER_ROOT:$RECEIPT" in
    /*:/*:/*:/*) ;;
    *) echo "error: offline attestation paths must be absolute" >&2; exit 2 ;;
esac

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$ROOT/src" \
    exec "$PYTHON_PATH" -m rapp_stack_cubby attest-installed \
    --install-root "$INSTALL_ROOT" \
    --controller-dir "$CONTROLLER_ROOT" \
    --receipt "$RECEIPT"
