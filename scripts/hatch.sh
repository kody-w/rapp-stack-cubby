#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${PYTHON:?set PYTHON to the explicit CPython 3.11 executable}"
: "${RAPP_EGG:?set RAPP_EGG to an explicit cubby egg path}"
: "${RAPP_INSTALL_ROOT:?set RAPP_INSTALL_ROOT to a new explicit install path}"
: "${RAPP_EGG_SHA256:?set RAPP_EGG_SHA256 to the externally verified digest}"
: "${RAPP_RELEASE_MANIFEST:?set RAPP_RELEASE_MANIFEST to the signed sidecar}"
: "${RAPP_RELEASE_MANIFEST_SHA256:?set RAPP_RELEASE_MANIFEST_SHA256 explicitly}"
: "${RAPP_RELEASE_TRUST:?set RAPP_RELEASE_TRUST to RELEASE_TRUST.json}"

case "$PYTHON:$RAPP_EGG:$RAPP_INSTALL_ROOT:$RAPP_RELEASE_MANIFEST:$RAPP_RELEASE_TRUST" in
  /*:/*:/*:/*:/*) ;;
  *) echo "error: Python, artifact, trust, and install paths must be absolute" >&2; exit 2 ;;
esac

export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH=$ROOT/src
set -- "$PYTHON" -m rapp_stack_cubby hatch-egg \
  --egg "$RAPP_EGG" \
  --install-root "$RAPP_INSTALL_ROOT" \
  --python "$PYTHON" \
  --egg-sha256 "$RAPP_EGG_SHA256" \
  --release-manifest "$RAPP_RELEASE_MANIFEST" \
  --release-manifest-sha256 "$RAPP_RELEASE_MANIFEST_SHA256" \
  --release-trust "$RAPP_RELEASE_TRUST"
if [ -n "${RAPP_CONTROLLER_LOADOUT_ROOT:-}" ]; then
  case "$RAPP_CONTROLLER_LOADOUT_ROOT" in
    /*) ;;
    *) echo "error: controller loadout path must be absolute" >&2; exit 2 ;;
  esac
  set -- "$@" --controller-loadout-root "$RAPP_CONTROLLER_LOADOUT_ROOT"
fi
if [ "${RAPP_TRUSTED_DEVELOPMENT:-0}" = "1" ]; then
  set -- "$@" --trusted-development
fi
exec "$@"
