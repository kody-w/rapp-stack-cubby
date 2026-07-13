#!/bin/sh
set -eu

PYTHON_PATH=
SOURCE_ROOT=
CONFIG_PATH=
PLIST_PATH=

while [ "$#" -gt 0 ]; do
    case "$1" in
        --python) PYTHON_PATH=$2; shift 2 ;;
        --source-root) SOURCE_ROOT=$2; shift 2 ;;
        --config) CONFIG_PATH=$2; shift 2 ;;
        --plist) PLIST_PATH=$2; shift 2 ;;
        *) echo "error: unsupported service installer argument" >&2; exit 2 ;;
    esac
done

[ -n "$PYTHON_PATH" ] && [ -n "$SOURCE_ROOT" ] &&
    [ -n "$CONFIG_PATH" ] && [ -n "$PLIST_PATH" ] || {
    echo "error: python, source-root, config, and plist are required" >&2
    exit 2
}

PYTHONPATH="$SOURCE_ROOT/src" "$PYTHON_PATH" -m rapp_stack_cubby \
    imessage service-install \
    --python "$PYTHON_PATH" \
    --source-root "$SOURCE_ROOT" \
    --config "$CONFIG_PATH" \
    --plist "$PLIST_PATH"
