#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TAG=${1:?usage: validate-release-inputs.sh TAG EXACT_COMMIT}
COMMIT=${2:?usage: validate-release-inputs.sh TAG EXACT_COMMIT}
VERSION=$(cat "$ROOT/VERSION")
PYTHON_COMMAND=${PYTHON:-python3}
EXPECTED_TAG=$(
  "$PYTHON_COMMAND" -c '
import re
import sys
match = re.fullmatch(
    r"(?P<base>[0-9]+\.[0-9]+\.[0-9]+)(?:rc(?P<rc>[1-9][0-9]*))?",
    sys.argv[1],
)
if match is None:
    raise SystemExit("error: VERSION is invalid")
suffix = "-rc." + match.group("rc") if match.group("rc") else ""
print("v" + match.group("base") + suffix)
' "$VERSION"
)

if [ "$TAG" != "$EXPECTED_TAG" ]; then
  echo "error: release tag is not the exact VERSION-derived tag" >&2
  exit 2
fi
case "$COMMIT" in
  *[!0-9a-f]*|'') echo "error: release commit must be 40 lowercase hex" >&2; exit 2 ;;
esac
if [ "${#COMMIT}" -ne 40 ]; then
  echo "error: release commit must be 40 lowercase hex" >&2
  exit 2
fi

printf 'PASS release inputs: %s at %s\n' "$EXPECTED_TAG" "$COMMIT"
