#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ALLOW_PREVIOUS=false
if [ "${1:-}" = --previous ]; then
  ALLOW_PREVIOUS=true
  shift
fi
TAG=${1:?usage: resolve-release-tag.sh [--previous] TAG EXACT_COMMIT}
EXPECTED_COMMIT=${2:?usage: resolve-release-tag.sh [--previous] TAG EXACT_COMMIT}
PYTHON_COMMAND=${PYTHON:-python3}

if [ "$ALLOW_PREVIOUS" = true ]; then
  "$PYTHON_COMMAND" - "$TAG" "$EXPECTED_COMMIT" <<'PY'
import re
import sys
if re.fullmatch(
    r"v[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[1-9][0-9]*)?", sys.argv[1]
) is None or re.fullmatch(r"[0-9a-f]{40}", sys.argv[2]) is None:
    raise SystemExit("error: previous release tag or commit is invalid")
PY
else
  "$ROOT/scripts/validate-release-inputs.sh" "$TAG" "$EXPECTED_COMMIT" >/dev/null
fi

if ! REMOTE_OUTPUT=$(
  git -C "$ROOT" ls-remote --exit-code origin \
    "refs/tags/$TAG" "refs/tags/$TAG^{}"
); then
  echo "error: exact remote release tag is unavailable" >&2
  exit 2
fi
REMOTE_COMMIT=$(
  printf '%s\n' "$REMOTE_OUTPUT" |
    "$PYTHON_COMMAND" -c '
import re
import sys

tag = sys.argv[1]
base = f"refs/tags/{tag}"
allowed = {base, f"{base}^{{}}"}
records = {}
for line in sys.stdin:
    parts = line.rstrip("\n").split("\t")
    if len(parts) != 2 or parts[1] not in allowed or parts[1] in records:
        raise SystemExit("error: remote tag response is ambiguous")
    if re.fullmatch(r"[0-9a-f]{40}", parts[0]) is None:
        raise SystemExit("error: remote tag object is invalid")
    records[parts[1]] = parts[0]
if base not in records:
    raise SystemExit("error: remote release tag is missing")
print(records.get(f"{base}^{{}}", records[base]))
' "$TAG"
)
if [ "$REMOTE_COMMIT" != "$EXPECTED_COMMIT" ]; then
  echo "error: remote release tag moved or names another commit" >&2
  exit 2
fi

git -C "$ROOT" fetch --quiet --no-tags origin "refs/tags/$TAG"
OBJECT_TYPE=$(git -C "$ROOT" cat-file -t FETCH_HEAD)
case "$OBJECT_TYPE" in
  commit) FETCHED_COMMIT=$(git -C "$ROOT" rev-parse FETCH_HEAD) ;;
  tag) FETCHED_COMMIT=$(git -C "$ROOT" rev-parse "FETCH_HEAD^{commit}") ;;
  *) echo "error: release tag does not resolve to a commit" >&2; exit 2 ;;
esac
if [ "$FETCHED_COMMIT" != "$EXPECTED_COMMIT" ]; then
  echo "error: fetched release tag moved during resolution" >&2
  exit 2
fi
printf '%s\n' "$FETCHED_COMMIT"
