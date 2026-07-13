#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${CENSUS_CUTOFF:?set CENSUS_CUTOFF to an exact UTC RFC3339 timestamp}"
OUTPUT=${CENSUS_CANDIDATE_OUTPUT:-docs/research/census-refresh-candidate.json}
OWNER=${CENSUS_OWNER:-kody-w}
PYTHON_COMMAND=${PYTHON:-python3.11}

export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH=$ROOT/src
exec "$PYTHON_COMMAND" -m rapp_stack_cubby.census_refresh \
    --root "$ROOT" \
    --owner "$OWNER" \
    --cutoff "$CENSUS_CUTOFF" \
    --output "$OUTPUT"
