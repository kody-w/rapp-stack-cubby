#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TAG=${1:?usage: prepare-release.sh TAG EXACT_COMMIT [candidate|final]}
EXPECTED_COMMIT=${2:?usage: prepare-release.sh TAG EXACT_COMMIT [candidate|final]}
STAGE=${3:-candidate}
VERSION=$(cat "$ROOT/VERSION")
if [ -n "${PYTHON:-}" ]; then
    PYTHON_COMMAND=$PYTHON
elif command -v python3.11 >/dev/null 2>&1; then
    PYTHON_COMMAND=python3.11
else
    echo "error: set PYTHON or install python3.11" >&2
    exit 2
fi

"$ROOT/scripts/validate-release-inputs.sh" "$TAG" "$EXPECTED_COMMIT" >/dev/null
case "$STAGE" in
  candidate|final) ;;
  *) echo "error: release stage must be candidate or final" >&2; exit 2 ;;
esac
: "${RAPP_PUBLICATION_SCAN_RECEIPT:?set the signed publication scan receipt}"
: "${RAPP_PUBLICATION_SCAN_SIGNATURE:?set the publication scan detached signature}"
case "$RAPP_PUBLICATION_SCAN_RECEIPT:$RAPP_PUBLICATION_SCAN_SIGNATURE" in
  /*:/*) ;;
  *) echo "error: publication scan paths must be absolute" >&2; exit 2 ;;
esac
case "$STAGE:$(basename "$RAPP_PUBLICATION_SCAN_RECEIPT"):$(basename "$RAPP_PUBLICATION_SCAN_SIGNATURE")" in
  candidate:candidate-publication-scan.json:candidate-publication-scan.json.sig) ;;
  final:final-publication-scan.json:final-publication-scan.json.sig) ;;
  *) echo "error: publication scan asset names do not match the release stage" >&2; exit 2 ;;
esac
PYTHON="$PYTHON_COMMAND" "$ROOT/scripts/verify-publication-scan.sh" \
  --receipt "$RAPP_PUBLICATION_SCAN_RECEIPT" \
  --phase "$STAGE" \
  --signature "$RAPP_PUBLICATION_SCAN_SIGNATURE" \
  --trust "$ROOT/RELEASE_TRUST.json" \
  --source-commit "$EXPECTED_COMMIT" >/dev/null
if [ "$STAGE" = final ]; then
  : "${RAPP_PROMOTION_EVIDENCE_DIRECTORY:?set the exact signed promotion evidence directory}"
  : "${RAPP_LIVE_PROOF_SHA256:?set the protected live proof receipt digest}"
  case "$RAPP_PROMOTION_EVIDENCE_DIRECTORY" in
    /*) ;;
    *) echo "error: promotion evidence directory must be absolute" >&2; exit 2 ;;
  esac
  PYTHONPATH="$ROOT/src" "$PYTHON_COMMAND" -m rapp_stack_cubby \
    verify-promotion \
    --root "$ROOT" \
    --evidence-directory "$RAPP_PROMOTION_EVIDENCE_DIRECTORY" \
    --policy "$ROOT/PUBLICATION_SCAN_POLICY.json" \
    --trust "$ROOT/RELEASE_TRUST.json" \
    --tag "$TAG" \
    --commit "$EXPECTED_COMMIT" \
    --live-proof-sha256 "$RAPP_LIVE_PROOF_SHA256" >/dev/null
fi
REMOTE_COMMIT=$(
  PYTHON="$PYTHON_COMMAND" \
    "$ROOT/scripts/resolve-release-tag.sh" "$TAG" "$EXPECTED_COMMIT"
)

HEAD_COMMIT=$(git -C "$ROOT" rev-parse HEAD)
if [ "$HEAD_COMMIT" != "$EXPECTED_COMMIT" ] ||
   [ "$REMOTE_COMMIT" != "$EXPECTED_COMMIT" ]; then
    echo "error: HEAD, remote tag, and expected commit must be identical" >&2
    exit 2
fi
git -C "$ROOT" fetch --quiet --no-tags origin main
if ! git -C "$ROOT" merge-base --is-ancestor "$EXPECTED_COMMIT" FETCH_HEAD; then
    echo "error: release commit is not on protected main history" >&2
    exit 2
fi
if ! git -C "$ROOT" diff --quiet --ignore-submodules -- ||
   ! git -C "$ROOT" diff --cached --quiet --ignore-submodules -- ||
   test -n "$(git -C "$ROOT" ls-files --others --exclude-standard)"; then
    echo "error: release preparation requires a clean source tree" >&2
    exit 2
fi

PYPROJECT_VERSION=$(
  PYTHONDONTWRITEBYTECODE=1 "$PYTHON_COMMAND" -c \
    'import pathlib,tomllib; print(tomllib.loads(pathlib.Path("'"$ROOT"'/pyproject.toml").read_text())["project"]["version"])'
)
if [ "$PYPROJECT_VERSION" != "$VERSION" ]; then
    echo "error: pyproject.toml and VERSION disagree" >&2
    exit 2
fi
if ! grep -Fq "__version__: Final = \"$VERSION\"" "$ROOT/src/rapp_stack_cubby/constants.py"; then
    echo "error: package version and VERSION disagree" >&2
    exit 2
fi
if ! grep -Fq "\"status\": \"pending\"" "$ROOT/RELEASE_STATUS.json"; then
    echo "error: committed source must remain release-pending" >&2
    exit 2
fi
PYTHONDONTWRITEBYTECODE=1 "$PYTHON_COMMAND" - \
  "$ROOT" "$VERSION" "$TAG" "$STAGE" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
version = sys.argv[2]
tag = sys.argv[3]
stage = sys.argv[4]
paths = (
    "RELEASE_STATUS.json",
    "STORE_INDEX.json",
    "rapp-super-rar.json",
    "cubbies/kody-w/rapplications/rapp-stack/manifest.json",
    "cubbies/kody-w/rapplications/rapp-stack/index_entry.json",
)
if any(json.loads((root / path).read_text())["version"] != version for path in paths):
    raise SystemExit("error: product manifests and VERSION disagree")
lock = json.loads((root / "STACK_LOCK.json").read_text())
if lock.get("project", {}).get("candidate_tag") != tag:
    raise SystemExit("error: STACK_LOCK candidate tag disagrees")
unresolved = {
    item.get("id")
    for item in lock.get("unresolved", [])
    if isinstance(item, dict) and item.get("status") == "unresolved"
}
status = lock.get("lock_status", {})
allow_release = lock.get("build_policy", {}).get("allow_release")
stages = lock.get("build_policy", {}).get("release_stages", {})
candidate_allowed = {
    "final-release-sha",
    "live-enrollment-publication-proof",
    "publication-scan",
    "public-end-to-end-attestation",
}
if stage == "candidate":
    protected = stages.get("protected_prerelease", {})
    live = stages.get("live_private", {})
    final = stages.get("final", {})
    if (
        unresolved != candidate_allowed
        or stages.get("phase_order") != [
            "A-source-offline",
            "B-protected-prerelease",
            "C-live-private",
            "D-pages-promotion",
        ]
        or set(stages.get("candidate", {}).get("allowed_unresolved_ids", []))
        != candidate_allowed
        or stages.get("candidate", {}).get("phase")
        != "A-source-offline"
        or stages.get("candidate", {}).get(
            "offline_installed_attestation_required"
        )
        is not True
        or stages.get("candidate", {}).get("publication")
        != "protected_prerelease_only"
        or stages.get("candidate", {}).get("publication_scan_receipt")
        != "signed_source_history_pages_release_assets_zero_findings"
        or stages.get("candidate", {}).get("asset_mutation_after_attestation")
        is not False
        or status.get("build_blocked") is not True
        or allow_release is not False
        or protected.get("phase") != "B-protected-prerelease"
        or protected.get("commit_and_assets")
        != "unchanged_from_phase_a"
        or protected.get("public_redownload_attestation_required")
        is not True
        or protected.get("candidate_publication_scan_asset_required")
        is not True
        or protected.get("postflight_evidence")
        != "signed_attested_actions_artifact_not_release_mutation"
        or protected.get("failure_state")
        != "explicit_failed_prerelease_no_pages"
        or live.get("phase") != "C-live-private"
        or live.get("same_public_commit_required") is not True
        or live.get("model_preflight_required") is not True
        or live.get("owner_enrollment_private") is not True
        or final.get("phase") != "D-pages-promotion"
        or final.get("new_source_commit_allowed") is not False
        or final.get("promotion_evidence")
        != "signed_attested_actions_artifact_then_verified_pages"
        or final.get("second_publication_scan_required")
        != "signed_public_redownload_and_completed_actions_logs"
    ):
        raise SystemExit("error: candidate stage unresolved gate allowlist changed")
else:
    final = stages.get("final", {})
    if (
        unresolved != candidate_allowed
        or set(final.get("source_allowed_unresolved_ids", []))
        != candidate_allowed
        or final.get("allowed_unresolved_ids") != []
        or final.get("external_promotion_receipt_closes_source_gates") is not True
        or final.get("receipt_signature_required") is not True
        or final.get("same_source_commit_required") is not True
        or final.get("promotion_evidence")
        != "signed_attested_actions_artifact_then_verified_pages"
        or status.get("build_blocked") is not True
        or allow_release is not False
    ):
        raise SystemExit(
            "error: final release requires signed external same-commit promotion closure"
        )
PY

echo "PASS release preparation ($STAGE): $TAG at $EXPECTED_COMMIT"
