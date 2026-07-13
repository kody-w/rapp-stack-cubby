#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON_COMMAND=${PYTHON:-python3}
REPOSITORY=${GITHUB_REPOSITORY:-kody-w/rapp-stack-cubby}
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT/src"
TAG=
COMMIT=
MANIFEST_SHA=
LIVE_PROOF=
LIVE_PROOF_SIGNATURE=
LIVE_PROOF_SHA=
POSTFLIGHT_RECEIPT=
POSTFLIGHT_SIGNATURE=
POSTFLIGHT_ATTESTATION=
SIGNING_KEY=
CANDIDATE_DIR=
REDOWNLOAD_DIR=
LOGS_DIR=
OUTPUT_DIR=
ACTIONS_LOGS=
TIMESTAMP=${PROMOTION_TIMESTAMP:-}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --tag) TAG=$2; shift 2 ;;
    --commit) COMMIT=$2; shift 2 ;;
    --release-manifest-sha256) MANIFEST_SHA=$2; shift 2 ;;
    --live-proof) LIVE_PROOF=$2; shift 2 ;;
    --live-proof-signature) LIVE_PROOF_SIGNATURE=$2; shift 2 ;;
    --live-proof-sha256) LIVE_PROOF_SHA=$2; shift 2 ;;
    --postflight-receipt) POSTFLIGHT_RECEIPT=$2; shift 2 ;;
    --postflight-signature) POSTFLIGHT_SIGNATURE=$2; shift 2 ;;
    --postflight-attestation) POSTFLIGHT_ATTESTATION=$2; shift 2 ;;
    --signing-key) SIGNING_KEY=$2; shift 2 ;;
    --candidate-dir) CANDIDATE_DIR=$2; shift 2 ;;
    --redownload-dir) REDOWNLOAD_DIR=$2; shift 2 ;;
    --logs-dir) LOGS_DIR=$2; shift 2 ;;
    --output-dir) OUTPUT_DIR=$2; shift 2 ;;
    --timestamp) TIMESTAMP=$2; shift 2 ;;
    --actions-log)
      ACTIONS_LOGS="${ACTIONS_LOGS}
$2"
      shift 2
      ;;
    *) echo "error: unsupported promotion argument: $1" >&2; exit 2 ;;
  esac
done

for VALUE in "$LIVE_PROOF" "$LIVE_PROOF_SIGNATURE" \
  "$POSTFLIGHT_RECEIPT" "$POSTFLIGHT_SIGNATURE" \
  "$POSTFLIGHT_ATTESTATION" "$SIGNING_KEY" \
  "$CANDIDATE_DIR" "$REDOWNLOAD_DIR" "$LOGS_DIR" "$OUTPUT_DIR"
do
  case "$VALUE" in
    /*) ;;
    *) echo "error: promotion paths must be explicit and absolute" >&2; exit 2 ;;
  esac
done
"$ROOT/scripts/validate-release-inputs.sh" "$TAG" "$COMMIT" >/dev/null
case "$MANIFEST_SHA:$LIVE_PROOF_SHA" in
  *[!0-9a-f:]*|:*) echo "error: promotion digests must be lowercase hex" >&2; exit 2 ;;
esac
if [ "${#MANIFEST_SHA}" -ne 64 ] || [ "${#LIVE_PROOF_SHA}" -ne 64 ]; then
  echo "error: promotion digests must be exact SHA-256" >&2
  exit 2
fi
case "$TIMESTAMP" in
  ????-??-??T??:??:??Z) ;;
  *) echo "error: promotion timestamp must be exact UTC seconds" >&2; exit 2 ;;
esac
if [ ! -f "$LIVE_PROOF" ] || [ -L "$LIVE_PROOF" ] ||
   [ ! -f "$LIVE_PROOF_SIGNATURE" ] || [ -L "$LIVE_PROOF_SIGNATURE" ] ||
   [ ! -f "$POSTFLIGHT_RECEIPT" ] || [ -L "$POSTFLIGHT_RECEIPT" ] ||
   [ ! -f "$POSTFLIGHT_SIGNATURE" ] || [ -L "$POSTFLIGHT_SIGNATURE" ] ||
   [ ! -f "$POSTFLIGHT_ATTESTATION" ] || [ -L "$POSTFLIGHT_ATTESTATION" ] ||
   [ ! -f "$SIGNING_KEY" ] || [ -L "$SIGNING_KEY" ] ||
   [ -e "$CANDIDATE_DIR" ] || [ -L "$CANDIDATE_DIR" ] ||
   [ -e "$REDOWNLOAD_DIR" ] || [ -L "$REDOWNLOAD_DIR" ] ||
   [ -e "$LOGS_DIR" ] || [ -L "$LOGS_DIR" ] ||
   [ -e "$OUTPUT_DIR" ] || [ -L "$OUTPUT_DIR" ]; then
  echo "error: promotion inputs or fresh output paths are invalid" >&2
  exit 2
fi

"$ROOT/scripts/resolve-release-tag.sh" "$TAG" "$COMMIT" >/dev/null
if [ "$(git -C "$ROOT" rev-parse HEAD)" != "$COMMIT" ]; then
  echo "error: promotion checkout is not the exact candidate commit" >&2
  exit 2
fi
if ! git -C "$ROOT" diff --quiet --ignore-submodules -- ||
   ! git -C "$ROOT" diff --cached --quiet --ignore-submodules -- ||
   test -n "$(git -C "$ROOT" ls-files --others --exclude-standard)"; then
  echo "error: promotion requires a clean exact source checkout" >&2
  exit 2
fi
mkdir -m 700 "$CANDIDATE_DIR" "$REDOWNLOAD_DIR" "$LOGS_DIR" "$OUTPUT_DIR"

METADATA="$OUTPUT_DIR.release-metadata.json"
RUNS_JSON="$OUTPUT_DIR.release-runs.json"
CORE_DIR="$OUTPUT_DIR.core-assets"
CORE_EVIDENCE="$OUTPUT_DIR.core-attestations"
PUBLICATION_EVIDENCE="$OUTPUT_DIR.publication-attestations"
CORE_RESULT="$OUTPUT_DIR.core-attestation.json"
PUBLICATION_RESULT="$OUTPUT_DIR.publication-attestation.json"
cleanup() {
  git -C "$ROOT" checkout -- \
    docs/index.html \
    docs/pages-manifest.json \
    docs/api/v1/architecture.json \
    docs/api/v1/capabilities.json \
    docs/api/v1/context.json \
    docs/api/v1/downloads.json \
    docs/api/v1/prompts.json \
    docs/api/v1/status.json >/dev/null 2>&1 || true
  rm -rf "$ROOT/docs/evidence"
  rm -f "$METADATA" "$RUNS_JSON" "$CORE_RESULT" "$PUBLICATION_RESULT"
  rm -rf "$CORE_DIR" "$CORE_EVIDENCE" "$PUBLICATION_EVIDENCE"
}
trap cleanup EXIT HUP INT TERM
gh api -H "Accept: application/vnd.github+json" \
  "repos/$REPOSITORY/releases/tags/$TAG" >"$METADATA"
"$PYTHON_COMMAND" - "$METADATA" "$TAG" "$COMMIT" <<'PY'
import json
import pathlib
import sys
from rapp_stack_cubby.promotion import SUCCESSFUL_CANDIDATE_ASSETS

path, tag, commit = sys.argv[1:]
value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
assets = value.get("assets")
names = sorted(
    item.get("name")
    for item in assets
    if isinstance(item, dict) and isinstance(item.get("name"), str)
) if isinstance(assets, list) else []
if (
    value.get("tag_name") != tag
    or value.get("target_commitish") != commit
    or value.get("draft") is not False
    or value.get("immutable") is not True
    or value.get("prerelease") is not True
    or str(value.get("name", "")).startswith("FAILED POSTFLIGHT")
    or str(value.get("name", "")).startswith("PROMOTED:")
    or names != sorted(SUCCESSFUL_CANDIDATE_ASSETS)
):
    raise SystemExit("error: candidate release metadata is not promotable")
PY

gh release download "$TAG" --repo "$REPOSITORY" --dir "$CANDIDATE_DIR"
gh release download "$TAG" --repo "$REPOSITORY" --dir "$REDOWNLOAD_DIR"
"$PYTHON_COMMAND" - "$CANDIDATE_DIR" "$REDOWNLOAD_DIR" <<'PY'
import pathlib
import sys
from rapp_stack_cubby.promotion import SUCCESSFUL_CANDIDATE_ASSETS

first, second = map(pathlib.Path, sys.argv[1:])
expected = set(SUCCESSFUL_CANDIDATE_ASSETS)
for root in (first, second):
    observed = {item.name for item in root.iterdir()}
    if observed != expected or any(
        not (root / name).is_file() or (root / name).is_symlink()
        for name in expected
    ):
        raise SystemExit("error: downloaded candidate inventory is not exact")
for name in expected:
    if (first / name).read_bytes() != (second / name).read_bytes():
        raise SystemExit(f"error: repeated public download changed: {name}")
PY

PYTHONPATH="$ROOT/src" "$PYTHON_COMMAND" - \
  "$CANDIDATE_DIR" "$ROOT/RELEASE_TRUST.json" "$TAG" "$COMMIT" \
  "$MANIFEST_SHA" "$LIVE_PROOF" "$LIVE_PROOF_SIGNATURE" "$LIVE_PROOF_SHA" \
  "$ROOT/PUBLICATION_SCAN_POLICY.json" "$POSTFLIGHT_RECEIPT" \
  "$POSTFLIGHT_SIGNATURE" <<'PY'
import pathlib
import sys
from rapp_stack_cubby.packaging.publication import verify_publication_receipt
from rapp_stack_cubby.promotion import (
    verify_live_proof_receipt,
    verify_postflight_receipt,
)

(directory, trust, tag, commit, manifest_sha, live, live_signature, live_sha,
 policy, postflight, postflight_signature) = sys.argv[1:]
verify_publication_receipt(
    pathlib.Path(directory) / "candidate-publication-scan.json",
    policy_path=policy,
    required_phase="candidate",
    signature_path=pathlib.Path(directory) / "candidate-publication-scan.json.sig",
    trust_path=trust,
    expected_source_commit=commit,
)
verify_postflight_receipt(
    postflight,
    postflight_signature,
    trust_path=trust,
    expected_tag=tag,
    expected_commit=commit,
    expected_manifest_sha256=manifest_sha,
)
verify_live_proof_receipt(
    live,
    live_signature,
    trust_path=trust,
    expected_tag=tag,
    expected_commit=commit,
    expected_sha256=live_sha,
)
PY

mkdir -m 700 "$CORE_DIR"
for ASSET in \
  SBOM.spdx.json \
  SHA256SUMS \
  rapp-stack-cubby-store.zip \
  rapp-stack-cubby.egg \
  rapp-super-rar.json \
  release-manifest.json \
  release-manifest.json.sig \
  release-provenance.json \
  store-index.json
do
  cp "$CANDIDATE_DIR/$ASSET" "$CORE_DIR/$ASSET"
done
PYTHON="$PYTHON_COMMAND" "$ROOT/scripts/verify-github-attestations.sh" \
  "$CORE_DIR" "$COMMIT" "$CORE_EVIDENCE" "$CORE_RESULT" core
PYTHON="$PYTHON_COMMAND" "$ROOT/scripts/verify-github-attestations.sh" \
  "$CANDIDATE_DIR" "$COMMIT" "$PUBLICATION_EVIDENCE" \
  "$PUBLICATION_RESULT" candidate-success
PYTHONPATH="$ROOT/src" "$PYTHON_COMMAND" -m rapp_stack_cubby verify-release \
  --release-manifest "$CORE_DIR/release-manifest.json" \
  --release-manifest-sha256 "$MANIFEST_SHA" \
  --trust "$ROOT/RELEASE_TRUST.json" \
  --signature "$CORE_DIR/release-manifest.json.sig" \
  --checksums "$CORE_DIR/SHA256SUMS" \
  --source-root "$ROOT" \
  --github-attestation "$CORE_RESULT" >/dev/null

if [ -z "$ACTIONS_LOGS" ]; then
  gh api \
    -H "Accept: application/vnd.github+json" \
    --paginate \
    --slurp \
    "repos/$REPOSITORY/actions/workflows/release.yml/runs?head_sha=$COMMIT&status=completed&per_page=100" \
    >"$RUNS_JSON"
  RUN_IDS=$(
    "$PYTHON_COMMAND" - "$RUNS_JSON" "$COMMIT" <<'PY'
import json
import pathlib
import sys

pages = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
commit = sys.argv[2]
if not isinstance(pages, list) or not pages:
    raise SystemExit("error: no completed release workflow logs were found")
runs = []
for page in pages:
    if not isinstance(page, dict) or not isinstance(page.get("workflow_runs"), list):
        raise SystemExit("error: release workflow pagination is invalid")
    runs.extend(page["workflow_runs"])
if not runs:
    raise SystemExit("error: no completed release workflow logs were found")
ids = []
for run in runs:
    if (
        not isinstance(run, dict)
        or run.get("head_sha") != commit
        or run.get("status") != "completed"
        or not str(run.get("path", "")).endswith("/release.yml")
        or not isinstance(run.get("id"), int)
        or isinstance(run["id"], bool)
        or run["id"] <= 0
        or not isinstance(run.get("conclusion"), str)
    ):
        raise SystemExit("error: release workflow run metadata is invalid")
    ids.append(str(run["id"]))
if len(ids) != len(set(ids)):
    raise SystemExit("error: duplicate release workflow run ID")
print("\n".join(sorted(ids, key=int)))
PY
  )
  for RUN_ID in $RUN_IDS
  do
    gh api \
      -H "Accept: application/vnd.github+json" \
      "repos/$REPOSITORY/actions/runs/$RUN_ID/logs" >"$LOGS_DIR/$RUN_ID.zip"
  done
else
  printf '%s\n' "$ACTIONS_LOGS" | sed '/^$/d' | while IFS= read -r ENTRY
  do
    RUN_ID=${ENTRY%%=*}
    ARCHIVE=${ENTRY#*=}
    case "$RUN_ID" in
      ''|*[!0-9]*) echo "error: Actions run ID must be numeric" >&2; exit 2 ;;
    esac
    case "$ARCHIVE" in
      /*) ;;
      *) echo "error: Actions log path must be absolute" >&2; exit 2 ;;
    esac
    if [ ! -f "$ARCHIVE" ] || [ -L "$ARCHIVE" ]; then
      echo "error: explicit Actions log archive is invalid" >&2
      exit 2
    fi
    RUN_METADATA=$(
      gh api -H "Accept: application/vnd.github+json" \
        "repos/$REPOSITORY/actions/runs/$RUN_ID"
    )
    printf '%s' "$RUN_METADATA" | "$PYTHON_COMMAND" -c \
      'import json,sys; v=json.load(sys.stdin); expected=sys.argv[1]; assert v["head_sha"] == expected and v["status"] == "completed" and v["path"].endswith("/release.yml")' \
      "$COMMIT"
    cp "$ARCHIVE" "$LOGS_DIR/$RUN_ID.zip"
  done
fi

PYTHON="$PYTHON_COMMAND" "$ROOT/scripts/pages-build.sh" --candidate \
  --release-directory "$CANDIDATE_DIR" \
  --release-manifest "$CANDIDATE_DIR/release-manifest.json" \
  --release-manifest-sha256 "$MANIFEST_SHA" \
  --release-signature "$CANDIDATE_DIR/release-manifest.json.sig" \
  --release-trust "$ROOT/RELEASE_TRUST.json" \
  --checksums "$CANDIDATE_DIR/SHA256SUMS" \
  --source-root "$ROOT" \
  --github-attestation "$CORE_RESULT" \
  --publication-attestation "$PUBLICATION_RESULT" \
  --postflight-attestation "$POSTFLIGHT_ATTESTATION" \
  --release-metadata "$METADATA" \
  --candidate-publication-scan "$CANDIDATE_DIR/candidate-publication-scan.json" \
  --candidate-publication-scan-signature "$CANDIDATE_DIR/candidate-publication-scan.json.sig" \
  --postflight-receipt "$POSTFLIGHT_RECEIPT" \
  --postflight-signature "$POSTFLIGHT_SIGNATURE" \
  --release-tag "$TAG"

cp "$CANDIDATE_DIR/candidate-publication-scan.json" \
  "$OUTPUT_DIR/candidate-publication-scan.json"
cp "$CANDIDATE_DIR/candidate-publication-scan.json.sig" \
  "$OUTPUT_DIR/candidate-publication-scan.json.sig"
cp "$POSTFLIGHT_RECEIPT" "$OUTPUT_DIR/postflight-success.json"
cp "$POSTFLIGHT_SIGNATURE" "$OUTPUT_DIR/postflight-success.json.sig"
cp "$LIVE_PROOF" "$OUTPUT_DIR/live-proof-receipt.json"
cp "$LIVE_PROOF_SIGNATURE" "$OUTPUT_DIR/live-proof-receipt.json.sig"

PYTHONPATH="$ROOT/src" "$PYTHON_COMMAND" - \
  "$ROOT" "$CANDIDATE_DIR" "$REDOWNLOAD_DIR" "$LOGS_DIR" \
  "$OUTPUT_DIR" "$TIMESTAMP" "$SIGNING_KEY" \
  "$TAG" "$COMMIT" "$MANIFEST_SHA" <<'PY'
import json
import pathlib
import sys
from rapp_stack_cubby.packaging.publication import (
    scan_publication,
    sign_publication_receipt,
    write_publication_receipt,
)
from rapp_stack_cubby.promotion import sign_evidence, write_promotion_receipt

root, candidate, redownload, logs, output = map(pathlib.Path, sys.argv[1:6])
timestamp = sys.argv[6]
key = pathlib.Path(sys.argv[7])
actions = [
    (path.stem, path)
    for path in sorted(logs.glob("*.zip"), key=lambda value: int(value.stem))
]
if not actions:
    raise SystemExit("error: final scan requires completed Actions logs")
final_path = output / "final-publication-scan.json"
final_signature = output / "final-publication-scan.json.sig"
receipt = scan_publication(
    root,
    policy_path=root / "PUBLICATION_SCAN_POLICY.json",
    pages_root=root / "docs",
    release_assets_root=candidate,
    public_redownload_root=redownload,
    actions_logs=actions,
    phase="final",
    timestamp=timestamp,
)
write_publication_receipt(final_path, receipt)
if receipt["result"] != "pass":
    raise SystemExit("error: final publication scan has findings")
sign_publication_receipt(
    final_path,
    final_signature,
    key_path=key,
    repository_root=root,
    trust_path=root / "RELEASE_TRUST.json",
)
promotion_path = output / "promotion-receipt.json"
write_promotion_receipt(
    promotion_path,
    tag=sys.argv[8],
    commit=sys.argv[9],
    manifest_sha256=sys.argv[10],
    evidence_directory=output,
    actions_evidence=receipt["actions_evidence"],
    timestamp=timestamp,
)
sign_evidence(
    promotion_path,
    output / "promotion-receipt.json.sig",
    key_path=key,
    repository_root=root,
    trust_path=root / "RELEASE_TRUST.json",
)
PY

git -C "$ROOT" checkout -- \
  docs/index.html \
  docs/pages-manifest.json \
  docs/api/v1/architecture.json \
  docs/api/v1/capabilities.json \
  docs/api/v1/context.json \
  docs/api/v1/downloads.json \
  docs/api/v1/prompts.json \
  docs/api/v1/status.json
rm -rf "$ROOT/docs/evidence"

PYTHONPATH="$ROOT/src" "$PYTHON_COMMAND" -m rapp_stack_cubby verify-promotion \
  --evidence-directory "$OUTPUT_DIR" \
  --policy "$ROOT/PUBLICATION_SCAN_POLICY.json" \
  --trust "$ROOT/RELEASE_TRUST.json" \
  --tag "$TAG" \
  --commit "$COMMIT" \
  --live-proof-sha256 "$LIVE_PROOF_SHA" >/dev/null

RAPP_PUBLICATION_SCAN_RECEIPT="$OUTPUT_DIR/final-publication-scan.json" \
RAPP_PUBLICATION_SCAN_SIGNATURE="$OUTPUT_DIR/final-publication-scan.json.sig" \
RAPP_PROMOTION_EVIDENCE_DIRECTORY="$OUTPUT_DIR" \
RAPP_LIVE_PROOF_SHA256="$LIVE_PROOF_SHA" \
PYTHON="$PYTHON_COMMAND" \
  "$ROOT/scripts/prepare-release.sh" "$TAG" "$COMMIT" final

"$ROOT/scripts/resolve-release-tag.sh" "$TAG" "$COMMIT" >/dev/null
printf 'PASS promotion evidence prepared: %s at %s\n' "$TAG" "$COMMIT"
