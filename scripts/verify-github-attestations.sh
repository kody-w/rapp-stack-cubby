#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RELEASE_DIR=${1:?usage: verify-github-attestations.sh RELEASE_DIR COMMIT EVIDENCE_DIR RESULT}
COMMIT=${2:?usage: verify-github-attestations.sh RELEASE_DIR COMMIT EVIDENCE_DIR RESULT}
EVIDENCE_DIR=${3:?usage: verify-github-attestations.sh RELEASE_DIR COMMIT EVIDENCE_DIR RESULT}
RESULT=${4:?usage: verify-github-attestations.sh RELEASE_DIR COMMIT EVIDENCE_DIR RESULT [core|candidate|candidate-success|final|postflight|promotion]}
PROFILE=${5:-core}
REPOSITORY=kody-w/rapp-stack-cubby
RELEASE_WORKFLOW="$REPOSITORY/.github/workflows/release.yml"
PROMOTION_WORKFLOW="$REPOSITORY/.github/workflows/promote.yml"
PYTHON_COMMAND=${PYTHON:-python3}

case "$COMMIT" in
  *[!0-9a-f]*|'') echo "error: attestation commit must be 40 lowercase hex" >&2; exit 2 ;;
esac
if [ "${#COMMIT}" -ne 40 ] || [ ! -d "$RELEASE_DIR" ] ||
   [ -e "$EVIDENCE_DIR" ] || [ -L "$EVIDENCE_DIR" ] ||
   [ -e "$RESULT" ] || [ -L "$RESULT" ]; then
  echo "error: attestation inputs or fresh outputs are invalid" >&2
  exit 2
fi
mkdir -m 700 "$EVIDENCE_DIR"

case "$PROFILE" in
core)
  ASSET_LIST='
  SBOM.spdx.json SHA256SUMS rapp-stack-cubby-store.zip rapp-stack-cubby.egg
  rapp-super-rar.json release-manifest.json release-manifest.json.sig
  release-provenance.json
  store-index.json'
  ;;
candidate)
  ASSET_LIST='
  SBOM.spdx.json SHA256SUMS rapp-stack-cubby-store.zip rapp-stack-cubby.egg
  rapp-super-rar.json release-manifest.json release-manifest.json.sig
  release-provenance.json store-index.json
  candidate-publication-scan.json candidate-publication-scan.json.sig'
  ;;
candidate-success)
  ASSET_LIST='
  SBOM.spdx.json SHA256SUMS rapp-stack-cubby-store.zip rapp-stack-cubby.egg
  rapp-super-rar.json release-manifest.json release-manifest.json.sig
  release-provenance.json store-index.json
  candidate-publication-scan.json candidate-publication-scan.json.sig
  postflight-success.json postflight-success.json.sig'
  ;;
final)
  ASSET_LIST='
  SBOM.spdx.json SHA256SUMS rapp-stack-cubby-store.zip rapp-stack-cubby.egg
  rapp-super-rar.json release-manifest.json release-manifest.json.sig
  release-provenance.json store-index.json
  candidate-publication-scan.json candidate-publication-scan.json.sig'
  ;;
promotion)
  ASSET_LIST='
  final-publication-scan.json final-publication-scan.json.sig
  live-proof-receipt.json live-proof-receipt.json.sig
  promotion-receipt.json promotion-receipt.json.sig'
  ;;
postflight)
  ASSET_LIST='postflight-success.json postflight-success.json.sig'
  ;;
*) echo "error: invalid attestation asset profile" >&2; exit 2 ;;
esac

for ASSET in $ASSET_LIST
do
  SIGNER_WORKFLOW=$RELEASE_WORKFLOW
  case "$ASSET" in
    final-publication-scan.json|final-publication-scan.json.sig|\
    live-proof-receipt.json|live-proof-receipt.json.sig|\
    promotion-receipt.json|promotion-receipt.json.sig)
      SIGNER_WORKFLOW=$PROMOTION_WORKFLOW
      ;;
  esac
  gh attestation verify "$RELEASE_DIR/$ASSET" \
    --repo "$REPOSITORY" \
    --signer-workflow "$SIGNER_WORKFLOW" \
    --source-digest "$COMMIT" \
    --deny-self-hosted-runners \
    --format json >"$EVIDENCE_DIR/$ASSET.json"
done

"$PYTHON_COMMAND" "$ROOT/scripts/record-attestations.py" \
  --release-dir "$RELEASE_DIR" \
  --evidence-dir "$EVIDENCE_DIR" \
  --source-commit "$COMMIT" \
  --output "$RESULT" \
  --profile "$PROFILE"
