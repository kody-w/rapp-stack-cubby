#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
USAGE='usage: postflight-release.sh TAG COMMIT BUILT_DIR DOWNLOAD_DIR EVIDENCE_DIR ATTESTATION_RESULT SUCCESS_RESULT [candidate]'
TAG=${1:?$USAGE}
COMMIT=${2:?$USAGE}
BUILT_DIR=${3:?$USAGE}
DOWNLOAD_DIR=${4:?$USAGE}
EVIDENCE_DIR=${5:?$USAGE}
ATTESTATION_RESULT=${6:?$USAGE}
SUCCESS_RESULT=${7:?$USAGE}
PROFILE=${8:-candidate}
PYTHON_COMMAND=${PYTHON:-python3}
REPOSITORY=${GITHUB_REPOSITORY:-kody-w/rapp-stack-cubby}

case "$PROFILE" in
  candidate)
    EXPECTED_ASSETS='
SBOM.spdx.json
SHA256SUMS
candidate-publication-scan.json
candidate-publication-scan.json.sig
rapp-stack-cubby-store.zip
rapp-stack-cubby.egg
rapp-super-rar.json
release-manifest.json
release-manifest.json.sig
release-provenance.json
store-index.json'
    ATTESTATION_PROFILE=candidate
    ;;
  *) echo "error: invalid postflight profile" >&2; exit 2 ;;
esac

"$ROOT/scripts/validate-release-inputs.sh" "$TAG" "$COMMIT" >/dev/null
"$ROOT/scripts/resolve-release-tag.sh" "$TAG" "$COMMIT" >/dev/null
if [ ! -d "$BUILT_DIR" ] || [ -L "$BUILT_DIR" ] ||
   [ -e "$DOWNLOAD_DIR" ] || [ -L "$DOWNLOAD_DIR" ] ||
   [ -e "$EVIDENCE_DIR" ] || [ -L "$EVIDENCE_DIR" ] ||
   [ -e "$ATTESTATION_RESULT" ] || [ -L "$ATTESTATION_RESULT" ] ||
   [ -e "$SUCCESS_RESULT" ] || [ -L "$SUCCESS_RESULT" ]; then
  echo "error: postflight requires an existing build and fresh outputs" >&2
  exit 2
fi
mkdir -m 700 "$DOWNLOAD_DIR"
mkdir -m 700 "$EVIDENCE_DIR"

RELEASE_METADATA="$EVIDENCE_DIR/release-metadata.json"
gh api \
  -H "Accept: application/vnd.github+json" \
  "repos/$REPOSITORY/releases/tags/$TAG" >"$RELEASE_METADATA"

EXPECTED_FILE="$EVIDENCE_DIR/expected-assets.txt"
printf '%s\n' "$EXPECTED_ASSETS" | sed '/^$/d' | LC_ALL=C sort >"$EXPECTED_FILE"
"$PYTHON_COMMAND" - "$RELEASE_METADATA" "$EXPECTED_FILE" "$TAG" "$COMMIT" <<'PY'
import json
import pathlib
import sys

metadata_path, expected_path, tag, commit = sys.argv[1:]
value = json.loads(pathlib.Path(metadata_path).read_text(encoding="utf-8"))
expected = pathlib.Path(expected_path).read_text(encoding="utf-8").splitlines()
assets = value.get("assets")
observed = sorted(
    item.get("name")
    for item in assets
    if isinstance(item, dict) and isinstance(item.get("name"), str)
) if isinstance(assets, list) else []
title = value.get("name")
if (
    value.get("tag_name") != tag
    or value.get("target_commitish") != commit
    or value.get("draft") is not False
    or value.get("immutable") is not True
    or value.get("prerelease") is not True
    or not isinstance(title, str)
    or title.startswith("FAILED POSTFLIGHT")
    or observed != expected
    or len(observed) != len(set(observed))
):
    raise SystemExit("error: release metadata or exact remote inventory is invalid")
PY

gh release download "$TAG" \
  --repo "$REPOSITORY" \
  --dir "$DOWNLOAD_DIR"

"$PYTHON_COMMAND" - "$BUILT_DIR" "$DOWNLOAD_DIR" "$EXPECTED_FILE" <<'PY'
import pathlib
import sys

built = pathlib.Path(sys.argv[1])
download = pathlib.Path(sys.argv[2])
expected = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8").splitlines()
for root, label in ((built, "local"), (download, "public")):
    observed = sorted(item.name for item in root.iterdir())
    if observed != expected:
        raise SystemExit(f"error: {label} release directory is not the exact asset set")
    if any(not (root / name).is_file() or (root / name).is_symlink() for name in expected):
        raise SystemExit(f"error: {label} release asset is not a regular file")
for name in expected:
    if (built / name).read_bytes() != (download / name).read_bytes():
        raise SystemExit(f"error: postflight byte mismatch or missing asset: {name}")
PY

PYTHON="$PYTHON_COMMAND" "$ROOT/scripts/verify-publication-scan.sh" \
  --receipt "$DOWNLOAD_DIR/candidate-publication-scan.json" \
  --phase candidate \
  --signature "$DOWNLOAD_DIR/candidate-publication-scan.json.sig" \
  --trust "$ROOT/RELEASE_TRUST.json" \
  --source-commit "$COMMIT" >/dev/null

CORE_DIR="$EVIDENCE_DIR/core-assets"
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
  cp "$DOWNLOAD_DIR/$ASSET" "$CORE_DIR/$ASSET"
done

PYTHON="$PYTHON_COMMAND" "$ROOT/scripts/verify-github-attestations.sh" \
  "$DOWNLOAD_DIR" "$COMMIT" "$EVIDENCE_DIR/public-attestations" \
  "$ATTESTATION_RESULT" "$ATTESTATION_PROFILE"
PYTHON="$PYTHON_COMMAND" "$ROOT/scripts/verify-github-attestations.sh" \
  "$CORE_DIR" "$COMMIT" "$EVIDENCE_DIR/core-attestations" \
  "$EVIDENCE_DIR/core-attestation-result.json" core

MANIFEST_SHA=$(
  "$PYTHON_COMMAND" -c \
    'import hashlib,pathlib,sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' \
    "$CORE_DIR/release-manifest.json"
)
PYTHONPATH="$ROOT/src" "$PYTHON_COMMAND" -m rapp_stack_cubby verify-release \
  --release-manifest "$CORE_DIR/release-manifest.json" \
  --release-manifest-sha256 "$MANIFEST_SHA" \
  --trust "$ROOT/RELEASE_TRUST.json" \
  --signature "$CORE_DIR/release-manifest.json.sig" \
  --checksums "$CORE_DIR/SHA256SUMS" \
  --source-root "$ROOT" \
  --github-attestation "$EVIDENCE_DIR/core-attestation-result.json" >/dev/null

CANDIDATE_SCAN_SHA=$(
  "$PYTHON_COMMAND" -c \
    'import hashlib,pathlib,sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' \
    "$DOWNLOAD_DIR/candidate-publication-scan.json"
)
"$PYTHON_COMMAND" - \
  "$TAG" "$COMMIT" "$MANIFEST_SHA" "$CANDIDATE_SCAN_SHA" \
  "$EXPECTED_FILE" "$SUCCESS_RESULT" "$PROFILE" <<'PY'
import hashlib
import json
import pathlib
import sys

tag, commit, manifest_sha, scan_sha, inventory_path, output_name, profile = sys.argv[1:]
inventory = pathlib.Path(inventory_path).read_text(encoding="utf-8").splitlines()
if profile != "candidate":
    raise SystemExit("error: invalid immutable postflight profile")
value = {
    "asset_count": len(inventory),
    "bytes_equal": True,
    "candidate_publication_scan_sha256": scan_sha,
    "draft": False,
    "failed_postflight": False,
    "github_attestations_verified": True,
    "immutable": True,
    "prerelease": True,
    "release_manifest_sha256": manifest_sha,
    "remote_inventory": inventory,
    "remote_inventory_sha256": hashlib.sha256(
        (json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode()
    ).hexdigest(),
    "schema": "rapp-release-postflight/1.0",
    "source_commit": commit,
    "tag": tag,
    "verified": True,
}
output = pathlib.Path(output_name)
output.parent.mkdir(parents=True, exist_ok=True)
with output.open("x", encoding="utf-8") as destination:
    json.dump(value, destination, indent=2, sort_keys=True)
    destination.write("\n")
PY

"$ROOT/scripts/resolve-release-tag.sh" "$TAG" "$COMMIT" >/dev/null
printf 'PASS release postflight (%s): %s at %s\n' "$PROFILE" "$TAG" "$COMMIT"
