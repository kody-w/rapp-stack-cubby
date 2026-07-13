# Exact-commit promotion

One reviewed commit and its existing tag pass through candidate, public
postflight, private live proof, and final promotion. No phase creates a source
commit, moves a tag, or rebuilds/replaces a candidate asset.

## Phase A — protected candidate construction

Dispatch from the tag itself, never from `main` or a raw commit:

```sh
gh workflow run release.yml \
  --repo kody-w/rapp-stack-cubby \
  --ref "$RELEASE_TAG" \
  -f "tag=$RELEASE_TAG" \
  -f "commit=$RELEASE_COMMIT"
```

The workflow rejects execution unless `github.ref` is
`refs/tags/$RELEASE_TAG` and `github.sha` is `$RELEASE_COMMIT` before checkout
or source execution. Checkout uses that same commit, binding the OIDC
attestation source digest.

It builds twice, performs offline installed proof, scans exact source/history/
Pages/assets, signs `candidate-publication-scan.json`, and attests/uploads the
explicit candidate set to a draft, then publishes it once as the immutable
prerelease. Postflight reads all release metadata/assets, rejects
extras, verifies every byte, signature, checksum, source binding, and GitHub
attestation, then stores signed/attested `postflight-success.json` as exact
candidate Actions evidence. The immutable 11-asset release is never mutated. Any
failure marks the prerelease `FAILED POSTFLIGHT`; no Pages or promotion is
dispatched.

## Phase B — public postflight

The candidate workflow performs the complete initial and successful-candidate
postflight described above before any private operation. Candidate source and
core assets remain byte-identical; signed postflight evidence stays outside
the immutable release until verified Pages publishes it.

## Phase C — private live proof

Keep host paths, model credentials, account/chat/message identifiers, message
content, and raw GUIDs outside source and Actions. Produce only the canonical
`rapp-live-proof/1.0` receipt. It contains digest identities and booleans for
provider preflight, signed twin-chat, Full Disk Access, owner round trip,
outgoing GUID confirmation, restart, and sleep/wake. Sign it with the pinned
release key. Store its exact JSON/signature in the protected `promotion`
environment and retain its SHA-256 separately.

## Phase D — final promotion and released Pages

Dispatch the protected workflow from the same tag:

```sh
gh workflow run promote.yml \
  --repo kody-w/rapp-stack-cubby \
  --ref "$RELEASE_TAG" \
  -f "tag=$RELEASE_TAG" \
  -f "commit=$RELEASE_COMMIT" \
  -f "live_proof_sha256=$LIVE_PROOF_SHA256"
```

The workflow downloads the exact successful candidate, verifies postflight
and live proof, retrieves every completed exact-commit release workflow log,
builds candidate-state Pages without a source commit, and runs the final
publication scan over source/history/Pages/local downloads/public redownload/
Actions logs. It signs the final scan and promotion receipt, attests and
uploads the ten-file promotion evidence bundle as an attested Actions artifact,
reverifies all 11 immutable release assets, marks the immutable prerelease
`PROMOTED` through its editable title/notes, and dispatches
`pages.yml --ref "$TAG"`. Released Pages verifies and publishes
the sanitized receipts under its exact static inventory.

`STACK_LOCK.json` intentionally remains unresolved in source. The signed
external promotion receipt closes those final gates for that commit only;
`prepare-release final` verifies it rather than requiring a circular source
update.
