# Packaging and release

## Trust boundaries

`RELEASE_TRUST.json` is the only production release verifier. Development demo
trust is ephemeral, external, signed, and accepted only with the explicit
development hatch/adopt flags. No local command publishes, deploys Pages,
enrolls iMessage, or sends a message.

Dependency fetch is a separate, explicit network step:

```sh
PYTHON="<ABSOLUTE_PYTHON_311>" \
RAPP_DEPENDENCY_CACHE="<ABSOLUTE_EXTERNAL_CACHE>" \
  scripts/fetch-dependencies.sh
```

Every later build/hatch/demo command uses that verified cache offline.

For `WORKTREE` builds, the builder first validates the self-excluding source
manifest and copies only its recorded files, plus the manifest itself, through
hash-, size-, mode-, and no-follow-verified descriptors into a private source
snapshot outside the repository. Dependency and output staging, SBOM
generation, and release verification use that snapshot. A final path-by-path
manifest recheck catches live source movement without scanning generated
output, so a repository-root `dist/` build cannot become its own source.

## Repository protection setup

For a personal repository with one owner, configure release environments
without an impossible self-review gate:

```sh
scripts/configure-repository.sh \
  --repo OWNER/REPOSITORY \
  --sole-owner
```

Strict reviewer mode remains the default for repositories with another user
or team available:

```sh
scripts/configure-repository.sh \
  --repo OWNER/REPOSITORY \
  --reviewer-user-id USER_API_ID \
  --reviewer-team-id TEAM_API_ID
```

The modes are mutually exclusive. Both preserve required `verify` CI,
disabled branch force-push/deletion, the active no-bypass
`immutable-release-tags` deletion/update ruleset, and the `v*` tag-only
release/promotion environment policy. Environment calls use the versioned
GitHub REST API. The script enables and verifies immutable releases when that
endpoint is supported; only an endpoint 404 selects the exact tag-ruleset
proof. Other API errors fail.

The release job's limited `GITHUB_TOKEN` ruleset detail can omit the
administration-only `bypass_actors` field. In that fallback only, every
observable policy field remains exact; an absent or null `bypass_actors` and
an exact empty list are accepted, while any visible actor fails closed.
Omission is limited observability, not proof of an empty list. Run
`configure-repository.sh` with an owner token before dispatch and repeat its
owner-token verification after candidate postflight; the administrative
readback requires an explicit exact empty list and closes that observation
gap.

## Phase A — source commit, candidate build, offline proof

1. Regenerate catalogs, command manifest, context, Pages, provenance/locks,
   source manifest, and development artifacts twice.
2. Run doctor, context, Pages, full checks, and candidate preparation.
3. Build the exact clean commit twice with one epoch and protected signer.
4. Verify release, Store, egg, SPDX, provenance, indexes, signature, and
   checksums.
5. Hatch, verify installed bytes, adopt that install, start the explicit
   attestation child, call signed `SelfTest action=run` through the authenticated
   deterministic global `/chat`, stop, and prove no orphan.
6. Scan the exact candidate and sign its redacted receipt outside the source
   tree:

```sh
scripts/scan-publication.sh \
  --phase candidate \
  --pages "$REPOSITORY_ROOT/docs" \
  --release-assets "$BUILT_DIR" \
  --timestamp "$SCAN_TIMESTAMP" \
  --output "$EVIDENCE_DIR/candidate-publication-scan.json" \
  --signing-key "$RAPP_RELEASE_SIGNING_KEY" \
  --signing-trust "$REPOSITORY_ROOT/RELEASE_TRUST.json" \
  --signature-output "$EVIDENCE_DIR/candidate-publication-scan.json.sig"

scripts/verify-publication-scan.sh \
  --receipt "$EVIDENCE_DIR/candidate-publication-scan.json" \
  --phase candidate \
  --signature "$EVIDENCE_DIR/candidate-publication-scan.json.sig" \
  --trust "$REPOSITORY_ROOT/RELEASE_TRUST.json"
```

`candidate` requires a real commit and complete history. Copy both verified
files into the explicit prerelease asset inventory before candidate
preparation. `prepare-release.sh` requires their absolute paths through
`RAPP_PUBLICATION_SCAN_RECEIPT` and
`RAPP_PUBLICATION_SCAN_SIGNATURE`.

Development operators can prove the same product path without release
credentials:

```sh
scripts/demo-product.sh --python "$PYTHON_311" \
  --work-dir "$RAPP_WORK" \
  --dependency-cache "$RAPP_CACHE" \
  --install-dir "$RAPP_INSTALLS" \
  --controller-dir "$RAPP_CONTROLLER" \
  --receipt "$EXTERNAL_ROOT/demo-receipt.json" \
  --cleanup
```

Candidate preparation is exact:

```sh
scripts/prepare-release.sh "$RELEASE_TAG" "$RELEASE_COMMIT" candidate
```

The release workflow runs:

```sh
scripts/attest-installed-offline.sh \
  "$PYTHON_311" \
  "$INSTALLED_TWIN" \
  "$OFFLINE_CONTROLLER_ROOT" \
  "$OFFLINE_ATTESTATION_RECEIPT"
```

This proof has no model auth/network and does not weaken signed-only ingress.
Normal live start still requires an exact advertised model and successful
`provider-preflight`.

## Phase B — protected unchanged prerelease

The protected workflow rechecks the remote immutable tag immediately before
publication, attests the explicit nine files, and creates one prerelease from
the unchanged Phase-A commit. It then runs:

```sh
scripts/postflight-release.sh \
  "$RELEASE_TAG" \
  "$RELEASE_COMMIT" \
  "$BUILT_DIR" \
  "$DOWNLOAD_DIR" \
  "$EVIDENCE_DIR" \
  "$ATTESTATION_RESULT" \
  "$SUCCESS_RESULT"
```

Postflight publicly redownloads every immutable release asset, checks GitHub attestations, pinned
trust, source/tree/digest, canonical checksums, and local/public byte equality.
Its signed/attested receipt is candidate Actions evidence, not a later release
asset; immutable published releases are never appended to.
On any postflight failure the workflow edits an existing prerelease title to
`FAILED POSTFLIGHT` and explicitly says not to promote or deploy Pages.

After every job has completed, export the complete Actions log ZIPs and run
the second gate:

```sh
scripts/scan-publication.sh \
  --phase final \
  --pages "$DEPLOYED_PAGES_DIR" \
  --release-assets "$BUILT_DIR" \
  --public-redownload "$DOWNLOAD_DIR" \
  --actions-log "$ACTIONS_RUN_ID=$ACTIONS_LOG_ZIP" \
  --timestamp "$FINAL_SCAN_TIMESTAMP" \
  --output "$EVIDENCE_DIR/final-publication-scan.json" \
  --signing-key "$RAPP_RELEASE_SIGNING_KEY" \
  --signing-trust "$REPOSITORY_ROOT/RELEASE_TRUST.json" \
  --signature-output "$EVIDENCE_DIR/final-publication-scan.json.sig"
```

Repeat `--actions-log RUN_ID=ABSOLUTE_ZIP` for every run. The scanner never
fetches logs, release assets, private runtime roots, or owner configuration.

## Phase C — live private owner enrollment

Only after Phase B, on the declared supported host:

1. create/select the explicit external token file using
   `PROVIDER_AUTH.md`;
2. run installed `models --github-token-file
   "$RAPP_GITHUB_TOKEN_FILE" --json`;
3. run installed `provider-preflight --github-token-file
   "$RAPP_GITHUB_TOKEN_FILE" --model "$RAPP_MODEL"`;
4. start the same public installed twin with that exact model and token-file
   path;
5. auto-discover exactly one owner self-chat/account with `imessage init`;
6. prove Full Disk Access and signed tool readiness with
   `doctor --imessage`/`imessage preflight`;
7. grant Automation only to the exact process and perform one private owner
   message proof.

Private identifiers, message content, account ID, token bytes, paths, and
transport state never enter source, shell history literals, release notes,
Actions output, Pages, or public receipts.

## Phase D — released Pages and same-commit promotion

Dispatch `pages.yml` only with the same public tag, 40-hex commit, and recorded
release-manifest SHA-256 from Phase B. Verify the deployed
`pages-manifest.json`, then mark the same immutable prerelease `PROMOTED` in
its editable title/notes. Do not rebuild, replace assets, retag, or create a
source “hash commit.”

Final mode consumes the signed external promotion receipt while the committed
source lock intentionally remains unresolved. The source manifest remains
self-excluding and commit-free; release/evidence sidecars own exact commit and
artifact hashes.

## Failure and rollback

Before any deletion, stop and archive the returned controller instance. Then
remove the service, pinned tool, purge controller state, uninstall the
identity-bound installed twin, delete the candidate release **or** mark it
failed, and redeploy the previous trusted Pages artifact:

```sh
scripts/rollback-product.sh \
  --receipt "$PRIVATE_DEMO_OR_LIVE_ROLLBACK_RECEIPT" \
  --release-action mark-failed
```

The single `rapp-private-demo-live-receipt/1.0` file is outside source, is
mode `0600`, and owns the exact product/installed/controller identities,
paths, failed tag, and prior Pages tag/commit/manifest digest. The script
verifies the prior tag peel and dispatches Pages with `--ref "$PREVIOUS_TAG"`,
never the raw commit.

Its fail-closed sequence is equivalent to these exact interface calls (values
are extracted from the private receipt, not shell literals):

```sh
"$PYTHON_311" -m rapp_stack_cubby imessage service-uninstall \
  --config "$IMESSAGE_CONFIG" --plist "$SERVICE_PLIST" --stop
"$PYTHON_311" -m rapp_stack_cubby imessage install-tool \
  --install-root "$TOOLS_ROOT" --uninstall
"$PYTHON_311" -m rapp_stack_cubby uninstall-twin \
  --install-root "$INSTALLED_TWIN" --controller-root "$CONTROLLER_DATA" \
  --product-rappid "$PRODUCT_RAPPID" \
  --instance-rappid "$INSTALLED_INSTANCE_RAPPID" \
  --confirmation "$INSTALLED_INSTANCE_RAPPID"
gh release edit "$RELEASE_TAG" --prerelease \
  --title "FAILED POSTFLIGHT: RAPP Stack CUBBY $RELEASE_TAG"
# Or, only where immutable-release policy permits:
gh release delete "$RELEASE_TAG" --yes
gh workflow run pages.yml --ref "$PREVIOUS_TAG" \
  -f "release_stage=final" -f "release_tag=$PREVIOUS_TAG" \
  -f "release_commit=$PREVIOUS_COMMIT" \
  -f "release_manifest_sha256=$PREVIOUS_MANIFEST_SHA" \
  -f "promotion_receipt_sha256=$PREVIOUS_PROMOTION_SHA" \
  -f "promotion_run_id=$PREVIOUS_PROMOTION_RUN_ID"
```

Use `--release-action delete` only when policy allows deleting the release
object; the script never deletes the immutable tag. Confirm the Pages workflow
before closing rollback.
