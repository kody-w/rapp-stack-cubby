# Release checklist

Candidate: `0.1.0rc6`
Expected tag: `v0.1.0-rc.6`
Current status: **unreleased**

## Phase A — source/CI candidate and offline product proof

- [ ] Select one clean reviewed 40-hex commit on protected `main`; require
      successful `CI / verify` and protected `release` approval.
- [ ] Confirm version/manifests/tag; peel the remote tag to the exact commit;
      require the release object absent.
- [ ] With an owner token, run repository configuration/readback and require
      the ruleset `bypass_actors` field to be present and exactly `[]`.
- [ ] Regenerate command manifest, catalogs, matrices, context, Pages,
      provenance, locks, source manifest, and development artifacts twice.
- [ ] Run offline `doctor`, context, Pages, and full checks.
- [ ] Candidate unresolved IDs are exactly `final-release-sha`,
      `live-enrollment-publication-proof`, `publication-scan`, and
      `public-end-to-end-attestation`.
- [ ] Build signed assets twice with one commit/epoch/cache/toolchain; compare
      every filename and byte.
- [ ] Verify release, Store, egg, SPDX, provenance, indexes, low-S signature,
      exact `SHA256SUMS`, and source bindings.
- [ ] Hatch offline and run `verify-install`.
- [ ] Run `scripts/attest-installed-offline.sh`; require installed-source
      digest equality, explicit host CPython for global control, static install
      verification plus isolated installed-Python launch probe, explicit
      attestation mode/model, signed-only installed-runtime child, signed
      global `/chat` SelfTest, stop, and `orphan_count:0`.
- [ ] Run `scripts/scan-publication.sh --phase candidate` over the exact
      source/history, generated Pages, and release assets. Require zero
      findings; detached-sign and verify
      `candidate-publication-scan.json` and its `.sig`.
- [ ] Run `scripts/prepare-release.sh <TAG> <COMMIT> candidate` with those
      exact signed scanner paths; require policy/trust/source binding.

## Phase B — unchanged protected prerelease

- [ ] Recheck the immutable remote tag immediately before creation.
- [ ] Attest and upload the explicit build inventory plus the signed candidate
      publication receipt to a draft, then publish it once as the immutable
      prerelease.
- [ ] Redownload into a fresh directory.
- [ ] Run `gh attestation verify` for every file with exact repository,
      signer workflow, and source digest.
- [ ] Run `scripts/postflight-release.sh`; require public/local byte equality
      and a signed/attested `postflight-success.json` Actions artifact; keep
      the immutable 11-asset release exact and reject every extra or omission.
- [ ] Repeat owner-token repository readback after candidate postflight;
      require explicit exact `bypass_actors: []` to close the workflow
      token's limited ruleset-detail observability.
- [ ] On any postflight failure, mark the existing prerelease
      `FAILED POSTFLIGHT`; do not dispatch Pages.

## Phase C — same-public-commit live private gate

- [ ] Select the explicit external token file per `PROVIDER_AUTH.md`; run
      installed `models` and exact `provider-preflight` with
      `--github-token-file`.
- [ ] Start the same public installed twin with that exact model and external
      token-file path; no path/token may enter a receipt.
- [ ] Auto-discover exactly one owner self-chat/account; do not type private
      identifiers as command literals.
- [ ] Prove pinned tool, Full Disk Access, Automation, one private owner
      message, restart, and sleep/wake.
- [ ] Retain only sanitized content-free evidence. Never publish message,
      account/chat IDs, token, path, key, pairing, or private RAPPID.

## Phase D — same-commit promotion and released Pages

- [ ] Export complete logs for every finished Actions run and produce/verify
      signed zero-finding `final-publication-scan.json` over candidate Pages,
      public redownload, and every log archive.
- [ ] Verify the signed live proof and create/sign the same-commit promotion
      receipt. The source lock remains unresolved; this external receipt closes
      it without a source commit.
- [ ] Mark the same immutable prerelease `PROMOTED` in title/notes; do not
      retag, rebuild, replace assets, toggle immutable fields, or create a
      source hash commit.
- [ ] Dispatch `pages.yml --ref <TAG>` only with the same tag, exact commit,
      release-manifest SHA-256, promotion-receipt SHA-256, and completed
      promotion run ID.
- [ ] Verify deployed `pages-manifest.json`, all 11 immutable release assets,
      and every published scanner/postflight/live/promotion receipt.

## Rollback

- [ ] Run exact controller stop/archive, service uninstall, tool uninstall,
      controller purge, and identity-bound `uninstall-twin`.
- [ ] Delete the release object or explicitly mark it failed; never delete or
      move the immutable tag.
- [ ] Redeploy the previous trusted Pages tag/commit/manifest digest.
- [ ] Use `scripts/rollback-product.sh --receipt <MODE_0600_PRIVATE_RECEIPT>`
      and verify the resulting Pages
      workflow before closing the incident.

Public verifier: [`RELEASE_TRUST.json`](RELEASE_TRUST.json), key ID
`0d7fb1acf871d707bf24b3c298d0f47b1f39f0084e3212ed54c7f0b0abf98b07`.
