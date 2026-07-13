# Pages operations

## Local pending build

The committed source status is intentionally pending:

```sh
PYTHON=/absolute/python3.11 scripts/pages-build.sh
PYTHON=/absolute/python3.11 scripts/pages-check.sh
```

The build deterministically updates six `docs/api/v1/*.json` documents, every
marked release-state block in `docs/index.html`, and
`docs/pages-manifest.json`. The manifest is the exact file/hash/size/kind
inventory; its own digest is calculated with its self-record digest zeroed. It
does not fetch, publish, or start a server.

## Checked deployment

`.github/workflows/pages.yml` repeats context, full, build, and Pages checks,
then archives and checks the exact inventory before uploading only `docs/`.
`include-hidden-files: true` preserves `.nojekyll`. The deploy job uses the
`github-pages` environment. All official actions are pinned to exact commits
in `../../GITHUB_ACTIONS_LOCK.json`.

Before the first final release, an automatic `main` push may publish the
truthful pending site. Once a non-draft, non-prerelease release exists, `main`
pushes preserve the deployed released site and require exact-tag promotion;
they never downgrade it to pending.

A manual final deployment supplies the exact tag, peeled 40-hex commit,
release-manifest SHA-256, and promotion-receipt SHA-256 and runs from
`--ref "$TAG"`. It rejects any ref/SHA mismatch, failed-postflight title,
non-immutable release, draft/unpromoted state, extra/missing asset, or
target-commit mismatch. It
downloads all remote assets and runs `gh attestation verify` for each with the
exact release signer workflow and source digest. It retrieves the exact
completed promotion Actions artifact, verifies its release/postflight/promotion
attestations, and publishes the sanitized receipt bytes under `docs/evidence/`.
`pages-build --final` then verifies:

- the external manifest digest and detached signature;
- the checked-in [`RELEASE_TRUST.json`](../../RELEASE_TRUST.json);
- canonical `SHA256SUMS` and every declared downloaded asset;
- the exact checkout HEAD, Git tree, and source-tree digest; and
- core and complete mixed-workflow GitHub attestation results;
- signed candidate scanner and successful postflight receipts; and
- signed live proof, final scanner, and same-commit promotion receipts.

Only that verifier capability can enable released prose and download links.
The public key ID is
`0d7fb1acf871d707bf24b3c298d0f47b1f39f0084e3212ed54c7f0b0abf98b07`;
no signer secret is part of Pages.

## Failure and rollback

Every HTML, SVG, CSS, JSON, XML, JavaScript, manifest, and robots file is
structurally checked. XML/SVG processing instructions and doctypes, malformed
markup, duplicate HTML attributes, and noncanonical sitemap bytes are rejected.
Exact inventory drift, an unexpected hidden file, active
content, forms, browser storage, service workers, loopback URLs, external
executable resources, CSS imports/remote URLs, SVG scripts/references, stale
release wording, workflow drift, or size violations block deployment. The 404
page uses `/rapp-stack-cubby/`-absolute assets and links so nested missing paths
remain usable. Do not bypass the checker. Follow
[`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md) if suspect bytes reached a
public surface.
