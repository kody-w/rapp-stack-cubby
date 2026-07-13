# Security policy

## Current status

This repository is the complete local RAPP product but has no supported public
release or conformance claim. It contains the loopback runtime, guarded
controller, deterministic package chain, offline dependency fetch, hostile-ZIP
verification, and isolated hatcher. Do not treat unsigned development
artifacts, source catalogs, controller loadouts, or local hatch receipts as a
release.

Controller lifecycle mutations are disabled unless both an explicit private
data root and `RAPP_STACK_ALLOW_CONTROLLER_MUTATIONS=1` are present.
Production controller hatch verifies fetched `HEAD` against the requested
exact commit separately, then verifies the self-excluding
`rapp-release-source-manifest/1.0` and tree. The committed manifest cannot and
does not contain its own commit. Controller chat/self-test require durable action idempotency keys and use
paired ECDSA-P256 current-epoch, canonical, low-S signed requests and responses
through only `POST /chat`, with a phased claim/dispatch replay journal.
Controller-launched and adopted children are signed-only. A global
controller route requires an explicit mode-0600 32-byte token file, strict
constant-time bearer verification, and a fresh content-free HMAC endpoint
challenge before the bridge sends a bearer or owner content. Its deterministic
result proof binds the request, canonical controller result, exact child
response, signed status, instance RAPPID, and key epoch; a log marker alone is
never authority. The owner-only iMessage bridge source and pinned installer
are implemented, but repository checks never enroll an owner or send. Live
messaging remains unavailable until the exact public twin, private config,
macOS permissions, and host attestation exist. Packaging, isolated hatch,
static Pages checks, candidate/postflight scanning, and same-commit promotion
verification are available locally; no live Pages, publication, remote
setting, final signature, or public attestation is claimed.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting feature for this repository. Do
not include credentials, private keys, message content, transport identifiers,
local paths, or other private data in a public issue.

Public issues are appropriate for non-sensitive correctness problems.

## Repository boundary

Only public source, contracts, synthetic fixtures, and inert placeholders
belong in this repository. Never commit:

- secrets, credentials, private keys, tokens, or key-store references;
- real account, chat, transport, or phone identifiers;
- messages, memories, journals, databases, receipts, or installed twin state;
- local configuration, environment dumps, absolute workstation paths, or
  dependency caches; or
- generated release artifacts in source (verified local outputs belong only
  under ignored `dist/`).

Source contains no wheel or imsg archive. `fetch-dependencies` accepts only
lock URLs and an explicit cache outside the repository, verifies exact size
and SHA-256, and never executes downloads. Build consumes only that verified
cache. Egg hatch rejects traversal, duplicate names, links, special files,
unsafe modes/compression, bombs, undeclared members, and any hash/size/mode
mismatch before extraction. It invokes Python, pip, and the local imsg
installer with fixed argument arrays and no shell strings or network index.

Release signing accepts only an explicit external P-256 key. No release
private key is generated or stored by this repository. Unsigned output and
`WORKTREE` output are marked development-only.

The focused Security agent is a current-tree helper, not the future
publication scanner. Its deterministic iterative walk never follows symlinks
or opens nonregular entries and stops at hard limits: 2,048 encountered
entries, 256 directories, 500 files, 4 MiB total, 512 KiB per file, and depth
64. Rejected and special entries still consume the entry budget; responses
expose only paths, rule IDs, counters, and the limit reason.

Controller state belongs only under the explicit private controller root.
Directories are mode 0700 and state, locks, journals, sessions, logs, and
receipts are mode 0600. Receipts and logs must never contain credentials,
environment dumps, private paths, or message bodies.

iMessage raw handles, chat IDs, and account bindings may exist only in its
mode-0600 explicit config. Its mode-0700 state root contains a mode-0600 HMAC
secret and SQLite files; the database uses only keyed logical identifiers.
Bounded message/response content may exist only in that private database.
Operational logs, status, agent results, process arguments, and source are
content- and identifier-free. The internal `IMessage` agent receives only the
dedicated redacted status path, never raw bridge configuration. Unknown sends
are never automatically retried. Service uninstall preserves its plist unless
exact `launchctl bootout` succeeds; tool uninstall verifies exact evidence and
links before deletion and supports a no-delete dry run.

The local v1 key profile stores exact unencrypted P-256 PKCS#8
`BEGIN PRIVATE KEY` PEM only in
those explicit private roots (0600); public JWK files are 0644 beneath 0700
directories. Keychain is not required. Same-user process/private-root
compromise is out of scope. Private key, pairing, replay, nonce, and message
state must never enter source, tests, artifacts, SBOM inputs, or publication.
Synthetic fixtures contain public keys/signatures only and are labeled.

Release trust is separate: `RELEASE_TRUST.json` contains only the pinned public
P-256 JWK and key ID. The corresponding mode-0600 private key exists only
under an explicit private root outside this repository. Detached sidecars
cannot select a JWK; `verify-release` requires canonical low-S signatures,
exact checksums/assets, and the externally expected manifest digest.

The complete publication policy is in
`docs/PUBLIC_PRIVATE_BOUNDARY.md`. Pages has no backend, data-entry,
third-party executable dependency, browser persistence, service worker, or
local/private request. A verifier or Pages pass is a local integrity check,
not a live deployment or release security attestation.
