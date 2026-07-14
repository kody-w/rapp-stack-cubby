# Changelog

All notable product changes will be documented here. The repository is not yet
publicly released.

## 0.1.0rc12 — release candidate

### Fixed

- Pre-tag pull-request run `29304286160` was safely blocked by the full signed
  development demo after source, build, signed development release, egg,
  hatch, and install proof passed and lifecycle reached the child readiness
  window. Demo and installed-attestation diagnostics now preserve only a
  bounded health-attempt count and finite last-result category, including
  when failed child cleanup leaves the guarded process in `starting`.
- Protected release run `29300424649` exhausted the full 75-second installed
  child health window while the persisted child remained alive with empty
  stderr. Its 23-byte stdout SHA-256
  `44667ccbb99a366dd6308b6751b1396cd64d5fe27c7c57bbc7d54aeebaf81a5a`
  binds exactly to the loopback URL emitted only after startup, import, origin,
  and bind validation. Child `/health` probes now receive up to 15 seconds
  each, capped by the remaining unchanged 75-second total budget.
- The development demo now drives its installed lifecycle controller through
  the validated setup Python and installed source/site-packages bootstrap used
  by protected release while retaining installed-Python static verification
  and the isolated launch probe. Normal macOS pull-request/main CI runs this
  full signed development hatch, adopted signed-only SelfTest, lifecycle, and
  cleanup gate from runner-temporary paths before candidate tagging.
- Content-free installed-attestation failures now report finite controller
  client category and return-code fields independently from global controller
  process status.

## 0.1.0rc11 — release candidate

### Fixed

- Release run `29296311089` reached adopted child startup with empty logs and
  persisted `starting` process state carrying the 75-second health budget, but
  the lifecycle controller client still used its 30-second default timeout.
  Every installed lifecycle controller action, including rollback stop, now
  uses an explicit 90-second timeout below the 180-second subprocess bound.
  Controller rejections now expose only a finite allowlisted error code, with
  all unknown values mapped to `unclassified`.

## 0.1.0rc10 — release candidate

### Fixed

- Release run `29292402986` adopted the verified install but reported child
  process `not_started` because startup probed the copied runner Python before
  selecting the stored attestation host Python. Offline self-test start now
  verifies the install manifest, runtime digest, and installed Python static
  inventory, hash, and mode before validating and selecting the stored host
  Python without probing the copied executable. Normal/live start still
  validates and executes the installed Python.

## 0.1.0rc9 — release candidate

### Fixed

- Release run `29287233724` reached a ready global controller, adopted the
  verified installed bytes, and launched a child with empty stdout/stderr, but
  the controller's hardcoded 12-second health timeout expired at child start.
  Child readiness now uses the named 75-second cold-runner budget already
  proven by installed attestation, with bounded process-aware polling and fast
  process-exit and identity-mismatch failure. Content-free controller status,
  start receipts, and child-start diagnostics report the applied timeout.

## 0.1.0rc8 — release candidate

### Fixed

- Release run `29280172743` reached a ready global controller and adopted the
  verified install, but its signed-only child could not start from GitHub's
  copied framework-venv Python; the exact artifact continued to attest
  locally. Offline installed attestation now binds an explicit, matching host
  CPython 3.11 only in `offline-self-test` mode, launches it with isolated
  verified installed source and dependency paths, and proves dependency
  origins before readiness. Installed runtime measurements remain distinct
  and authoritative for normal/live starts. Child-start failures expose only
  process status and stdout/stderr size/digests.

## 0.1.0rc7 — release candidate

### Fixed

- Release run `29275520997` failed installed offline attestation while the
  global controller remained running with an empty log beyond the fixed
  15-second readiness window; the exact artifact attests locally. Controller
  startup now uses a named 75-second cold-runner budget with efficient,
  process-aware polling and fast exit detection. Attestation controller and
  child diagnostics are unbuffered, while timeout evidence remains
  content-free and limited to log size/digest and process return category.

## 0.1.0rc6 — release candidate

### Fixed

- Release run `29268450887` passed build, signature verification, and hatch,
  but the global controller did not become ready when launched from GitHub's
  copied setup-python venv. Installed attestation now runs global
  controller/auth/CLI operations with the explicit trusted host CPython 3.11
  while retaining the verified installed source as `PYTHONPATH` and product
  root. Pre-adoption remains static except for one bounded, content-free
  `-I -S` installed-Python launch probe; the signed-only child still starts
  from the measured installed venv/source and exercises its dependencies.
  Failure receipts and workflow output expose only allowlisted stage/process
  categories, controller-log size/digest, and child stage.

## 0.1.0rc5 — release candidate

### Fixed

- Release run `29265827544` showed that an Actions `GITHUB_TOKEN` ruleset
  detail can omit the administration-only `bypass_actors` field even though
  owner-token readback proves the active ruleset has an exact empty list. The
  release-only fallback now accepts only absent/null or exact empty actors,
  rejects every visible actor, and keeps all observable rule and condition
  checks exact; owner configuration and postflight readback still require
  explicit `[]`. Product behavior is unchanged.

## 0.1.0rc4 — release candidate

### Fixed

- Release run `29261541865` exposed that the immutable-releases endpoint is
  unavailable on this personal public repository. Release authorization now
  falls back only on endpoint 404 and proves the exact active, no-bypass
  deletion/update tag ruleset; all other API errors still fail closed.
- Repository setup now uses versioned environment APIs and supports an
  explicit sole-owner mode without an impossible self-review requirement,
  while retaining strict reviewer mode and all CI, branch, tag, and
  environment-tag protections. Product behavior is unchanged.

## 0.1.0rc3 — release candidate

### Fixed

- `0.1.0rc2` public `main` CI exposed two public GitHub merge identities
  inserted by the protected squash merge commit. `0.1.0rc3` narrowly allows
  only their exact hashes in publication scans; product behavior is unchanged.

### Added

- Complete dependency-free static Pages front door and deterministic API v1.
- Generated source metrics, architecture, capability, context, downloads, and
  ten-prompt catalogs.
- Fail-closed Pages, privacy, accessibility, project-path, workflow, and
  release-truth checks.
- Immutable-SHA CI, Pages, and exact-commit release-preparation workflows.
- Separate macOS arm64 CI dependency lock and official-action provenance lock.
- Candidate version, checklist, promotion runbook, and repository settings
  guidance.
- Authenticated candidate-only census refresh, sanitized 307-repository
  bounded-window snapshot at existence cutoff
  `2026-07-13T08:57:20.399000Z`, per-request timing/ETags/digests, exact raw
  cross-binding, eight full-record local shards, twelve completed drift
  reviews, separate post-window movement, and deterministic graph generator.
- Explicit network-free AttestationProvider, signed installed-byte SelfTest
  proof, fresh doctor/bootstrap, one-command product demo, generated command
  manifest/tutorial validation, complete rollback, and content-free receipts.
- Exact-tag candidate attestation binding, signed candidate scanner and
  postflight assets, all-asset remote inventory verification, protected final
  promotion/live-proof/log scanning, and receipt-gated released Pages.
- Idempotent, read-back-verified repository settings automation for Pages,
  protected main/tags/releases, and reviewed release/promotion environments.
- Explicit private Copilot token-file schema, bounded GitHub device
  login/refresh, exact-model status-aware preflight, controller child
  propagation, and content-free this-host live tool-loop proof.

### Changed

- Removed retired model fallbacks; runtime startup now requires an explicit
  live-preflighted chat-completions model.
- Added explicit dedicated-process agent context, strict production agent ABI,
  canonical generated agents, cross-process Memory/AgentFactory transactions,
  bounded HTTP parsing, UTF-8 response safety, and terminal signed-response
  recovery.
- Corrected TwinChat capability ownership and bounded Security traversal.
- Hardened signed-only child chat with exact canonical low-S epoch-bound wire
  verification, crash-phased replay recovery, and durable controller request
  idempotency across timeouts and restarts.
- Replaced ambient setup assumptions with an external Python 3.11 venv and
  exact hash-locked dependency installation.
- Corrected the runtime model to original clean-room implementation with
  Microsoft reference-only, separated the non-antecedent local product node,
  enriched all 61 selected capability routes, and future-owned the unbuilt
  full publication scanner.
- Synchronized context claims with the repaired SPDX root/file/dependency
  closure, with all six OpenRappter adaptations mapped in provenance, SBOM
  inputs, generated file comments, and NOTICE.
- Switched the official macOS 15 ARM64 runner label to `macos-15`, removed the
  invalid setup-python cache boolean, hardened static markup parsing, and made
  rollback consume one private mode-0600 identity receipt.

### Release status

Unreleased. Offline end-to-end local attestation and this-host live Copilot
provider proof are implemented. Exact-public-product provider repetition,
iMessage proof, final public redownload, and released Pages remain blocked.
