# Changelog

All notable product changes will be documented here. The repository is not yet
publicly released.

## 0.1.0rc2 — release candidate

### Fixed

- `0.1.0rc1` failed public CI because runner-only fixture assumptions used a
  host-specific Python path and shared `dist/` residue. `0.1.0rc2` makes those
  tests portable and isolated without changing product behavior.

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
