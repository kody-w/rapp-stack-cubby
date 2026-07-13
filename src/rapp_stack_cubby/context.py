"""Build and validate the repository-local RAPP context closure."""

from __future__ import annotations

import argparse
import ast
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .constants import CONTEXT_INDEX_SCHEMA
from .errors import RappStackCubbyError

CONTEXT_INDEX_RELATIVE: Final = Path("CONTEXT_INDEX.json")
CONTEXT_SCHEMA_RELATIVE: Final = Path("schemas/context-index.schema.json")
IMPLEMENTATION_MATRIX_RELATIVE: Final = Path(
    "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/"
    "implementation-matrix.json"
)
CAPABILITY_MATRIX_RELATIVE: Final = Path("CAPABILITY_MATRIX.json")
DRAFT_2020_12: Final = "https://json-schema.org/draft/2020-12/schema"

CANONICAL_PROFILES: Final = {
    "AGENT_ABI.md": "Exact synchronous actual-agent ABI, discovery, and packaging identity.",
    "ARTIFACT_CHAIN.md": "Exact source-to-installed-twin artifact profile.",
    "CHAT_WIRE.md": "Implemented single local capability wire.",
    "CLOUD_ENTERPRISE.md": "Mapped cloud and enterprise progression boundary.",
    "FLEET_AND_LEVIATHAN.md": "Mapped fleet and wrapped-organism distinction.",
    "GAP_REGISTER.md": "Owned release gaps and completion evidence.",
    "GLOSSARY.md": "Narrow meanings for overloaded RAPP terms.",
    "IDENTITY_AND_TRUST.md": "Selected RAPPID, key, and authorization model.",
    "IMPLEMENTATION_STATUS.md": "Current implementation truth by system area.",
    "MESSAGING_IMESSAGE.md": "Owner-only iMessage edge profile.",
    "NEIGHBORHOOD_ESTATE_METROPOLIS.md": (
        "Mapped neighborhood and discovery hierarchy."
    ),
    "ROADMAP.md": "Dependency-ordered end-to-end delivery sequence.",
    "SECURITY_AND_RELEASE.md": "Security, privacy, and release-gate profile.",
    "SYSTEM_MODEL.md": "Selected end-to-end architecture and boundaries.",
    "SHOWCASE_PROMPTS.md": "Exact ten-prompt static product showcase.",
    "TWIN_CHAT.md": "Implemented signed replay-safe local twin transport.",
    "TWIN_LIFECYCLE.md": "Controller/isolated-child lifecycle profile.",
}

DECISIONS: Final = {
    "actual-agents-not-skills.md": "Keep executable child capabilities as agents.",
    "artifact-chain.md": "Select one non-substitutable artifact chain.",
    "clean-room-runtime.md": "Keep runtime implementation newly authored.",
    "direct-evidence-over-indexes.md": "Resolve claims from direct evidence.",
    "exact-commit-release.md": "Bind every release surface to one commit.",
    "explicit-copilot-token-file.md": (
        "Use explicit private OAuth files and exact live model preflight."
    ),
    "file-backed-transport-keys.md": (
        "Use private file-backed P-256 transport keys for local v1."
    ),
    "grail-pointer-not-source.md": "Separate behavioral pointer from source rights.",
    "isolated-controller-child.md": "Separate controller and child authority/state.",
    "one-capability-wire.md": "Use one local capability endpoint.",
    "one-repo-context.md": "Make this repository sufficient working context.",
    "one-repo-product.md": "Make this repository the complete RAPP product.",
    "owner-only-imessage-v1.md": "Narrow messaging to one owner direct chat.",
    "public-private-boundary.md": "Default deny every publication surface.",
    "signed-twin-chat.md": "Require signed replay-safe twin request/response.",
    "static-pages-public-boundary.md": (
        "Keep Pages static, dependency-free, private-state-free, and unreleased."
    ),
}

RUNBOOKS: Final = {
    "CONTEXT_MAINTENANCE.md": "Regenerate and review local context safely.",
    "CONTROLLER_LOADOUT.md": "Build and operate the controller-only loadout.",
    "DEVELOPER_SETUP.md": "Prepare the locked Python 3.11 workspace.",
    "DEPENDENCY_FETCH_AND_VENDOR.md": "Fetch and verify inert locked archives.",
    "HANDOFF.md": "Operate and evolve RAPP end to end from this repository.",
    "IMESSAGE_ONBOARDING.md": (
        "Fresh-fork owner-only iMessage installation and operations."
    ),
    "INCIDENT_RESPONSE.md": "Contain, revoke, repair, and verify an exposure.",
    "ISOLATED_HATCH.md": "Verify, hatch, inspect, and remove an installed twin.",
    "LOCAL_LIFECYCLE.md": "Hatch and supervise a local isolated child.",
    "PACKAGING_AND_RELEASE.md": "Build locally and close future release gates.",
    "REPOSITORY_VERIFICATION.md": "Run and interpret local verification gates.",
    "TEST_STRATEGY.md": "Select deterministic test families and escalation.",
    "TWIN_CHAT_OPERATIONS.md": "Pair, rotate, and recover signed twin chat.",
    "EXACT_COMMIT_PROMOTION.md": "Promote one clean exact commit without self-reference.",
    "PAGES_OPERATIONS.md": "Build, check, and deploy the static handoff safely.",
    "PROVIDER_AUTH.md": (
        "Create, select, preflight, and protect live provider authentication."
    ),
    "REPOSITORY_SETTINGS.md": "Guide unapplied branch, Pages, and environment settings.",
}

SCHEMAS: Final = {
    "agent-manifest.schema.json": "Native rapp-agent/1.0 manifest.",
    "brainstem-chat-request.schema.json": "Implemented local chat request.",
    "brainstem-chat-response.schema.json": "Implemented local chat response.",
    "capability-matrix.schema.json": "Direct-evidence capability matrix.",
    "commons-signed-wrapper.schema.json": (
        "Canonical low-S signed Commons twin wrapper."
    ),
    "context-index.schema.json": "Machine-readable local context closure.",
    "controller-action.schema.json": "Exact deterministic controller route action.",
    "controller-journal.schema.json": (
        "Private lifecycle and signed outbound transition journal."
    ),
    "controller-loadout.schema.json": "Controller-only external loadout.",
    "controller-receipt.schema.json": "Private lifecycle receipt.",
    "controller-result-proof.schema.json": "Content-free controller result proof.",
    "controller-state.schema.json": "Private isolated-child controller state.",
    "controller-tombstone.schema.json": "Permanent purge tombstone.",
    "command-manifest.schema.json": "Generated argparse command and flag surface.",
    "copilot-token.schema.json": "Private versioned Copilot-compatible OAuth file.",
    "cubby.schema.json": "Public narrowed cubby shelf manifest.",
    "imessage-local-config.schema.json": "Implemented private owner iMessage config.",
    "imessage-status.schema.json": "Content-free private bridge heartbeat.",
    "implementation-matrix.schema.json": "Generated implementation ownership.",
    "installed-twin.schema.json": "Verified isolated installed-twin manifest.",
    "local-agent-catalog.schema.json": "Generated actual-agent catalog.",
    "live-provider-status.schema.json": (
        "Content-free this-host provider completion/tool-loop proof."
    ),
    "rapplication.schema.json": "Complete deterministic rapplication artifact.",
    "source-census.schema.json": "Direct public repository census.",
    "source-release-manifest.schema.json": "Exact release source manifest.",
    "source-tree.schema.json": "Deterministic scanned source tree.",
    "system-graph.schema.json": "Normalized evidence system graph.",
    "twin-chat-pairing.schema.json": (
        "Private monotonic-epoch controller-child key pairing."
    ),
    "twin-chat-request.schema.json": (
        "Implemented canonical epoch-bound twin-chat request."
    ),
    "twin-chat-signed-response.schema.json": (
        "Implemented canonical nonce/digest/epoch-bound twin response."
    ),
    "brainstem-egg.schema.json": "Verified offline cubby egg artifact.",
    "birth.schema.json": "Stable synthetic public product birth.",
    "detached-signature.schema.json": "Pinned low-S P-256 release signature.",
    "evidence-signature.schema.json": "Pinned signature for external release evidence.",
    "hatch-receipt.schema.json": "Content-free isolated hatch receipt.",
    "rappid.schema.json": "Canonical stable public product RAPPID.",
    "release-manifest.schema.json": "External revision/artifact sidecar binding.",
    "release-provenance.schema.json": "Deterministic build material provenance.",
    "release-trust.schema.json": "Pinned public P-256 release trust anchor.",
    "store-index.schema.json": "Local deterministic Store intake index.",
    "super-rar.schema.json": "SHA-deduplicated source and artifact index.",
    "github-actions-lock.schema.json": "Immutable official Actions and runner lock.",
    "github-attestation-result.schema.json": (
        "Sanitized exact gh attestation verification evidence."
    ),
    "publication-attestation-result.schema.json": (
        "Mixed release/promotion workflow attestation evidence."
    ),
    "live-proof.schema.json": "Sanitized live host and iMessage proof.",
    "pages-api.schema.json": "Six deterministic public static API profiles.",
    "pages-manifest.schema.json": "Exact deployable static Pages inventory.",
    "publication-scan-policy.schema.json": "Fail-closed public scan rules and allowlist.",
    "publication-scan-receipt.schema.json": "Redacted deterministic publication gate receipt.",
    "publication-scan-signature.schema.json": "Pinned detached scan-receipt signature.",
    "release-postflight.schema.json": "Public release byte/attestation postflight.",
    "promotion-receipt.schema.json": "Signed same-commit final promotion closure.",
    "rollback-receipt.schema.json": "Private mode-0600 operational rollback input.",
    "release-status.schema.json": "Explicit current-source unreleased truth.",
    "demo-receipt.schema.json": "Content-free local development journey proof.",
    "installed-offline-attestation.schema.json": (
        "Signed installed-byte offline SelfTest proof."
    ),
    "uninstall-journal.schema.json": "Content-free installed-twin removal journal.",
}

FUTURE_OWNERS: Final = {
    "release-attestation": "Publish and verify the exact final release commit.",
}

_STATUS_VALUES = frozenset(
    {
        "authoritative_profile",
        "tested_implementation",
        "direct_evidence",
        "generated_index",
        "decision",
        "runbook",
        "historical_context",
        "future_owned",
    }
)
_LOCAL_PATH_RE = re.compile(
    r"(?:/(?:Users|home)/[^/\s]+/|[A-Za-z]:\\Users\\[^\\\s]+\\)"
)
_EXTERNAL_LINK_RE = re.compile(r"https?://", re.IGNORECASE)
_MARKDOWN_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
_PHONE_RE = re.compile(r"(?<![0-9])(?:\+?1[-. ]?)?\(?[2-9][0-9]{2}\)?"
                       r"[-. ][2-9][0-9]{2}[-. ][0-9]{4}(?![0-9])")
_SECRET_VALUE_RE = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?i:authorization:\s*bearer\s+[A-Za-z0-9._-]{12,}))"
)
_PRIVATE_IDENTIFIER_RE = re.compile(
    r"(?:\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\b|"
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|"
    r"\biMessage;[-+];[^\s\"']+)",
    re.IGNORECASE,
)
_JSON_MESSAGE_VALUE_RE = re.compile(
    r'"(?:content|message|response|user_input)"\s*:\s*"([^"]+)"'
)


class ContextValidationError(RappStackCubbyError, ValueError):
    """Raised when local context cannot be read or validated."""


class _DuplicateKeyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ContextValidationResult:
    """Structured context validation outcome."""

    errors: tuple[str, ...]
    entry_count: int
    schema_count: int
    capability_count: int

    @property
    def ok(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "entry_count": self.entry_count,
            "schema_count": self.schema_count,
            "selected_capability_count": self.capability_count,
            "error_count": len(self.errors),
            "errors": list(self.errors),
        }


def _slug(name: str) -> str:
    return name.lower().removesuffix(".md").removesuffix(".schema.json").replace(
        "_", "-"
    )


def _entry(
    identifier: str,
    kind: str,
    path: str,
    role: str,
    status: str,
    *,
    prerequisites: Sequence[str] = (),
    read_after: Sequence[str] | None = None,
    implemented_by: Sequence[str] = (),
    verified_by: Sequence[str] = ("test.context",),
) -> dict[str, Any]:
    return {
        "id": identifier,
        "implemented_by": sorted(implemented_by),
        "kind": kind,
        "path": path,
        "prerequisites": sorted(prerequisites),
        "read_after": sorted(prerequisites if read_after is None else read_after),
        "role": role,
        "status": status,
        "verified_by": sorted(verified_by),
    }


def _base_entries() -> list[dict[str, Any]]:
    entries = [
        _entry(
            "entry.ai-context",
            "document",
            "AI_CONTEXT.md",
            "Mandatory local entrypoint, authority, routing, and reading order.",
            "authoritative_profile",
            verified_by=("test.context",),
        ),
        _entry(
            "document.changelog",
            "document",
            "CHANGELOG.md",
            "Candidate changes and explicit unreleased status.",
            "authoritative_profile",
            prerequisites=("canon.implementation-status",),
        ),
        _entry(
            "document.conformance",
            "document",
            "CONFORMANCE.md",
            "Original narrowed target and release gates retained for history.",
            "historical_context",
            prerequisites=("entry.ai-context",),
        ),
        _entry(
            "document.release-checklist",
            "document",
            "RELEASE_CHECKLIST.md",
            "Exact candidate verification, private proof, and publication checklist.",
            "authoritative_profile",
            prerequisites=("runbook.exact-commit-promotion",),
        ),
        _entry(
            "document.controller-location",
            "document",
            "cubbies/kody-w/agents/README.md",
            "Explains why exactly one controller occupies the streamable directory.",
            "authoritative_profile",
            prerequisites=("canon.twin-lifecycle",),
        ),
        _entry(
            "evidence.github-actions-lock",
            "evidence",
            "GITHUB_ACTIONS_LOCK.json",
            "Directly resolved immutable official Action tags and runner profile.",
            "direct_evidence",
            prerequisites=("canon.security-and-release",),
            verified_by=("test.pages", "test.all"),
        ),
        _entry(
            "document.contributing",
            "document",
            "CONTRIBUTING.md",
            "Contribution and local-context maintenance rules.",
            "authoritative_profile",
            prerequisites=("entry.ai-context",),
        ),
        _entry(
            "implementation.pages",
            "implementation",
            "src/rapp_stack_cubby/pages.py",
            "Deterministic static API generator and fail-closed deployment checker.",
            "tested_implementation",
            prerequisites=("decision.static-pages-public-boundary",),
            verified_by=("test.pages", "test.all"),
        ),
        _entry(
            "document.license",
            "document",
            "LICENSE",
            "License for newly authored project material.",
            "authoritative_profile",
            prerequisites=("entry.ai-context",),
        ),
        _entry(
            "implementation.pages-site",
            "implementation",
            "docs/index.html",
            "Accessible dependency-free static public product handoff.",
            "tested_implementation",
            prerequisites=("implementation.pages",),
            verified_by=("test.pages",),
        ),
        _entry(
            "document.notice",
            "document",
            "NOTICE",
            "Original-work and external-reference notices.",
            "authoritative_profile",
            prerequisites=("evidence.provenance",),
        ),
        _entry(
            "implementation.workflows",
            "implementation",
            ".github/workflows",
            "Immutable-action CI, Pages, and exact-commit release preparation.",
            "tested_implementation",
            prerequisites=("evidence.github-actions-lock",),
            verified_by=("test.pages",),
        ),
        _entry(
            "document.public-private-boundary",
            "document",
            "docs/PUBLIC_PRIVATE_BOUNDARY.md",
            "Default-deny publication and private-state policy.",
            "authoritative_profile",
            prerequisites=("canon.security-and-release",),
        ),
        _entry(
            "manifest.publication-scan-policy",
            "manifest",
            "PUBLICATION_SCAN_POLICY.json",
            "Fail-closed scanner limits, rules, and exact reviewed allowlist.",
            "authoritative_profile",
            prerequisites=("document.public-private-boundary",),
            verified_by=("test.packaging",),
        ),
        _entry(
            "implementation.publication-scanner",
            "implementation",
            "src/rapp_stack_cubby/packaging/publication.py",
            "Static full-history/archive/Pages/release/Actions publication scanner.",
            "tested_implementation",
            prerequisites=("manifest.publication-scan-policy",),
            verified_by=("test.packaging",),
        ),
        _entry(
            "manifest.live-provider-status",
            "manifest",
            "LIVE_PROVIDER_STATUS.json",
            (
                "Content-free this-host exact-model completion/tool-loop "
                "proof; not a public-product attestation."
            ),
            "tested_implementation",
            prerequisites=("implementation.runtime",),
            verified_by=("test.runtime", "test.packaging"),
        ),
        _entry(
            "manifest.release-status",
            "manifest",
            "RELEASE_STATUS.json",
            "Explicit candidate pending truth; released state requires external sidecars.",
            "authoritative_profile",
            prerequisites=("decision.static-pages-public-boundary",),
            verified_by=("test.pages",),
        ),
        _entry(
            "manifest.release-trust",
            "manifest",
            "RELEASE_TRUST.json",
            "Sole checked-in public signer key ID and P-256 JWK.",
            "authoritative_profile",
            prerequisites=("canon.security-and-release",),
            verified_by=("test.packaging", "test.pages"),
        ),
        _entry(
            "manifest.pages-inventory",
            "manifest",
            "docs/pages-manifest.json",
            "Exact deployable Pages file/hash/size/kind inventory.",
            "generated_index",
            prerequisites=("implementation.pages",),
            verified_by=("test.pages",),
        ),
        _entry(
            "manifest.version",
            "manifest",
            "VERSION",
            "Single normalized release-candidate version.",
            "authoritative_profile",
            prerequisites=("manifest.project",),
            verified_by=("test.pages", "test.all"),
        ),
        _entry(
            "manifest.requirements-ci-lock",
            "manifest",
            "requirements-ci.lock",
            "Hash-required macOS arm64 GitHub runner install input.",
            "authoritative_profile",
            prerequisites=("evidence.dependency-lock",),
            verified_by=("test.pages", "test.all"),
        ),
        _entry(
            "document.rapplication-source",
            "document",
            "cubbies/kody-w/rapplications/rapp-stack/README.md",
            "Explains the under-construction local rapplication source boundary.",
            "authoritative_profile",
            prerequisites=("canon.artifact-chain",),
        ),
        _entry(
            "script.pages-build",
            "script",
            "scripts/pages-build.sh",
            "Deterministic static API and marked-facts generator.",
            "tested_implementation",
            prerequisites=("implementation.pages",),
            verified_by=("test.pages",),
        ),
        _entry(
            "script.pages-check",
            "script",
            "scripts/pages-check.sh",
            "Exact deploy-root, privacy, link, API, and workflow gate.",
            "tested_implementation",
            prerequisites=("script.pages-build",),
            verified_by=("test.pages",),
        ),
        _entry(
            "script.prepare-release",
            "script",
            "scripts/prepare-release.sh",
            "Clean exact tag, commit, and candidate version preflight.",
            "tested_implementation",
            prerequisites=("runbook.exact-commit-promotion",),
            verified_by=("test.pages",),
        ),
        _entry(
            "implementation.release-verifier",
            "implementation",
            "src/rapp_stack_cubby/packaging/release.py",
            "Pinned signature, asset, source, checksum, and attestation verifier.",
            "tested_implementation",
            prerequisites=("manifest.release-trust",),
            verified_by=("test.packaging", "test.pages"),
        ),
        _entry(
            "implementation.promotion-verifier",
            "implementation",
            "src/rapp_stack_cubby/promotion.py",
            "Signed postflight, live-proof, attestation, and promotion verifier.",
            "tested_implementation",
            prerequisites=("implementation.release-verifier",),
            verified_by=("test.release-scripts", "test.pages"),
        ),
        _entry(
            "script.promote-release",
            "script",
            "scripts/promote-release.sh",
            "Prepare exact same-commit final publication and promotion evidence.",
            "tested_implementation",
            prerequisites=("implementation.promotion-verifier",),
            verified_by=("test.release-scripts", "test.pages"),
        ),
        _entry(
            "script.configure-repository",
            "script",
            "scripts/configure-repository.sh",
            "Apply and verify protected GitHub repository settings through gh API.",
            "tested_implementation",
            prerequisites=("runbook.repository-settings",),
            verified_by=("test.release-scripts",),
        ),
        _entry(
            "script.resolve-release-tag",
            "script",
            "scripts/resolve-release-tag.sh",
            "Remote annotated/lightweight tag resolver and race gate.",
            "tested_implementation",
            prerequisites=("script.prepare-release",),
            verified_by=("test.release-scripts",),
        ),
        _entry(
            "script.verify-release-attestations",
            "script",
            "scripts/verify-github-attestations.sh",
            "Exact-asset GitHub attestation verification and result builder.",
            "tested_implementation",
            prerequisites=("implementation.release-verifier",),
            verified_by=("test.release-scripts",),
        ),
        _entry(
            "script.release-postflight",
            "script",
            "scripts/postflight-release.sh",
            "Fresh public redownload, byte parity, trust, and attestation postflight.",
            "tested_implementation",
            prerequisites=(
                "script.resolve-release-tag",
                "script.verify-release-attestations",
            ),
            verified_by=("test.release-scripts",),
        ),
        _entry(
            "document.rapp-end-to-end",
            "evidence",
            "RAPP_END_TO_END.md",
            "Preserved antecedent synthesis plus direct 307-repository bounded-window refresh.",
            "direct_evidence",
            prerequisites=("canon.system-model",),
        ),
        _entry(
            "test.pages",
            "test_family",
            "tests/pages",
            "Static API, HTML, privacy, accessibility, workflow, and release tests.",
            "tested_implementation",
            prerequisites=("implementation.pages",),
            verified_by=(),
        ),
        _entry(
            "test.release-scripts",
            "test_family",
            "tests/packaging/test_release_scripts.py",
            "Malicious tag, moved tag, mocked GitHub, and byte-mismatch tests.",
            "tested_implementation",
            prerequisites=("script.release-postflight",),
            verified_by=(),
        ),
        _entry(
            "document.readme",
            "document",
            "README.md",
            "Public repository orientation and truthful feature status.",
            "authoritative_profile",
            prerequisites=("entry.ai-context",),
        ),
        _entry(
            "document.security",
            "document",
            "SECURITY.md",
            "Current security posture and reporting boundary.",
            "authoritative_profile",
            prerequisites=("canon.security-and-release",),
        ),
        _entry(
            "document.test-fixtures",
            "document",
            "tests/fixtures/README.md",
            "Synthetic-only fixture policy for deterministic tests.",
            "authoritative_profile",
            prerequisites=("runbook.test-strategy",),
        ),
        _entry(
            "document.tools",
            "document",
            "tools/README.md",
            "Scope and safety boundary for repository build helpers.",
            "authoritative_profile",
            prerequisites=("entry.ai-context",),
        ),
        _entry(
            "document.twin-soul",
            "document",
            "cubbies/kody-w/rapplications/rapp-stack/twin/soul.md",
            "Agent-first operating contract loaded by the local runtime.",
            "tested_implementation",
            prerequisites=("canon.agent-abi",),
            verified_by=("test.agents", "test.runtime"),
        ),
        _entry(
            "evidence.account-crawl",
            "evidence",
            "docs/research/account-crawl.md",
            "Human-readable direct account crawl evidence.",
            "direct_evidence",
            prerequisites=("entry.ai-context",),
        ),
        _entry(
            "evidence.audit-manifest",
            "evidence",
            "docs/research/AUDIT_MANIFEST.json",
            "Digest-bound coverage manifest for all local census shards.",
            "direct_evidence",
            prerequisites=("evidence.source-census",),
            implemented_by=("implementation.audit-generator",),
            verified_by=("test.census-audit", "test.context"),
        ),
        _entry(
            "evidence.public-account-snapshot",
            "evidence",
            "docs/research/public-account-snapshot.json",
            (
                "Sanitized authenticated API inventory with response timing, "
                "ETags/page digests, a distinct existence cutoff, individually "
                "timed heads, and deterministic raw-record digests."
            ),
            "direct_evidence",
            prerequisites=("entry.ai-context",),
            implemented_by=("implementation.census-refresh",),
            verified_by=("test.census-audit", "test.context"),
        ),
        _entry(
            "evidence.system-graph-overlay",
            "evidence",
            "docs/research/system-graph-overlay.json",
            "Curated non-repository nodes, relationships, collisions, and eight paths.",
            "direct_evidence",
            prerequisites=("evidence.source-census",),
            implemented_by=("implementation.graph-generator",),
            verified_by=("test.census-audit", "test.context"),
        ),
        _entry(
            "evidence.capability-matrix",
            "evidence",
            "CAPABILITY_MATRIX.json",
            "Capability-level direct evidence, gaps, and CUBBY selection.",
            "direct_evidence",
            prerequisites=("evidence.source-census",),
        ),
        _entry(
            "evidence.dependency-lock",
            "evidence",
            "DEPENDENCY_LOCK.json",
            "Exact target wheels, sources, licenses, and verified hashes.",
            "direct_evidence",
            prerequisites=("canon.security-and-release",),
            verified_by=("test.protocols", "test.all"),
        ),
        _entry(
            "evidence.provenance",
            "evidence",
            "PROVENANCE.json",
            "Per-source inclusion state and original-file hash evidence.",
            "direct_evidence",
            prerequisites=("entry.ai-context",),
        ),
        _entry(
            "evidence.sbom-input",
            "evidence",
            "SBOM_INPUT.json",
            "Pre-release component input; explicitly not a final SBOM.",
            "direct_evidence",
            prerequisites=("evidence.dependency-lock",),
            verified_by=("test.protocols", "test.all"),
        ),
        _entry(
            "evidence.source-census",
            "evidence",
            "SOURCE_CENSUS.json",
            (
                "Direct 307-repository bounded-window census with pinned "
                "evidence heads, twelve completed drift reviews, and separate "
                "post-window movement."
            ),
            "direct_evidence",
            prerequisites=("entry.ai-context",),
        ),
        _entry(
            "evidence.system-graph",
            "evidence",
            "SYSTEM_GRAPH.json",
            "Normalized evidence graph, collisions, and mapped paths.",
            "direct_evidence",
            prerequisites=("evidence.source-census",),
        ),
        _entry(
            "generated.agent-catalog",
            "generated_catalog",
            "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/"
            "agent-catalog.json",
            "Deterministic inventory and exact synchronous ABI of twelve actual agent sources.",
            "generated_index",
            prerequisites=("implementation.actual-agents",),
            implemented_by=("implementation.catalog-builder",),
            verified_by=("test.agents", "test.context"),
        ),
        _entry(
            "generated.context-index",
            "generated_catalog",
            "CONTEXT_INDEX.json",
            "Deterministic machine map of all load-bearing local context.",
            "generated_index",
            prerequisites=("entry.ai-context",),
            implemented_by=("implementation.context-helper",),
        ),
        _entry(
            "generated.census-shards",
            "generated_catalog",
            "docs/research/shards",
            "Eight deterministic complete repository evidence shard ledgers.",
            "generated_index",
            prerequisites=("evidence.source-census",),
            implemented_by=("implementation.audit-generator",),
            verified_by=("test.census-audit", "test.context"),
        ),
        _entry(
            "generated.controller-catalog",
            "generated_catalog",
            "cubbies/kody-w/catalog/controller-catalog.json",
            "Deterministic sole-controller action and source catalog.",
            "generated_index",
            prerequisites=("implementation.controller-agent",),
            implemented_by=("implementation.catalog-builder",),
            verified_by=("test.controller", "test.context"),
        ),
        _entry(
            "generated.command-manifest",
            "generated_catalog",
            "COMMAND_MANIFEST.json",
            "Deterministic argparse commands, nested actions, and exact flags.",
            "generated_index",
            prerequisites=("implementation.product-journey",),
            implemented_by=("implementation.product-journey",),
            verified_by=("test.product-journey", "test.context"),
        ),
        _entry(
            "generated.implementation-matrix",
            "generated_catalog",
            IMPLEMENTATION_MATRIX_RELATIVE.as_posix(),
            "Capability-by-capability local implementation ownership truth.",
            "generated_index",
            prerequisites=("evidence.capability-matrix", "generated.agent-catalog"),
            implemented_by=("implementation.catalog-builder",),
            verified_by=("test.agents", "test.context"),
        ),
        _entry(
            "implementation.actual-agents",
            "implementation",
            "cubbies/kody-w/rapplications/rapp-stack/twin/agents",
            "Twelve independently loadable focused BasicAgent implementations with exact synchronous perform ABI.",
            "tested_implementation",
            prerequisites=("canon.agent-abi",),
            verified_by=("test.agents",),
        ),
        _entry(
            "implementation.agent-closure-package",
            "implementation",
            "src/rapp_stack_cubby/agents",
            "Static actual-agent source safety and exact-AST ABI scanner package.",
            "tested_implementation",
            prerequisites=("canon.agent-abi",),
            verified_by=("test.agents",),
        ),
        _entry(
            "implementation.catalog-builder",
            "implementation",
            "src/rapp_stack_cubby/catalog.py",
            "Deterministic source-inspecting catalog generator.",
            "tested_implementation",
            prerequisites=("canon.agent-abi",),
            verified_by=("test.agents",),
        ),
        _entry(
            "implementation.context-helper",
            "implementation",
            "src/rapp_stack_cubby/context.py",
            "Deterministic context generator and stdlib validator.",
            "tested_implementation",
            prerequisites=("entry.ai-context",),
            verified_by=("test.context",),
        ),
        _entry(
            "implementation.audit-generator",
            "implementation",
            "src/rapp_stack_cubby/audit.py",
            "Deterministic shard/AUDIT_MANIFEST generator and digest validator.",
            "tested_implementation",
            prerequisites=("evidence.source-census",),
            verified_by=("test.census-audit", "test.context"),
        ),
        _entry(
            "implementation.census-refresh",
            "implementation",
            "src/rapp_stack_cubby/census_refresh.py",
            (
                "Authenticated paginated candidate-only metadata/head refresh "
                "with existence cutoff, bounded capture timing, ETags/page and "
                "head digests, individual head times, and review gates."
            ),
            "tested_implementation",
            prerequisites=("evidence.source-census",),
            verified_by=("test.census-audit",),
        ),
        _entry(
            "implementation.graph-generator",
            "implementation",
            "src/rapp_stack_cubby/graph.py",
            "Census-derived repository graph generator and endpoint/path validator.",
            "tested_implementation",
            prerequisites=(
                "evidence.source-census",
                "evidence.system-graph-overlay",
            ),
            verified_by=("test.census-audit", "test.context"),
        ),
        _entry(
            "implementation.controller-agent",
            "implementation",
            "cubbies/kody-w/agents/rapp_stack_cubby_agent.py",
            "Sole streamable exact-source local lifecycle controller.",
            "tested_implementation",
            prerequisites=("canon.twin-lifecycle",),
            verified_by=("test.controller",),
        ),
        _entry(
            "implementation.controller-package",
            "implementation",
            "src/rapp_stack_cubby/controller",
            "Controller loadout builder and source safety scanner.",
            "tested_implementation",
            prerequisites=("implementation.controller-agent",),
            verified_by=("test.controller",),
        ),
        _entry(
            "implementation.controller-loadout-tool",
            "implementation",
            "tools/build_controller_loadout.py",
            "Command wrapper for deterministic controller-only loadout creation.",
            "tested_implementation",
            prerequisites=("implementation.controller-package",),
            verified_by=("test.controller",),
        ),
        _entry(
            "implementation.imessage",
            "implementation",
            "src/rapp_stack_cubby/imessage",
            "Pinned owner-only bridge, RPC supervision, durable state, and CLI.",
            "tested_implementation",
            prerequisites=("canon.messaging-imessage", "evidence.dependency-lock"),
            verified_by=("test.imessage",),
        ),
        _entry(
            "implementation.package",
            "implementation",
            "src/rapp_stack_cubby",
            "Installable verifier, CLI, runtime, catalog, and controller package.",
            "tested_implementation",
            prerequisites=("canon.system-model",),
            verified_by=("test.all",),
        ),
        _entry(
            "implementation.product-journey",
            "implementation",
            "src/rapp_stack_cubby/demo.py",
            (
                "Fresh doctor/bootstrap, signed offline installed-byte demo, "
                "command manifest, receipt, cleanup, and release proof."
            ),
            "tested_implementation",
            prerequisites=(
                "implementation.packaging",
                "implementation.controller-agent",
                "implementation.runtime",
            ),
            verified_by=("test.product-journey", "test.all"),
        ),
        _entry(
            "implementation.packaging",
            "implementation",
            "src/rapp_stack_cubby/packaging",
            (
                "Deterministic source, Store, egg, SBOM, provenance, index, "
                "dependency fetch, and isolated hatch implementation."
            ),
            "tested_implementation",
            prerequisites=("canon.artifact-chain", "evidence.dependency-lock"),
            verified_by=("test.packaging", "test.all"),
        ),
        _entry(
            "implementation.protocols",
            "implementation",
            "src/rapp_stack_cubby/protocols",
            "Canonical JSON, P-256, twin envelopes, keys, and replay journal.",
            "tested_implementation",
            prerequisites=("canon.twin-chat", "evidence.dependency-lock"),
            verified_by=("test.protocols", "test.runtime", "test.controller"),
        ),
        _entry(
            "implementation.rapplication-source",
            "implementation",
            "cubbies/kody-w/rapplications/rapp-stack",
            "Local soul, actual-agent, and generated-catalog source assembly.",
            "tested_implementation",
            prerequisites=("implementation.actual-agents",),
            verified_by=("test.agents", "test.controller"),
        ),
        _entry(
            "implementation.runtime",
            "implementation",
            "src/rapp_stack_cubby/runtime",
            (
                "Clean-room isolated BasicAgent runtime with explicit private "
                "provider auth, exact-model preflight, and strict agent ABI."
            ),
            "tested_implementation",
            prerequisites=("canon.agent-abi", "canon.chat-wire"),
            verified_by=("test.runtime",),
        ),
        _entry(
            "lock.stack",
            "lock",
            "STACK_LOCK.json",
            "Build-blocking selected profile, pins, and release gaps.",
            "authoritative_profile",
            prerequisites=("canon.gap-register",),
        ),
        _entry(
            "manifest.cubby",
            "manifest",
            "cubbies/kody-w/cubby.json",
            "Public non-secret cubby shelf and controller identity.",
            "tested_implementation",
            prerequisites=("implementation.controller-agent",),
            verified_by=("test.controller", "test.context"),
        ),
        _entry(
            "manifest.controller-receipt-template",
            "manifest",
            "cubbies/kody-w/catalog/controller-receipt-template.json",
            "Public field/privacy template for private lifecycle receipts.",
            "tested_implementation",
            prerequisites=("implementation.controller-agent",),
            verified_by=("test.controller", "test.context"),
        ),
        _entry(
            "manifest.project",
            "manifest",
            "pyproject.toml",
            "Python 3.11 package metadata with exact cryptography dependency.",
            "authoritative_profile",
            prerequisites=("implementation.package",),
            verified_by=("test.all",),
        ),
        _entry(
            "manifest.product-identity",
            "manifest",
            "rappid.json",
            "Stable public RAPP product identity bound to synthetic birth facts.",
            "tested_implementation",
            prerequisites=("canon.identity-and-trust",),
            implemented_by=("implementation.packaging",),
            verified_by=("test.packaging",),
        ),
        _entry(
            "manifest.release-source",
            "manifest",
            "rapp-release-source-manifest.json",
            "Self-excluding exact per-file source tree manifest.",
            "tested_implementation",
            prerequisites=("canon.artifact-chain",),
            implemented_by=("implementation.packaging",),
            verified_by=("test.packaging", "test.controller"),
        ),
        _entry(
            "manifest.store-index",
            "manifest",
            "STORE_INDEX.json",
            "Committed non-release local Store source index.",
            "tested_implementation",
            prerequisites=("implementation.packaging",),
            verified_by=("test.packaging",),
        ),
        _entry(
            "manifest.super-rar",
            "manifest",
            "rapp-super-rar.json",
            "Committed SHA-deduplicated controller/application source index.",
            "tested_implementation",
            prerequisites=("implementation.packaging",),
            verified_by=("test.packaging",),
        ),
        _entry(
            "manifest.requirements-lock",
            "manifest",
            "requirements.lock",
            "Hash-required target-only Python dependency install input.",
            "authoritative_profile",
            prerequisites=("evidence.dependency-lock",),
            verified_by=("test.protocols", "test.all"),
        ),
        _entry(
            "script.check",
            "script",
            "scripts/check.sh",
            "Full local verification gate after locked dependencies are installed.",
            "tested_implementation",
            prerequisites=("script.context-check",),
            verified_by=("test.all",),
        ),
        _entry(
            "script.context-check",
            "script",
            "scripts/context-check.sh",
            "Focused context closure gate.",
            "tested_implementation",
            prerequisites=("implementation.context-helper",),
            verified_by=("test.context",),
        ),
        _entry(
            "script.install-imsg",
            "script",
            "scripts/install-imsg.sh",
            "Immutable hash, signature, architecture, and layout verified installer.",
            "tested_implementation",
            prerequisites=("implementation.imessage",),
            verified_by=("test.imessage",),
        ),
        _entry(
            "script.demo",
            "script",
            "scripts/demo-product.sh",
            "One-command offline signed development product journey.",
            "tested_implementation",
            prerequisites=("implementation.product-journey",),
            verified_by=("test.product-journey",),
        ),
        _entry(
            "script.makefile",
            "script",
            "Makefile",
            "Convenience entrypoints for context, tests, and verification.",
            "tested_implementation",
            prerequisites=("script.check",),
            verified_by=("test.all",),
        ),
        _entry(
            "test.agents",
            "test_family",
            "tests/agents",
            "Exact actual-agent contracts, actions, state, and bounded iterative security tests.",
            "tested_implementation",
            prerequisites=("implementation.actual-agents",),
            verified_by=(),
        ),
        _entry(
            "test.all",
            "test_family",
            "tests",
            "Complete stdlib unittest suite.",
            "tested_implementation",
            prerequisites=("implementation.package",),
            verified_by=(),
        ),
        _entry(
            "test.context",
            "test_family",
            "tests/test_context.py",
            "Context index, schema, status, link, and privacy tests.",
            "tested_implementation",
            prerequisites=("implementation.context-helper",),
            verified_by=(),
        ),
        _entry(
            "test.census-audit",
            "test_family",
            "tests",
            (
                "Mocked pagination/rate/error refresh, shard digest, graph "
                "closure, and source metadata exclusion tests."
            ),
            "tested_implementation",
            prerequisites=(
                "implementation.audit-generator",
                "implementation.census-refresh",
                "implementation.graph-generator",
            ),
            verified_by=(),
        ),
        _entry(
            "test.controller",
            "test_family",
            "tests/controller",
            "Controller source, loadout, lifecycle, process, and chat tests.",
            "tested_implementation",
            prerequisites=("implementation.controller-agent",),
            verified_by=(),
        ),
        _entry(
            "test.imessage",
            "test_family",
            "tests/imessage",
            "Owner policy, RPC, durability, routing, installer, CLI, and agent tests.",
            "tested_implementation",
            prerequisites=("implementation.imessage",),
            verified_by=(),
        ),
        _entry(
            "test.packaging",
            "test_family",
            "tests/packaging",
            (
                "Source, identity, dependency, ZIP, artifact, reproducibility, "
                "hatch, rollback, and installed parity tests."
            ),
            "tested_implementation",
            prerequisites=("implementation.packaging",),
            verified_by=(),
        ),
        _entry(
            "test.protocols",
            "test_family",
            "tests/protocols",
            "Canonical, P-256, envelope, replay, concurrency, and key tests.",
            "tested_implementation",
            prerequisites=("implementation.protocols",),
            verified_by=(),
        ),
        _entry(
            "test.product-journey",
            "test_family",
            "tests/test_doctor_demo.py",
            "Doctor modes, fixture demo transitions, receipt, and cleanup tests.",
            "tested_implementation",
            prerequisites=("implementation.product-journey",),
            verified_by=(),
        ),
        _entry(
            "test.runtime",
            "test_family",
            "tests/runtime",
            "Runtime exact ABI, registry, awaitable rejection, storage, provider, orchestration, and HTTP tests.",
            "tested_implementation",
            prerequisites=("implementation.runtime",),
            verified_by=(),
        ),
    ]

    for name, role in CANONICAL_PROFILES.items():
        identifier = f"canon.{_slug(name)}"
        if name == "SYSTEM_MODEL.md":
            prerequisites = ("entry.ai-context",)
        elif name == "IMPLEMENTATION_STATUS.md":
            prerequisites = ("canon.system-model",)
        elif name == "GAP_REGISTER.md":
            prerequisites = ("canon.implementation-status",)
        elif name == "ROADMAP.md":
            prerequisites = ("canon.gap-register",)
        elif name == "GLOSSARY.md":
            prerequisites = ("entry.ai-context",)
        else:
            prerequisites = ("canon.system-model",)
        entries.append(
            _entry(
                identifier,
                "canonical_profile",
                f"docs/canon/{name}",
                role,
                "authoritative_profile",
                prerequisites=prerequisites,
            )
        )

    for name, role in DECISIONS.items():
        entries.append(
            _entry(
                f"decision.{_slug(name)}",
                "decision",
                f"docs/decisions/{name}",
                role,
                "decision",
                prerequisites=("entry.ai-context",),
            )
        )

    for name, role in RUNBOOKS.items():
        if name == "HANDOFF.md":
            prerequisites = (
                "canon.gap-register",
                "canon.implementation-status",
                "canon.system-model",
            )
        elif name == "PACKAGING_AND_RELEASE.md":
            prerequisites = ("canon.artifact-chain", "canon.gap-register")
        elif name == "LOCAL_LIFECYCLE.md":
            prerequisites = ("canon.twin-lifecycle",)
        elif name == "INCIDENT_RESPONSE.md":
            prerequisites = ("canon.security-and-release",)
        else:
            prerequisites = ("entry.ai-context",)
        entries.append(
            _entry(
                f"runbook.{_slug(name)}",
                "runbook",
                f"docs/operations/{name}",
                role,
                "runbook",
                prerequisites=prerequisites,
            )
        )

    for name, role in SCHEMAS.items():
        entries.append(
            _entry(
                f"schema.{_slug(name)}",
                "schema",
                f"schemas/{name}",
                role,
                "authoritative_profile",
                prerequisites=("entry.ai-context",),
            )
        )

    for owner, role in FUTURE_OWNERS.items():
        entries.append(
            _entry(
                f"future.{owner}",
                "future_owner",
                "docs/canon/GAP_REGISTER.md",
                role,
                "future_owned",
                prerequisites=("canon.gap-register",),
                implemented_by=(),
            )
        )
    return sorted(entries, key=lambda item: item["id"])


def _capability_routes(
    matrix: Mapping[str, Any],
    evidence_matrix: Mapping[str, Any],
) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    capabilities = matrix.get("capabilities")
    if not isinstance(capabilities, list):
        raise ContextValidationError("implementation matrix capabilities are invalid")
    evidence_capabilities = evidence_matrix.get("capabilities")
    if not isinstance(evidence_capabilities, list):
        raise ContextValidationError("capability evidence matrix is invalid")
    evidence_by_id = {
        item.get("id"): item
        for item in evidence_capabilities
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }
    for record in capabilities:
        if not isinstance(record, Mapping) or not record.get("selected"):
            continue
        capability_id = str(record.get("capability_id"))
        evidence = evidence_by_id.get(capability_id)
        if not isinstance(evidence, Mapping):
            raise ContextValidationError(
                f"selected capability lacks evidence: {capability_id}"
            )
        owner = record.get("owner")
        if not isinstance(owner, Mapping):
            raise ContextValidationError("selected capability owner is invalid")
        kind = owner.get("kind")
        name = owner.get("name")
        if kind == "future":
            context_id = f"future.{name}"
        elif kind == "pages":
            context_id = "implementation.pages"
        elif kind == "runtime":
            context_id = (
                "implementation.imessage"
                if isinstance(name, str) and name.startswith("imessage-")
                else "implementation.runtime"
            )
        elif kind == "packaging":
            context_id = "implementation.packaging"
        elif kind == "agent" and name == "RappStackCubbyController":
            context_id = "implementation.controller-agent"
        elif kind == "agent":
            context_id = "implementation.actual-agents"
        else:
            raise ContextValidationError(
                f"selected capability has unsupported owner: {record.get('capability_id')}"
            )
        action = owner.get("action")
        owner_text = f"{kind}:{name}"
        if isinstance(action, str) and action:
            owner_text += f"/{action}"
        implementation_state = str(record.get("implementation_state"))
        capability_status = str(record.get("capability_status"))
        if implementation_state == "future_owned":
            semantic_status = "future_owned"
            local_claim = (
                f"Not implemented locally. Future owner {name} must close "
                "the listed gaps before this profile capability is claimed."
            )
            context_status = "future_owned"
            future_owner: str | None = str(name)
        else:
            if capability_status in {"unsafe_legacy", "deprecated"}:
                semantic_status = "safe_narrowing_of_unsafe_reference"
            elif capability_status in {"partial", "contradictory", "spec_only"}:
                semantic_status = "narrowed_tested_implementation"
            else:
                semantic_status = "tested_implementation"
            local_claim = str(record.get("claim"))
            if capability_status != "implemented":
                local_claim += (
                    f" The ecosystem evidence status remains {capability_status}; "
                    "only the selected local narrowing is claimed."
                )
            context_status = "tested_implementation"
            future_owner = None
        direct_evidence: list[dict[str, Any]] = []
        sources = evidence.get("direct_source_repositories")
        if isinstance(sources, list):
            for source in sources:
                if not isinstance(source, Mapping):
                    continue
                direct_evidence.append(
                    {
                        "current_head_sha": source.get("current_head_sha"),
                        "current_observed_at": source.get(
                            "current_observed_at"
                        ),
                        "evidence_head_sha": source.get(
                            "evidence_head_sha", source.get("head_sha")
                        ),
                        "head_drift": source.get("head_drift"),
                        "locators": source.get("evidence", []),
                        "repository": source.get("name"),
                    }
                )
        routes.append(
            {
                "capability_id": capability_id,
                "capability_status": capability_status,
                "context_entry_id": context_id,
                "context_status": context_status,
                "direct_evidence": direct_evidence,
                "future_owner": future_owner,
                "implementation_state": implementation_state,
                "local_claim": local_claim,
                "major_gaps": list(evidence.get("major_gaps", [])),
                "owner": owner_text,
                "profile_contracts": list(
                    evidence.get("protocol_or_contract", [])
                ),
                "selected_implementation": str(
                    evidence.get("selected_implementation")
                ),
                "semantic_status": semantic_status,
            }
        )
    return sorted(routes, key=lambda item: item["capability_id"])


def build_context_index(root: str | Path) -> dict[str, Any]:
    """Build the deterministic context index from local inventories and truth."""

    repository = Path(root).resolve()
    matrix = _read_json(repository / IMPLEMENTATION_MATRIX_RELATIVE)
    evidence_matrix = _read_json(repository / CAPABILITY_MATRIX_RELATIVE)
    entries = _base_entries()
    routes = _capability_routes(matrix, evidence_matrix)
    kind_counts = Counter(str(item["kind"]) for item in entries)
    status_counts = Counter(str(item["status"]) for item in entries)
    return {
        "aggregates": {
            "canonical_profile_count": len(CANONICAL_PROFILES),
            "counts_by_kind": dict(sorted(kind_counts.items())),
            "counts_by_status": dict(sorted(status_counts.items())),
            "decision_count": len(DECISIONS),
            "entry_count": len(entries),
            "future_owner_count": len(FUTURE_OWNERS),
            "runbook_count": len(RUNBOOKS),
            "schema_count": len(SCHEMAS),
            "selected_capability_count": len(routes),
        },
        "authority_order": [
            "current tested code and executable contracts",
            "local decisions and narrowed canonical profiles",
            "direct local audit evidence",
            "external provenance links",
        ],
        "bootstrap_reading_path": [
            "entry.ai-context",
            "canon.system-model",
            "canon.implementation-status",
            "canon.gap-register",
            "runbook.handoff",
            "runbook.repository-verification",
        ],
        "capability_routes": routes,
        "determinism": {
            "encoding": "UTF-8",
            "entry_order": "id",
            "indent_spaces": 2,
            "key_order": "lexicographic",
            "newline": "LF",
            "route_order": "capability_id",
            "trailing_newline": True,
        },
        "entries": entries,
        "schema": CONTEXT_INDEX_SCHEMA,
    }


def write_context_index(root: str | Path) -> dict[str, Any]:
    """Write the deterministic index with repository JSON formatting."""

    repository = Path(root).resolve()
    value = build_context_index(repository)
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        indent=2,
        sort_keys=True,
    )
    (repository / CONTEXT_INDEX_RELATIVE).write_text(
        payload + "\n", encoding="utf-8", newline="\n"
    )
    return value


def validate_context(root: str | Path) -> ContextValidationResult:
    """Validate local context, schemas, ownership, status, and privacy."""

    repository = Path(root).resolve()
    errors: list[str] = []
    try:
        index = _read_json(repository / CONTEXT_INDEX_RELATIVE)
        index_schema = _read_json(repository / CONTEXT_SCHEMA_RELATIVE)
    except ContextValidationError as error:
        return ContextValidationResult((str(error),), 0, 0, 0)

    errors.extend(
        validate_schema_instance(
            index,
            index_schema,
            schema_path=repository / CONTEXT_SCHEMA_RELATIVE,
        )
    )
    try:
        expected = build_context_index(repository)
    except ContextValidationError as error:
        errors.append(str(error))
    else:
        if index != expected:
            errors.append(
                "CONTEXT_INDEX.json is stale; regenerate it with the context builder"
            )

    errors.extend(validate_index_structure(index, repository))
    schema_count, schema_errors = _validate_schema_corpus(repository)
    errors.extend(schema_errors)
    capability_count, truth_errors = _validate_status_truth(index, repository)
    errors.extend(truth_errors)
    errors.extend(_validate_essential_documents(index, repository))
    errors.extend(_validate_context_authorship(repository))

    entries = index.get("entries")
    entry_count = len(entries) if isinstance(entries, list) else 0
    return ContextValidationResult(
        tuple(sorted(set(errors))),
        entry_count,
        schema_count,
        capability_count,
    )


def validate_index_structure(
    index: Mapping[str, Any], repository: Path
) -> list[str]:
    """Validate IDs, paths, references, DAG, and bootstrap ordering."""

    errors: list[str] = []
    entries = index.get("entries")
    if not isinstance(entries, list):
        return ["context entries must be an array"]
    ids = [
        item.get("id")
        for item in entries
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    ]
    if len(ids) != len(entries):
        errors.append("every context entry must have a string id")
    if len(ids) != len(set(ids)):
        errors.append("context entry ids must be unique")
    if ids != sorted(ids):
        errors.append("context entries must be sorted by id")
    id_set = set(ids)
    by_id = {
        str(item["id"]): item
        for item in entries
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }

    graph: dict[str, set[str]] = {identifier: set() for identifier in ids}
    for identifier, entry in by_id.items():
        status = entry.get("status")
        if status not in _STATUS_VALUES:
            errors.append(f"{identifier}: unknown status")
        path = entry.get("path")
        if not isinstance(path, str) or not _safe_relative_path(path):
            errors.append(f"{identifier}: path must be safe and repository-relative")
        else:
            candidate = (repository / path).resolve()
            if candidate != repository and repository not in candidate.parents:
                errors.append(f"{identifier}: path escapes repository")
            elif not candidate.exists():
                errors.append(f"{identifier}: indexed path does not exist: {path}")
        for field in (
            "prerequisites",
            "read_after",
            "implemented_by",
            "verified_by",
        ):
            values = entry.get(field)
            if not isinstance(values, list):
                errors.append(f"{identifier}: {field} must be an array")
                continue
            if values != sorted(values) or len(values) != len(set(values)):
                errors.append(f"{identifier}: {field} must be sorted and unique")
            missing = sorted(set(values) - id_set)
            if missing:
                errors.append(
                    f"{identifier}: {field} references unknown ids: {', '.join(missing)}"
                )
            if field in {"prerequisites", "read_after"}:
                graph[identifier].update(
                    value for value in values if value in id_set
                )
    errors.extend(_cycle_errors(graph))

    bootstrap = index.get("bootstrap_reading_path")
    if not isinstance(bootstrap, list) or not bootstrap:
        errors.append("bootstrap_reading_path must be a non-empty array")
    else:
        if len(bootstrap) != len(set(bootstrap)):
            errors.append("bootstrap reading path must be unique")
        seen: set[str] = set()
        for identifier in bootstrap:
            if identifier not in by_id:
                errors.append(f"bootstrap references unknown id: {identifier}")
                continue
            dependencies = set(by_id[identifier].get("prerequisites", []))
            dependencies.update(by_id[identifier].get("read_after", []))
            unsatisfied = sorted(dependencies - seen)
            if unsatisfied:
                errors.append(
                    f"bootstrap {identifier} appears before: {', '.join(unsatisfied)}"
                )
            seen.add(identifier)

    indexed_canon = {
        str(item.get("path"))
        for item in entries
        if isinstance(item, Mapping) and item.get("kind") == "canonical_profile"
    }
    expected_canon = {f"docs/canon/{name}" for name in CANONICAL_PROFILES}
    if indexed_canon != expected_canon:
        errors.append("every canonical profile must be indexed exactly once")
    return errors


def _cycle_errors(graph: Mapping[str, set[str]]) -> list[str]:
    errors: list[str] = []
    state: dict[str, int] = {}

    def visit(node: str, stack: list[str]) -> None:
        current = state.get(node, 0)
        if current == 2:
            return
        if current == 1:
            start = stack.index(node) if node in stack else 0
            errors.append(
                "context dependency cycle: " + " -> ".join(stack[start:] + [node])
            )
            return
        state[node] = 1
        for dependency in sorted(graph.get(node, ())):
            visit(dependency, stack + [node])
        state[node] = 2

    for identifier in sorted(graph):
        visit(identifier, [])
    return errors


def _validate_schema_corpus(repository: Path) -> tuple[int, list[str]]:
    errors: list[str] = []
    schema_directory = repository / "schemas"
    observed = sorted(path.name for path in schema_directory.glob("*.schema.json"))
    expected = sorted(SCHEMAS)
    if observed != expected:
        errors.append("schema directory does not match the canonical schema inventory")
    loaded: dict[Path, dict[str, Any]] = {}
    for name in observed:
        path = schema_directory / name
        try:
            schema = _read_json(path)
        except ContextValidationError as error:
            errors.append(str(error))
            continue
        loaded[path.resolve()] = schema
        if schema.get("$schema") != DRAFT_2020_12:
            errors.append(f"{path.relative_to(repository)}: requires Draft 2020-12")
        identifier = schema.get("$id")
        if not isinstance(identifier, str) or not (
            identifier.startswith("urn:rapp:") or identifier.startswith("./")
        ):
            errors.append(f"{path.relative_to(repository)}: $id must be a local URN")
        for reference in _collect_refs(schema):
            errors.extend(_validate_ref(reference, path, repository))
        examples = schema.get("examples", [])
        if not isinstance(examples, list):
            errors.append(f"{path.relative_to(repository)}: examples must be an array")
        else:
            for index, example in enumerate(examples):
                for error in validate_schema_instance(
                    example, schema, schema_path=path
                ):
                    errors.append(
                        f"{path.relative_to(repository)} example {index}: {error}"
                    )

    artifact_schemas = {
        "CAPABILITY_MATRIX.json": "capability-matrix.schema.json",
        "CONTEXT_INDEX.json": "context-index.schema.json",
        "GITHUB_ACTIONS_LOCK.json": "github-actions-lock.schema.json",
        "LIVE_PROVIDER_STATUS.json": "live-provider-status.schema.json",
        "RELEASE_STATUS.json": "release-status.schema.json",
        "SOURCE_CENSUS.json": "source-census.schema.json",
        "SYSTEM_GRAPH.json": "system-graph.schema.json",
        "cubbies/kody-w/cubby.json": "cubby.schema.json",
        "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/"
        "agent-catalog.json": "local-agent-catalog.schema.json",
        "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/"
        "implementation-matrix.json": "implementation-matrix.schema.json",
        "docs/api/v1/architecture.json": "pages-api.schema.json",
        "docs/api/v1/capabilities.json": "pages-api.schema.json",
        "docs/api/v1/context.json": "pages-api.schema.json",
        "docs/api/v1/downloads.json": "pages-api.schema.json",
        "docs/api/v1/prompts.json": "pages-api.schema.json",
        "docs/api/v1/status.json": "pages-api.schema.json",
    }
    for artifact, schema_name in artifact_schemas.items():
        try:
            value = _read_json(repository / artifact)
            schema = loaded[(schema_directory / schema_name).resolve()]
        except (ContextValidationError, KeyError) as error:
            errors.append(f"{artifact}: cannot validate ({error})")
            continue
        for error in validate_schema_instance(
            value, schema, schema_path=schema_directory / schema_name
        ):
            errors.append(f"{artifact}: {error}")

    agent_schema = loaded.get((schema_directory / "agent-manifest.schema.json").resolve())
    if agent_schema is not None:
        source_paths = sorted(
            (
                repository
                / "cubbies/kody-w/rapplications/rapp-stack/twin/agents"
            ).glob("*_agent.py")
        )
        source_paths.append(
            repository / "cubbies/kody-w/agents/rapp_stack_cubby_agent.py"
        )
        for path in source_paths:
            try:
                manifest = _literal_manifest(path)
            except ContextValidationError as error:
                errors.append(str(error))
                continue
            for error in validate_schema_instance(
                manifest,
                agent_schema,
                schema_path=schema_directory / "agent-manifest.schema.json",
            ):
                errors.append(f"{path.relative_to(repository)} manifest: {error}")
    return len(observed), errors


def _validate_status_truth(
    index: Mapping[str, Any], repository: Path
) -> tuple[int, list[str]]:
    errors: list[str] = []
    try:
        matrix = _read_json(repository / IMPLEMENTATION_MATRIX_RELATIVE)
    except ContextValidationError as error:
        return 0, [str(error)]
    capabilities = matrix.get("capabilities")
    if not isinstance(capabilities, list):
        return 0, ["implementation matrix capabilities must be an array"]
    selected = [
        item
        for item in capabilities
        if isinstance(item, Mapping) and item.get("selected") is True
    ]
    routes = index.get("capability_routes")
    if not isinstance(routes, list):
        return len(selected), ["context capability_routes must be an array"]
    route_by_id = {
        item.get("capability_id"): item
        for item in routes
        if isinstance(item, Mapping)
    }
    if len(route_by_id) != len(routes):
        errors.append("capability routes must have unique capability ids")
    route_ids = [item.get("capability_id") for item in routes if isinstance(item, Mapping)]
    if route_ids != sorted(route_ids):
        errors.append("capability routes must be sorted")
    selected_ids = {item.get("capability_id") for item in selected}
    if set(route_by_id) != selected_ids:
        errors.append("every selected capability must have exactly one context route")

    entries = index.get("entries")
    by_id = {
        item.get("id"): item
        for item in entries
        if isinstance(entries, list) and isinstance(item, Mapping)
    }
    for capability in selected:
        identifier = capability.get("capability_id")
        route = route_by_id.get(identifier)
        if not isinstance(route, Mapping):
            continue
        state = capability.get("implementation_state")
        if route.get("implementation_state") != state:
            errors.append(f"{identifier}: context implementation state is stale")
        target = by_id.get(route.get("context_entry_id"))
        if not isinstance(target, Mapping):
            errors.append(f"{identifier}: context route target is absent")
        elif state == "future_owned" and target.get("status") != "future_owned":
            errors.append(f"{identifier}: future capability lacks future owner")
        elif state in {"implemented_now", "runtime_implemented"} and (
            target.get("status") != "tested_implementation"
        ):
            errors.append(f"{identifier}: implemented capability lacks tested owner")

    future_ids = matrix.get("future_task_ids")
    if not isinstance(future_ids, list):
        errors.append("implementation matrix future_task_ids must be an array")
    else:
        for owner in future_ids:
            entry = by_id.get(f"future.{owner}")
            if not isinstance(entry, Mapping) or entry.get("status") != "future_owned":
                errors.append(f"future todo owner is not indexed: {owner}")

    runtime = repository / "src/rapp_stack_cubby/runtime"
    controller = repository / "cubbies/kody-w/agents"
    agents = (
        repository / "cubbies/kody-w/rapplications/rapp-stack/twin/agents"
    )
    if not runtime.is_dir() or len(list(runtime.glob("*.py"))) < 9:
        errors.append("runtime status says implemented but runtime files are absent")
    if len(list(controller.glob("*_agent.py"))) != 1:
        errors.append("controller status requires exactly one top-level agent")
    if len(list(agents.glob("*_agent.py"))) != 12:
        errors.append("actual-agent status requires exactly twelve agent sources")
    status_text = (
        repository / "docs/canon/IMPLEMENTATION_STATUS.md"
    ).read_text(encoding="utf-8")
    for required in (
        "| Packaging chain | Trust resolved locally |",
        "| Signed twin-chat | Implemented locally |",
        "| iMessage bridge | Implemented, live enrollment pending |",
        "| Static Pages handoff | Implemented locally |",
        "| Publication | Prepared, unresolved |",
        "| Runtime | Implemented with offline attestation and this-host live provider gate |",
        "| Actual agents | Implemented |",
        "| Controller | Guarded local implementation |",
    ):
        if required not in status_text:
            errors.append(f"implementation status is missing truth row: {required}")
    return len(selected), errors


def _validate_essential_documents(
    index: Mapping[str, Any], repository: Path
) -> list[str]:
    errors: list[str] = []
    entries = index.get("entries")
    if not isinstance(entries, list):
        return errors
    essential_paths = {"AI_CONTEXT.md"}
    privacy_paths = {"AI_CONTEXT.md"}
    for item in entries:
        if not isinstance(item, Mapping):
            continue
        if item.get("kind") in {
            "canonical_profile",
            "decision",
            "runbook",
        }:
            path = item.get("path")
            if isinstance(path, str):
                essential_paths.add(path)
                privacy_paths.add(path)
        elif item.get("kind") == "schema":
            path = item.get("path")
            if isinstance(path, str):
                privacy_paths.add(path)
    for relative in sorted(privacy_paths):
        path = repository / relative
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if relative in essential_paths and _EXTERNAL_LINK_RE.search(text):
            errors.append(f"{relative}: essential context must not require external links")
        if _LOCAL_PATH_RE.search(text):
            errors.append(f"{relative}: absolute workstation path is forbidden")
        if _PHONE_RE.search(text):
            errors.append(f"{relative}: phone-number-shaped content is forbidden")
        if _SECRET_VALUE_RE.search(text):
            errors.append(f"{relative}: credential or private-key material is forbidden")
        if _PRIVATE_IDENTIFIER_RE.search(text):
            errors.append(f"{relative}: private-identifier-shaped content is forbidden")
        for value in _JSON_MESSAGE_VALUE_RE.findall(text):
            if not value.lower().startswith(("configured", "synthetic")):
                errors.append(
                    f"{relative}: examples may contain synthetic message text only"
                )
        if relative not in essential_paths:
            continue
        for raw_target in _MARKDOWN_LINK_RE.findall(text):
            target = raw_target.strip().split("#", 1)[0]
            if not target or target.startswith("#"):
                continue
            if "://" in target or target.startswith("mailto:"):
                errors.append(f"{relative}: link must resolve locally: {raw_target}")
                continue
            candidate = (path.parent / target).resolve()
            if (
                candidate != repository
                and repository not in candidate.parents
            ) or not candidate.exists():
                errors.append(f"{relative}: broken local link: {raw_target}")
    return errors


def _validate_context_authorship(repository: Path) -> list[str]:
    try:
        provenance = _read_json(repository / "PROVENANCE.json")
    except ContextValidationError as error:
        return [str(error)]
    entries = provenance.get("entries")
    if not isinstance(entries, list):
        return ["PROVENANCE.json: entries must be an array"]
    targets = [
        item
        for item in entries
        if isinstance(item, Mapping)
        and item.get("id") == "target-rapp-stack-cubby"
    ]
    if len(targets) != 1:
        return ["PROVENANCE.json: target context authorship is unavailable"]
    expected = {
        "copied_external_prose": False,
        "normalization_basis": "repository-local evidence and tested implementation",
        "original_new_roots": [
            ".github/workflows/",
            "AI_CONTEXT.md",
            "docs/api/v1/",
            "docs/assets/",
            "docs/canon/",
            "docs/decisions/",
            "docs/operations/",
            "schemas/",
            "tests/pages/",
        ],
        "source_copying": False,
    }
    if targets[0].get("context_authorship") != expected:
        return [
            "PROVENANCE.json: context authorship must declare original local "
            "normalization with no copied source or prose"
        ]
    return []


def validate_schema_instance(
    instance: Any,
    schema: Mapping[str, Any] | bool,
    *,
    schema_path: Path,
) -> list[str]:
    """Validate the project schema subset without third-party dependencies."""

    return _validate_value(
        instance,
        schema,
        schema_path=schema_path.resolve(),
        root_schema=schema,
        location="$",
    )


def _validate_value(
    instance: Any,
    schema: Mapping[str, Any] | bool,
    *,
    schema_path: Path,
    root_schema: Mapping[str, Any] | bool,
    location: str,
) -> list[str]:
    if schema is True:
        return []
    if schema is False:
        return [f"{location}: schema rejects every value"]
    if not isinstance(schema, Mapping):
        return [f"{location}: schema node must be an object or boolean"]
    errors: list[str] = []

    reference = schema.get("$ref")
    if isinstance(reference, str):
        try:
            target, target_path, target_root = _resolve_ref(
                reference, schema_path, root_schema
            )
        except ContextValidationError as error:
            errors.append(f"{location}: {error}")
        else:
            errors.extend(
                _validate_value(
                    instance,
                    target,
                    schema_path=target_path,
                    root_schema=target_root,
                    location=location,
                )
            )

    for keyword in ("allOf", "anyOf", "oneOf"):
        branches = schema.get(keyword)
        if not isinstance(branches, list):
            continue
        outcomes = [
            _validate_value(
                instance,
                branch,
                schema_path=schema_path,
                root_schema=root_schema,
                location=location,
            )
            for branch in branches
        ]
        matches = sum(not outcome for outcome in outcomes)
        if keyword == "allOf":
            for outcome in outcomes:
                errors.extend(outcome)
        elif keyword == "anyOf" and matches == 0:
            errors.append(f"{location}: value does not match any allowed schema")
        elif keyword == "oneOf" and matches != 1:
            errors.append(f"{location}: value must match exactly one allowed schema")
    denied = schema.get("not")
    if isinstance(denied, (Mapping, bool)) and not _validate_value(
        instance,
        denied,
        schema_path=schema_path,
        root_schema=root_schema,
        location=location,
    ):
        errors.append(f"{location}: value matches a forbidden schema")

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{location}: value does not match const")
    enum = schema.get("enum")
    if isinstance(enum, list) and instance not in enum:
        errors.append(f"{location}: value is not in enum")

    expected_type = schema.get("type")
    if isinstance(expected_type, str) and not _matches_type(instance, expected_type):
        errors.append(f"{location}: expected {expected_type}")
        return errors
    if isinstance(expected_type, list) and not any(
        isinstance(item, str) and _matches_type(instance, item)
        for item in expected_type
    ):
        errors.append(f"{location}: value has no allowed type")
        return errors

    if isinstance(instance, Mapping):
        required = schema.get("required", [])
        if isinstance(required, list):
            for key in required:
                if key not in instance:
                    errors.append(f"{location}: missing required property {key}")
        properties = schema.get("properties", {})
        property_map = properties if isinstance(properties, Mapping) else {}
        for key, value in instance.items():
            child = property_map.get(key)
            if isinstance(child, (Mapping, bool)):
                errors.extend(
                    _validate_value(
                        value,
                        child,
                        schema_path=schema_path,
                        root_schema=root_schema,
                        location=f"{location}.{key}",
                    )
                )
            elif schema.get("additionalProperties") is False:
                errors.append(f"{location}: additional property {key} is forbidden")
            elif isinstance(schema.get("additionalProperties"), Mapping):
                errors.extend(
                    _validate_value(
                        value,
                        schema["additionalProperties"],
                        schema_path=schema_path,
                        root_schema=root_schema,
                        location=f"{location}.{key}",
                    )
                )
    elif isinstance(instance, list):
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if isinstance(minimum, int) and len(instance) < minimum:
            errors.append(f"{location}: array has fewer than {minimum} items")
        if isinstance(maximum, int) and len(instance) > maximum:
            errors.append(f"{location}: array has more than {maximum} items")
        if schema.get("uniqueItems") is True:
            rendered = [
                json.dumps(value, ensure_ascii=False, sort_keys=True)
                for value in instance
            ]
            if len(rendered) != len(set(rendered)):
                errors.append(f"{location}: array items must be unique")
        item_schema = schema.get("items")
        if isinstance(item_schema, (Mapping, bool)):
            for index, value in enumerate(instance):
                errors.extend(
                    _validate_value(
                        value,
                        item_schema,
                        schema_path=schema_path,
                        root_schema=root_schema,
                        location=f"{location}[{index}]",
                    )
                )
    elif isinstance(instance, str):
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        if isinstance(minimum, int) and len(instance) < minimum:
            errors.append(f"{location}: string is shorter than {minimum}")
        if isinstance(maximum, int) and len(instance) > maximum:
            errors.append(f"{location}: string is longer than {maximum}")
        pattern = schema.get("pattern")
        if isinstance(pattern, str):
            try:
                matched = re.search(pattern, instance)
            except re.error as error:
                errors.append(f"{location}: invalid schema pattern ({error})")
            else:
                if matched is None:
                    errors.append(f"{location}: string does not match pattern")
    elif isinstance(instance, (int, float)) and not isinstance(instance, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, (int, float)) and instance < minimum:
            errors.append(f"{location}: number is below minimum")
        if isinstance(maximum, (int, float)) and instance > maximum:
            errors.append(f"{location}: number is above maximum")
    return errors


def _matches_type(value: Any, expected: str) -> bool:
    return {
        "array": isinstance(value, list),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "null": value is None,
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "object": isinstance(value, Mapping),
        "string": isinstance(value, str),
    }.get(expected, False)


def _resolve_ref(
    reference: str,
    schema_path: Path,
    root_schema: Mapping[str, Any] | bool,
) -> tuple[Mapping[str, Any] | bool, Path, Mapping[str, Any] | bool]:
    document, separator, fragment = reference.partition("#")
    if document:
        if "://" in document or document.startswith("urn:"):
            raise ContextValidationError(f"non-local schema reference: {reference}")
        target_path = (schema_path.parent / document).resolve()
        target_root = _read_json(target_path)
    else:
        target_path = schema_path
        target_root = root_schema
    target: Any = target_root
    if separator and fragment:
        if not fragment.startswith("/"):
            raise ContextValidationError(f"unsupported schema fragment: {reference}")
        for raw_part in fragment[1:].split("/"):
            part = raw_part.replace("~1", "/").replace("~0", "~")
            if not isinstance(target, Mapping) or part not in target:
                raise ContextValidationError(f"unresolved schema reference: {reference}")
            target = target[part]
    if not isinstance(target, (Mapping, bool)):
        raise ContextValidationError(f"schema reference is not a schema: {reference}")
    return target, target_path, target_root


def _collect_refs(value: Any) -> list[str]:
    references: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            if key == "$ref" and isinstance(child, str):
                references.append(child)
            else:
                references.extend(_collect_refs(child))
    elif isinstance(value, list):
        for child in value:
            references.extend(_collect_refs(child))
    return references


def _validate_ref(reference: str, schema_path: Path, repository: Path) -> list[str]:
    if reference.startswith("https://json-schema.org/"):
        return []
    document = reference.split("#", 1)[0]
    if not document:
        try:
            root = _read_json(schema_path)
            _resolve_ref(reference, schema_path, root)
        except ContextValidationError as error:
            return [f"{schema_path.relative_to(repository)}: {error}"]
        return []
    if "://" in document or document.startswith("urn:"):
        return [
            f"{schema_path.relative_to(repository)}: non-local $ref {reference}"
        ]
    target = (schema_path.parent / document).resolve()
    schema_root = (repository / "schemas").resolve()
    if schema_root not in target.parents or not target.is_file():
        return [
            f"{schema_path.relative_to(repository)}: unresolved local $ref {reference}"
        ]
    try:
        target_schema = _read_json(target)
        _resolve_ref(reference, schema_path, _read_json(schema_path))
    except ContextValidationError as error:
        return [f"{schema_path.relative_to(repository)}: {error}"]
    if target_schema.get("$schema") != DRAFT_2020_12:
        return [
            f"{schema_path.relative_to(repository)}: referenced schema is not Draft 2020-12"
        ]
    return []


def _literal_manifest(path: Path) -> dict[str, Any]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
    except (OSError, UnicodeError, SyntaxError) as error:
        raise ContextValidationError(f"{path}: cannot inspect agent manifest") from error
    values: list[Any] = []
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(
            isinstance(target, ast.Name) and target.id == "__manifest__"
            for target in node.targets
        ):
            try:
                values.append(ast.literal_eval(node.value))
            except (TypeError, ValueError) as error:
                raise ContextValidationError(
                    f"{path}: agent manifest is not literal"
                ) from error
    if len(values) != 1 or not isinstance(values[0], dict):
        raise ContextValidationError(f"{path}: exactly one object manifest is required")
    return values[0]


def _read_json(path: Path) -> dict[str, Any]:
    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _DuplicateKeyError(key)
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs_hook)
    except _DuplicateKeyError as error:
        raise ContextValidationError(
            f"{path}: duplicate JSON key {error.args[0]}"
        ) from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContextValidationError(f"{path}: cannot read valid JSON") from error
    if not isinstance(value, dict):
        raise ContextValidationError(f"{path}: top-level JSON must be an object")
    return value


def _safe_relative_path(value: str) -> bool:
    path = Path(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts


def context_summary(root: str | Path) -> dict[str, Any]:
    """Return a validated, concise local-context summary."""

    repository = Path(root).resolve()
    result = validate_context(repository)
    if not result.ok:
        raise ContextValidationError("; ".join(result.errors))
    index = _read_json(repository / CONTEXT_INDEX_RELATIVE)
    aggregates = index["aggregates"]
    by_id = {item["id"]: item for item in index["entries"]}
    return {
        "schema": index["schema"],
        "entries": aggregates["entry_count"],
        "canonical_profiles": aggregates["canonical_profile_count"],
        "schemas": aggregates["schema_count"],
        "decisions": aggregates["decision_count"],
        "runbooks": aggregates["runbook_count"],
        "selected_capabilities": aggregates["selected_capability_count"],
        "future_owners": aggregates["future_owner_count"],
        "bootstrap": [
            by_id[identifier]["path"]
            for identifier in index["bootstrap_reading_path"]
        ],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Generate or validate local context from the command line."""

    arguments = _parser().parse_args(argv)
    if arguments.write:
        write_context_index(arguments.root)
    result = validate_context(arguments.root)
    if arguments.json:
        print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
    elif result.ok:
        print(
            "PASS context closure: "
            f"{result.entry_count} entries, {result.schema_count} schemas, "
            f"{result.capability_count} selected capabilities"
        )
    else:
        for error in result.errors:
            print(f"error: {error}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
