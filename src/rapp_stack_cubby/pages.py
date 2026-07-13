"""Deterministic static Pages API generation and publication-surface checks."""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import tomllib
import urllib.parse
import xml.etree.ElementTree as ElementTree
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from typing import Any, Final

from .errors import RappStackCubbyError

REPOSITORY_URL: Final = "https://github.com/kody-w/rapp-stack-cubby"
PAGES_URL: Final = "https://kody-w.github.io/rapp-stack-cubby/"
API_VERSION: Final = "v1"
DOCS_RELATIVE: Final = Path("docs")
API_RELATIVE: Final = DOCS_RELATIVE / "api/v1"
PAGES_MANIFEST_RELATIVE: Final = DOCS_RELATIVE / "pages-manifest.json"
RELEASE_STATUS_RELATIVE: Final = Path("RELEASE_STATUS.json")
LIVE_PROVIDER_STATUS_RELATIVE: Final = Path("LIVE_PROVIDER_STATUS.json")
PROMPTS_RELATIVE: Final = Path("docs/canon/SHOWCASE_PROMPTS.md")
ACTION_LOCK_RELATIVE: Final = Path("GITHUB_ACTIONS_LOCK.json")
PROJECT_BASE_PATH: Final = "/rapp-stack-cubby/"
PAGES_MANIFEST_SCHEMA: Final = "rapp-pages-manifest/1.0"
PAGES_MANIFEST_SELF_HASH: Final = "sha256-zeroed-self-record"
RELEASE_MANIFEST_NAME: Final = "release-manifest.json"
RELEASE_SIGNATURE_NAME: Final = "release-manifest.json.sig"
RELEASE_CHECKSUMS_NAME: Final = "SHA256SUMS"
SITEMAP_BYTES: Final = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    "  <url>\n"
    f"    <loc>{PAGES_URL}</loc>\n"
    "  </url>\n"
    "</urlset>\n"
).encode("utf-8")

API_SCHEMAS: Final = {
    "architecture.json": "rapp-pages-architecture/1.0",
    "capabilities.json": "rapp-pages-capabilities/1.0",
    "context.json": "rapp-pages-context/1.0",
    "downloads.json": "rapp-pages-downloads/1.0",
    "prompts.json": "rapp-pages-prompts/1.0",
    "status.json": "rapp-pages-status/1.0",
}
DOWNLOAD_ASSETS: Final = (
    ("rapp-stack-cubby.egg", "CUBBY egg", "cubby-egg", "candidate"),
    ("rapp-stack-cubby-store.zip", "Store ZIP", "store-zip", "candidate"),
    ("SHA256SUMS", "SHA-256 sidecar", "checksums", "candidate"),
    ("SBOM.spdx.json", "SPDX SBOM", "sbom", "candidate"),
    (
        "candidate-publication-scan.json",
        "Candidate publication scan",
        "publication-scan",
        "candidate",
    ),
    (
        "candidate-publication-scan.json.sig",
        "Candidate scan signature",
        "detached-signature",
        "candidate",
    ),
    ("release-manifest.json", "Release manifest", "release-manifest", "candidate"),
    (
        "release-manifest.json.sig",
        "Pinned release signature",
        "detached-signature",
        "candidate",
    ),
    ("release-provenance.json", "Release provenance", "provenance", "candidate"),
    ("rapp-super-rar.json", "super-RAR index", "super-rar-index", "candidate"),
    ("store-index.json", "Store index", "store-index", "candidate"),
    (
        "postflight-success.json",
        "Successful public postflight",
        "postflight-receipt",
        "candidate",
    ),
    (
        "postflight-success.json.sig",
        "Postflight signature",
        "detached-signature",
        "candidate",
    ),
    (
        "final-publication-scan.json",
        "Final publication scan",
        "publication-scan",
        "final",
    ),
    (
        "final-publication-scan.json.sig",
        "Final scan signature",
        "detached-signature",
        "final",
    ),
    (
        "live-proof-receipt.json",
        "Sanitized live proof",
        "live-proof",
        "final",
    ),
    (
        "live-proof-receipt.json.sig",
        "Live proof signature",
        "detached-signature",
        "final",
    ),
    (
        "promotion-receipt.json",
        "Final promotion receipt",
        "promotion-receipt",
        "final",
    ),
    (
        "promotion-receipt.json.sig",
        "Promotion signature",
        "detached-signature",
        "final",
    ),
)
EXTERNAL_EVIDENCE_NAMES: Final = {
    "postflight-success.json",
    "postflight-success.json.sig",
    "final-publication-scan.json",
    "final-publication-scan.json.sig",
    "live-proof-receipt.json",
    "live-proof-receipt.json.sig",
    "promotion-receipt.json",
    "promotion-receipt.json.sig",
}
PAGES_EVIDENCE_RELATIVE: Final = DOCS_RELATIVE / "evidence"
FACTS_START: Final = "<!-- pages-build:facts:start -->"
FACTS_END: Final = "<!-- pages-build:facts:end -->"
PUBLIC_PROOF_START: Final = "<!-- pages-build:public-proof:start -->"
PUBLIC_PROOF_END: Final = "<!-- pages-build:public-proof:end -->"
STATUS_START: Final = "<!-- pages-build:release-status:start -->"
STATUS_END: Final = "<!-- pages-build:release-status:end -->"
DOWNLOAD_START: Final = "<!-- pages-build:download:start -->"
DOWNLOAD_END: Final = "<!-- pages-build:download:end -->"
MAX_SITE_FILE_BYTES: Final = 512 * 1024
MAX_SITE_TOTAL_BYTES: Final = 4 * 1024 * 1024
_HEX_40_RE = re.compile(r"^[0-9a-f]{40}$")
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_VERSION_RE = re.compile(
    r"^(?P<base>[0-9]+\.[0-9]+\.[0-9]+)(?:rc(?P<rc>[1-9][0-9]*))?$"
)
_PROMPT_RE = re.compile(
    r"^(?P<number>[1-9][0-9]*)\. \*\*(?P<title>[^*]+)\*\* — "
    r"(?P<text>.+)$"
)
_LOCAL_PATH_RE = re.compile(
    r"(?:/(?:Users|home)/[^/\s]+/|[A-Za-z]:\\Users\\[^\\\s]+\\)"
)
_PHONE_RE = re.compile(
    r"(?<![0-9])(?:\+?1[-. ]?)?\(?[2-9][0-9]{2}\)?"
    r"[-. ][2-9][0-9]{2}[-. ][0-9]{4}(?![0-9])"
)
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
_SECRET_RE = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{20,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"authorization:\s*bearer\s+[A-Za-z0-9._-]{12,})",
    re.IGNORECASE,
)
_FORBIDDEN_BROWSER_PATTERNS: Final = {
    "browser fetch": re.compile(r"\bfetch\s*\(", re.IGNORECASE),
    "XMLHttpRequest": re.compile(r"\bXMLHttpRequest\b", re.IGNORECASE),
    "WebSocket": re.compile(r"\bWebSocket\b", re.IGNORECASE),
    "EventSource": re.compile(r"\bEventSource\b", re.IGNORECASE),
    "localStorage": re.compile(r"\blocalStorage\b", re.IGNORECASE),
    "sessionStorage": re.compile(r"\bsessionStorage\b", re.IGNORECASE),
    "IndexedDB": re.compile(r"\bindexedDB\b", re.IGNORECASE),
    "cookie access": re.compile(r"\bdocument\.cookie\b", re.IGNORECASE),
    "service worker": re.compile(
        r"(?:serviceWorker|service-worker|sw\.js)", re.IGNORECASE
    ),
}
_EXPECTED_STATIC_FILES: Final = {
    ".nojekyll",
    "404.html",
    "assets/favicon.svg",
    "assets/styles.css",
    "index.html",
    "pages-manifest.json",
    "robots.txt",
    "sitemap.xml",
}
_ALLOWED_SITE_SUFFIXES: Final = {
    "",
    ".css",
    ".html",
    ".json",
    ".md",
    ".sig",
    ".svg",
    ".txt",
    ".xml",
}
_ACTIVE_HTML_TAGS: Final = {
    "applet",
    "audio",
    "base",
    "embed",
    "iframe",
    "object",
    "portal",
    "script",
    "style",
    "video",
}
_VOID_HTML_TAGS: Final = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr",
}
_RELEASE_PROOF_WORDS: Final = re.compile(
    r"\b(?:release pending|unreleased|no public artifact|"
    r"publication[^<.]*remain(?:s)? (?:a )?release gate)\b",
    re.IGNORECASE,
)


class PagesError(RappStackCubbyError, ValueError):
    """Raised when the static Pages surface is invalid or stale."""


@dataclass(frozen=True, slots=True)
class ReleaseEvidence:
    """Sanitized release truth used to generate the public static API."""

    state: str
    version: str
    tag: str
    source_commit: str | None
    source_git_tree: str | None
    source_tree_digest: str | None
    release_manifest_sha256: str | None
    key_id: str
    github_attestation_verified: bool
    publication_attestation_verified: bool
    candidate_publication_scan_sha256: str | None
    postflight_success_sha256: str | None
    final_publication_scan_sha256: str | None
    live_proof_sha256: str | None
    promotion_receipt_sha256: str | None
    promotion_run_id: str | None

    @property
    def released(self) -> bool:
        return self.state == "released"

    @property
    def candidate(self) -> bool:
        return self.state == "candidate"


@dataclass(frozen=True, slots=True)
class PagesCheckResult:
    """Structured result for the complete static publication check."""

    errors: tuple[str, ...]
    api_count: int
    file_count: int
    workflow_count: int

    @property
    def ok(self) -> bool:
        return not self.errors


class _DocumentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict[str, str]]] = []
        self.ids: set[str] = set()
        self.links: list[tuple[str, str, str]] = []
        self.text: list[str] = []
        self.h1_count = 0
        self.attributes: list[tuple[str, str, str]] = []
        self.errors: list[str] = []
        self.stack: list[str] = []
        self.doctype_count = 0

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        names = [key.casefold() for key, _value in attrs]
        if len(names) != len(set(names)):
            self.errors.append(f"duplicate attribute on <{tag}>")
        values = {
            key.casefold(): value or ""
            for key, value in attrs
        }
        self.tags.append((tag, values))
        if values.get("id"):
            if values["id"] in self.ids:
                self.errors.append(f"duplicate id {values['id']}")
            self.ids.add(values["id"])
        if tag == "h1":
            self.h1_count += 1
        for attribute in ("href", "src"):
            if values.get(attribute):
                self.links.append((tag, attribute, values[attribute]))
        self.attributes.extend(
            (tag, key, value)
            for key, value in values.items()
        )
        if tag not in _VOID_HTML_TAGS:
            self.stack.append(tag)

    def handle_startendtag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in _VOID_HTML_TAGS:
            self.stack.pop()

    def handle_endtag(self, tag: str) -> None:
        if tag in _VOID_HTML_TAGS:
            self.errors.append(f"void element </{tag}> has an end tag")
        elif not self.stack or self.stack[-1] != tag:
            expected = self.stack[-1] if self.stack else "none"
            self.errors.append(
                f"mismatched end tag </{tag}>; expected </{expected}>"
            )
        else:
            self.stack.pop()

    def handle_decl(self, decl: str) -> None:
        if decl.casefold() != "doctype html" or self.doctype_count:
            self.errors.append("unsupported or duplicate declaration")
        else:
            self.doctype_count += 1

    def handle_pi(self, data: str) -> None:
        del data
        self.errors.append("processing instructions are forbidden")

    def unknown_decl(self, data: str) -> None:
        del data
        self.errors.append("unknown declarations are forbidden")

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.text.append(data.strip())


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PagesError(f"{path.name}: cannot read JSON") from error
    if not isinstance(value, dict):
        raise PagesError(f"{path.name}: expected an object")
    return value


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _read_version(repository: Path) -> str:
    try:
        version = (repository / "VERSION").read_text(encoding="utf-8").strip()
        project = tomllib.loads(
            (repository / "pyproject.toml").read_text(encoding="utf-8")
        )["project"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as error:
        raise PagesError("VERSION and pyproject.toml must be readable") from error
    if _VERSION_RE.fullmatch(version) is None:
        raise PagesError("VERSION must be a normalized candidate version")
    if project.get("version") != version:
        raise PagesError("VERSION and pyproject.toml disagree")
    return version


def release_tag_for_version(version: str) -> str:
    """Return the sole public tag spelling for a normalized package version."""

    match = _VERSION_RE.fullmatch(version)
    if match is None:
        raise PagesError("VERSION must be a normalized candidate version")
    suffix = f"-rc.{match['rc']}" if match["rc"] is not None else ""
    return f"v{match['base']}{suffix}"


def _release_key_id(repository: Path) -> str:
    from .packaging.release import load_release_trust

    try:
        trust = load_release_trust(repository / "RELEASE_TRUST.json")
    except (OSError, RappStackCubbyError) as error:
        raise PagesError("RELEASE_TRUST.json is invalid") from error
    return str(trust["key_id"])


def _count_tests(repository: Path) -> int:
    count = 0
    for path in sorted((repository / "tests").rglob("test*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeError, SyntaxError) as error:
            raise PagesError(f"{path.name}: cannot count tests") from error
        count += sum(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
            for node in ast.walk(tree)
        )
    return count


def _read_release_status(repository: Path) -> dict[str, Any]:
    status = _read_json_object(repository / RELEASE_STATUS_RELATIVE)
    required = {
        "release",
        "schema",
        "source_commit",
        "status",
        "tag",
        "truth",
        "version",
    }
    if set(status) != required:
        raise PagesError("RELEASE_STATUS.json fields are invalid")
    if (
        status.get("schema") != "rapp-release-status/1.0"
        or status.get("status") != "pending"
        or status.get("release") is not False
        or status.get("source_commit") is not None
        or not isinstance(status.get("truth"), str)
        or not status["truth"]
    ):
        raise PagesError("current source must truthfully remain release-pending")
    version = _read_version(repository)
    if (
        status.get("version") != version
        or status.get("tag") != release_tag_for_version(version)
    ):
        raise PagesError("release status version/tag does not match VERSION")
    return status


def _read_live_provider_status(repository: Path) -> dict[str, Any]:
    value = _read_json_object(repository / LIVE_PROVIDER_STATUS_RELATIVE)
    shape = value.get("response_shape")
    if (
        set(value)
        != {"schema", "success", "model", "latency_ms", "response_shape"}
        or value.get("schema") != "rapp-live-provider-status/1.0"
        or value.get("success") is not True
        or not isinstance(value.get("model"), str)
        or not value["model"]
        or not isinstance(value.get("latency_ms"), int)
        or isinstance(value.get("latency_ms"), bool)
        or not 0 <= value["latency_ms"] <= 300_000
        or not isinstance(shape, dict)
        or set(shape)
        != {
            "completion_content_present",
            "completion_finish_reason_present",
            "completion_tool_calls",
            "initial_content_present",
            "initial_tool_calls",
        }
        or shape.get("initial_tool_calls") != 1
        or shape.get("completion_tool_calls") != 0
        or not isinstance(shape.get("initial_content_present"), bool)
        or not isinstance(shape.get("completion_content_present"), bool)
        or not isinstance(
            shape.get("completion_finish_reason_present"), bool
        )
    ):
        raise PagesError("live provider status is invalid")
    return value


def release_evidence(
    repository: Path,
    *,
    release_verification: Mapping[str, Any] | None = None,
    release_tag: str | None = None,
) -> ReleaseEvidence:
    """Resolve pending truth or consume an unforgeable verifier capability."""

    source = _read_release_status(repository)
    key_id = _release_key_id(repository)
    if release_verification is None:
        if release_tag is not None:
            raise PagesError("a release tag requires trusted release verification")
        return ReleaseEvidence(
            state="pending",
            version=source["version"],
            tag=source["tag"],
            source_commit=None,
            source_git_tree=None,
            source_tree_digest=None,
            release_manifest_sha256=None,
            key_id=key_id,
            github_attestation_verified=False,
            publication_attestation_verified=False,
            candidate_publication_scan_sha256=None,
            postflight_success_sha256=None,
            final_publication_scan_sha256=None,
            live_proof_sha256=None,
            promotion_receipt_sha256=None,
            promotion_run_id=None,
        )

    from .packaging.release import ReleaseVerification

    if not isinstance(release_verification, ReleaseVerification):
        raise PagesError("released Pages require local verify-release evidence")
    if release_tag is None or release_tag != source["tag"]:
        raise PagesError("verified release tag does not match VERSION")
    commit = release_verification.get("source_commit")
    git_tree = release_verification.get("source_git_tree")
    tree_digest = release_verification.get("source_tree_digest")
    manifest_digest = release_verification.get("release_manifest_sha256")
    stage = release_verification.get("pages_release_stage")
    candidate_scan_digest = release_verification.get(
        "candidate_publication_scan_sha256"
    )
    postflight_digest = release_verification.get("postflight_success_sha256")
    final_scan_digest = release_verification.get("final_publication_scan_sha256")
    live_proof_digest = release_verification.get("live_proof_sha256")
    promotion_digest = release_verification.get("promotion_receipt_sha256")
    promotion_run_id = release_verification.get("promotion_run_id")
    if (
        release_verification.get("verified") is not True
        or release_verification.get("release") is not True
        or release_verification.get("release_eligible") is not True
        or release_verification.get("signed") is not True
        or release_verification.get("development_only") is not False
        or release_verification.get("version") != source["version"]
        or release_verification.get("key_id") != key_id
        or release_verification.get("github_attestation_verified") is not True
        or release_verification.get("publication_attestation_verified") is not True
        or stage not in {"candidate", "final"}
        or not isinstance(candidate_scan_digest, str)
        or _HEX_64_RE.fullmatch(candidate_scan_digest) is None
        or not isinstance(postflight_digest, str)
        or _HEX_64_RE.fullmatch(postflight_digest) is None
        or (
            stage == "final"
            and (
                not isinstance(final_scan_digest, str)
                or _HEX_64_RE.fullmatch(final_scan_digest) is None
                or not isinstance(live_proof_digest, str)
                or _HEX_64_RE.fullmatch(live_proof_digest) is None
                or not isinstance(promotion_digest, str)
                or _HEX_64_RE.fullmatch(promotion_digest) is None
                or not isinstance(promotion_run_id, str)
                or not promotion_run_id.isdigit()
            )
        )
        or not isinstance(commit, str)
        or _HEX_40_RE.fullmatch(commit) is None
        or not isinstance(git_tree, str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", git_tree) is None
        or not isinstance(tree_digest, str)
        or _HEX_64_RE.fullmatch(tree_digest) is None
        or not isinstance(manifest_digest, str)
        or _HEX_64_RE.fullmatch(manifest_digest) is None
    ):
        raise PagesError("verify-release evidence is not release eligible")
    try:
        head = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "--verify", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        head_tree = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "HEAD^{tree}"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise PagesError("released Pages require an exact Git checkout") from error
    if head != commit or head_tree != git_tree:
        raise PagesError("Pages checkout HEAD/tree does not match the release")
    allowed_generated = {
        "docs/index.html",
        "docs/pages-manifest.json",
        *(f"docs/api/v1/{name}" for name in API_SCHEMAS),
        *(
            f"docs/evidence/{name}"
            for name in (
                "candidate-publication-scan.json",
                "candidate-publication-scan.json.sig",
                "final-publication-scan.json",
                "final-publication-scan.json.sig",
                "live-proof-receipt.json",
                "live-proof-receipt.json.sig",
                "postflight-success.json",
                "postflight-success.json.sig",
                "promotion-receipt.json",
                "promotion-receipt.json.sig",
            )
        ),
    }
    try:
        status = subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignored=no",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise PagesError("cannot inspect released Pages checkout") from error
    for record in status.split(b"\0"):
        if not record:
            continue
        try:
            code = record[:2].decode("ascii")
            relative = record[3:].decode("utf-8")
        except UnicodeError as error:
            raise PagesError("released Pages checkout status is invalid") from error
        if (
            relative not in allowed_generated
            or (
                code == "??"
                and not relative.startswith("docs/evidence/")
            )
            or code not in {" M", "??"}
        ):
            raise PagesError("released Pages checkout has non-generated changes")
    return ReleaseEvidence(
        state="released" if stage == "final" else "candidate",
        version=source["version"],
        tag=release_tag,
        source_commit=commit,
        source_git_tree=git_tree,
        source_tree_digest=tree_digest,
        release_manifest_sha256=manifest_digest,
        key_id=key_id,
        github_attestation_verified=True,
        publication_attestation_verified=True,
        candidate_publication_scan_sha256=candidate_scan_digest,
        postflight_success_sha256=postflight_digest,
        final_publication_scan_sha256=(
            final_scan_digest if isinstance(final_scan_digest, str) else None
        ),
        live_proof_sha256=(
            live_proof_digest if isinstance(live_proof_digest, str) else None
        ),
        promotion_receipt_sha256=(
            promotion_digest if isinstance(promotion_digest, str) else None
        ),
        promotion_run_id=(
            promotion_run_id if isinstance(promotion_run_id, str) else None
        ),
    )


def _verify_released_pages(
    repository: Path,
    *,
    released: bool,
    candidate: bool,
    final: bool,
    release_directory: Path | None,
    release_manifest: Path | None,
    release_manifest_sha256: str | None,
    release_signature: Path | None,
    release_trust: Path | None,
    checksums: Path | None,
    source_root: Path | None,
    github_attestation: Path | None,
    publication_attestation: Path | None,
    postflight_attestation: Path | None,
    promotion_attestation: Path | None,
    promotion_evidence_directory: Path | None,
    promotion_run_id: str | None,
    release_metadata: Path | None,
    candidate_publication_scan: Path | None,
    candidate_publication_scan_signature: Path | None,
    postflight_receipt: Path | None,
    postflight_signature: Path | None,
    promotion_receipt_sha256: str | None,
    release_tag: str | None,
) -> tuple[ReleaseEvidence, Mapping[str, Any] | None]:
    selected = sum((released, candidate, final))
    if selected > 1:
        raise PagesError("select only one candidate or final Pages mode")
    stage = "final" if released or final else ("candidate" if candidate else None)
    values = (
        release_directory,
        release_manifest,
        release_manifest_sha256,
        release_signature,
        release_trust,
        checksums,
        source_root,
        github_attestation,
        publication_attestation,
        postflight_attestation,
        release_metadata,
        candidate_publication_scan,
        candidate_publication_scan_signature,
        postflight_receipt,
        postflight_signature,
        release_tag,
    )
    if stage is None:
        if (
            any(value is not None for value in values)
            or promotion_receipt_sha256
            or promotion_attestation is not None
            or promotion_evidence_directory is not None
            or promotion_run_id is not None
        ):
            raise PagesError("release inputs require candidate or final mode")
        return release_evidence(repository), None
    if any(value is None for value in values):
        raise PagesError(
            "candidate/final Pages require release directory, exact metadata, "
            "manifest SHA, signatures, trust, source, scanner, postflight, "
            "both attestation results, and tag"
        )
    assert release_directory is not None
    assert release_manifest is not None
    assert release_manifest_sha256 is not None
    assert release_signature is not None
    assert release_trust is not None
    assert checksums is not None
    assert source_root is not None
    assert github_attestation is not None
    assert publication_attestation is not None
    assert postflight_attestation is not None
    assert release_metadata is not None
    assert candidate_publication_scan is not None
    assert candidate_publication_scan_signature is not None
    assert postflight_receipt is not None
    assert postflight_signature is not None
    assert release_tag is not None
    if stage == "final" and (
        not isinstance(promotion_receipt_sha256, str)
        or _HEX_64_RE.fullmatch(promotion_receipt_sha256) is None
        or promotion_attestation is None
        or promotion_evidence_directory is None
        or not isinstance(promotion_run_id, str)
        or not promotion_run_id.isdigit()
    ):
        raise PagesError("final Pages require external promotion receipt SHA-256")
    if stage == "candidate" and any(
        value is not None
        for value in (
            promotion_receipt_sha256,
            promotion_attestation,
            promotion_evidence_directory,
            promotion_run_id,
        )
    ):
        raise PagesError("candidate Pages cannot claim final promotion")
    try:
        directory = release_directory.resolve(strict=True)
        manifest = release_manifest.resolve(strict=True)
        signature = release_signature.resolve(strict=True)
        checksum = checksums.resolve(strict=True)
        trust = release_trust.resolve(strict=True)
        source = source_root.resolve(strict=True)
        metadata_path = release_metadata.resolve(strict=True)
        publication_result = publication_attestation.resolve(strict=True)
        postflight_result = postflight_attestation.resolve(strict=True)
        core_result = github_attestation.resolve(strict=True)
        candidate_scan_path = candidate_publication_scan.resolve(strict=True)
        candidate_signature_path = (
            candidate_publication_scan_signature.resolve(strict=True)
        )
        postflight_path = postflight_receipt.resolve(strict=True)
        postflight_signature_path = postflight_signature.resolve(strict=True)
        promotion_result = (
            promotion_attestation.resolve(strict=True)
            if promotion_attestation is not None
            else None
        )
        promotion_directory = (
            promotion_evidence_directory.resolve(strict=True)
            if promotion_evidence_directory is not None
            else None
        )
    except OSError as error:
        raise PagesError("released Pages inputs are unavailable") from error
    if (
        manifest != directory / RELEASE_MANIFEST_NAME
        or signature != directory / RELEASE_SIGNATURE_NAME
        or checksum != directory / RELEASE_CHECKSUMS_NAME
        or candidate_scan_path
        != directory / "candidate-publication-scan.json"
        or candidate_signature_path
        != directory / "candidate-publication-scan.json.sig"
        or postflight_path.name != "postflight-success.json"
        or postflight_signature_path
        != postflight_path.parent / "postflight-success.json.sig"
    ):
        raise PagesError("released Pages require canonical release/evidence sidecars")
    if trust != repository / "RELEASE_TRUST.json":
        raise PagesError("released Pages must use the checked-in RELEASE_TRUST.json")
    if source != repository:
        raise PagesError("released Pages source root must be the checked-out root")
    from .promotion import (
        CORE_RELEASE_ASSETS,
        FINAL_RELEASE_ASSETS,
        verify_postflight_receipt,
        verify_promotion_bundle,
        verify_publication_attestation,
    )

    expected_assets = FINAL_RELEASE_ASSETS
    observed_assets = {item.name for item in directory.iterdir()}
    if observed_assets != set(expected_assets) or any(
        not (directory / name).is_file() or (directory / name).is_symlink()
        for name in expected_assets
    ):
        raise PagesError("release download is not the exact stage asset inventory")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PagesError("release metadata is invalid") from error
    metadata_assets = metadata.get("assets") if isinstance(metadata, dict) else None
    names = sorted(
        item.get("name")
        for item in metadata_assets
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    ) if isinstance(metadata_assets, list) else []
    sizes = {
        item.get("name"): item.get("size")
        for item in metadata_assets
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    } if isinstance(metadata_assets, list) else {}
    if (
        not isinstance(metadata, dict)
        or metadata.get("tag_name") != release_tag
        or metadata.get("target_commitish") is None
        or metadata.get("draft") is not False
        or metadata.get("immutable") is not True
        or metadata.get("prerelease") is not True
        or str(metadata.get("name", "")).startswith("FAILED POSTFLIGHT")
        or (
            stage == "final"
            and not str(metadata.get("name", "")).startswith("PROMOTED:")
        )
        or (
            stage == "candidate"
            and str(metadata.get("name", "")).startswith("PROMOTED:")
        )
        or names != sorted(expected_assets)
        or any(
            sizes.get(name) != (directory / name).stat().st_size
            for name in expected_assets
        )
    ):
        raise PagesError("release metadata is failed, stale, or not exact")
    from .packaging.common import PackagingError
    from .packaging.release import verify_release

    try:
        verified = verify_release(
            manifest,
            expected_manifest_sha256=release_manifest_sha256,
            trust_path=trust,
            signature_path=signature,
            checksums_path=checksum,
            source_root=source,
            github_attestation=core_result,
            additional_assets=tuple(
                name for name in expected_assets if name not in CORE_RELEASE_ASSETS
            ),
            allow_generated_worktree=True,
        )
        commit = verified.get("source_commit")
        if (
            not isinstance(commit, str)
            or metadata.get("target_commitish") != commit
        ):
            raise PagesError("release metadata target does not match source commit")
        from .packaging.publication import verify_publication_receipt

        candidate_scan = verify_publication_receipt(
            candidate_scan_path,
            policy_path=repository / "PUBLICATION_SCAN_POLICY.json",
            required_phase="candidate",
            signature_path=candidate_signature_path,
            trust_path=trust,
            expected_source_commit=commit,
        )
        postflight = verify_postflight_receipt(
            postflight_path,
            postflight_signature_path,
            trust_path=trust,
            expected_tag=release_tag,
            expected_commit=commit,
            expected_manifest_sha256=release_manifest_sha256,
        )
        candidate_digest = hashlib.sha256(
            candidate_scan_path.read_bytes()
        ).hexdigest()
        if (
            candidate_scan.get("verified") is not True
            or postflight["value"]["candidate_publication_scan_sha256"]
            != candidate_digest
        ):
            raise PagesError("postflight does not bind the candidate scanner")
        verify_publication_attestation(
            publication_result,
            directory,
            expected_commit=commit,
            profile="candidate",
        )
        verify_publication_attestation(
            postflight_result,
            postflight_path.parent,
            expected_commit=commit,
            profile="postflight",
        )
        final_evidence: Mapping[str, Any] | None = None
        if stage == "final":
            assert promotion_directory is not None
            assert promotion_result is not None
            if (
                postflight_path.parent != promotion_directory
                or (promotion_directory / "candidate-publication-scan.json").read_bytes()
                != candidate_scan_path.read_bytes()
                or (
                    promotion_directory
                    / "candidate-publication-scan.json.sig"
                ).read_bytes()
                != candidate_signature_path.read_bytes()
            ):
                raise PagesError("promotion evidence changed candidate proof")
            final_evidence = verify_promotion_bundle(
                promotion_directory,
                policy_path=repository / "PUBLICATION_SCAN_POLICY.json",
                trust_path=trust,
                expected_tag=release_tag,
                expected_commit=commit,
            )
            verify_publication_attestation(
                promotion_result,
                promotion_directory,
                expected_commit=commit,
                profile="promotion",
            )
            promotion_path = promotion_directory / "promotion-receipt.json"
            if (
                hashlib.sha256(promotion_path.read_bytes()).hexdigest()
                != promotion_receipt_sha256
            ):
                raise PagesError("promotion receipt digest changed")
        verified["pages_release_stage"] = stage
        verified["publication_attestation_verified"] = True
        verified["candidate_publication_scan_sha256"] = candidate_digest
        verified["postflight_success_sha256"] = hashlib.sha256(
            postflight_path.read_bytes()
        ).hexdigest()
        verified["final_publication_scan_sha256"] = (
            hashlib.sha256(
                (
                    promotion_directory / "final-publication-scan.json"
                ).read_bytes()
            ).hexdigest()
            if stage == "final" and promotion_directory is not None
            else None
        )
        verified["live_proof_sha256"] = (
            final_evidence.get("live_proof_sha256")
            if final_evidence is not None
            else None
        )
        verified["promotion_receipt_sha256"] = (
            promotion_receipt_sha256 if stage == "final" else None
        )
        verified["promotion_run_id"] = (
            promotion_run_id if stage == "final" else None
        )
    except (OSError, PackagingError) as error:
        raise PagesError(f"verify-release rejected released Pages: {error}") from error
    return (
        release_evidence(
            repository,
            release_verification=verified,
            release_tag=release_tag,
        ),
        verified,
    )


def _prompt_records(repository: Path) -> list[dict[str, Any]]:
    try:
        lines = (repository / PROMPTS_RELATIVE).read_text(
            encoding="utf-8"
        ).splitlines()
    except (OSError, UnicodeError) as error:
        raise PagesError("showcase prompt catalog cannot be read") from error
    prompts: list[dict[str, Any]] = []
    for line in lines:
        match = _PROMPT_RE.fullmatch(line)
        if match is None:
            continue
        prompts.append(
            {
                "id": f"prompt-{int(match.group('number')):02d}",
                "number": int(match.group("number")),
                "prompt": match.group("text"),
                "title": match.group("title"),
            }
        )
    if (
        len(prompts) != 10
        or [item["number"] for item in prompts] != list(range(1, 11))
        or prompts[0]["title"] != "One idea to public product."
        or len({item["title"] for item in prompts}) != 10
    ):
        raise PagesError("showcase prompt catalog must contain the exact ten prompts")
    return prompts


def build_static_api(
    root: str | Path,
    *,
    release_verification: Mapping[str, Any] | None = None,
    release_tag: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Build all public API documents from repository-local source truth."""

    repository = Path(root).resolve(strict=True)
    evidence = release_evidence(
        repository,
        release_verification=release_verification,
        release_tag=release_tag,
    )
    census = _read_json_object(repository / "SOURCE_CENSUS.json")
    capability_source = _read_json_object(repository / "CAPABILITY_MATRIX.json")
    implementation = _read_json_object(
        repository
        / "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/"
        "implementation-matrix.json"
    )
    agent_catalog = _read_json_object(
        repository
        / "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/"
        "agent-catalog.json"
    )
    controller_catalog = _read_json_object(
        repository / "cubbies/kody-w/catalog/controller-catalog.json"
    )
    system_graph = _read_json_object(repository / "SYSTEM_GRAPH.json")
    context_index = _read_json_object(repository / "CONTEXT_INDEX.json")
    live_provider_status = _read_live_provider_status(repository)

    implementation_by_id = {
        item["capability_id"]: item
        for item in implementation.get("capabilities", [])
        if isinstance(item, dict)
        and isinstance(item.get("capability_id"), str)
    }
    capabilities = []
    for source in capability_source.get("capabilities", []):
        if not isinstance(source, dict) or not isinstance(source.get("id"), str):
            raise PagesError("capability source contains an invalid record")
        mapped = implementation_by_id.get(source["id"])
        if mapped is None:
            raise PagesError(f"capability mapping is missing: {source['id']}")
        capabilities.append(
            {
                "claim": mapped.get("claim"),
                "direct_evidence": source.get("direct_source_repositories"),
                "evidence_status": source.get("status"),
                "id": source["id"],
                "implementation_state": mapped.get("implementation_state"),
                "major_gaps": source.get("major_gaps"),
                "owner": mapped.get("owner"),
                "plane": source.get("plane"),
                "purpose": source.get("purpose"),
                "selected": source.get("selected_for_cubby") is True,
                "selected_implementation": source.get(
                    "selected_implementation"
                ),
            }
        )
    capabilities.sort(key=lambda item: item["id"])
    status_counts = Counter(
        str(item["implementation_state"]) for item in capabilities
    )
    publication_status = (
        "released"
        if evidence.released
        else ("candidate" if evidence.candidate else "pending-source")
    )
    release_value = {
        "candidate_publication_scan_sha256": (
            evidence.candidate_publication_scan_sha256
        ),
        "final_publication_scan_sha256": evidence.final_publication_scan_sha256,
        "github_attestation_verified": evidence.github_attestation_verified,
        "live_proof_sha256": evidence.live_proof_sha256,
        "pinned_key_id": evidence.key_id,
        "postflight_success_sha256": evidence.postflight_success_sha256,
        "promotion_receipt_sha256": evidence.promotion_receipt_sha256,
        "promotion_run_id": evidence.promotion_run_id,
        "publication_attestation_verified": (
            evidence.publication_attestation_verified
        ),
        "release_manifest_sha256": evidence.release_manifest_sha256,
        "source_commit": evidence.source_commit,
        "source_git_tree": evidence.source_git_tree,
        "source_tree_digest": evidence.source_tree_digest,
        "state": evidence.state,
        "tag": evidence.tag,
        "version": evidence.version,
    }
    trust_ref = evidence.source_commit if evidence.released else "main"
    trust = {
        "algorithm": "ecdsa-p256-sha256",
        "download_url": (
            f"{REPOSITORY_URL}/raw/{trust_ref}/RELEASE_TRUST.json"
        ),
        "key_id": evidence.key_id,
        "source": "RELEASE_TRUST.json",
        "source_url": (
            f"{REPOSITORY_URL}/blob/{trust_ref}/RELEASE_TRUST.json"
        ),
        "verify_command": (
            "PYTHONPATH=src python3.11 -m rapp_stack_cubby verify-release "
            "--release-manifest release-manifest.json "
            "--release-manifest-sha256 <external-sha256> "
            "--trust RELEASE_TRUST.json "
            "--signature release-manifest.json.sig "
            "--checksums SHA256SUMS --source-root <exact-checkout> "
            "--github-attestation github-attestation.json"
        ),
    }
    metrics = {
        "actual_agents": agent_catalog.get("agent_count"),
        "capabilities": capability_source.get("aggregates", {}).get(
            "capability_count"
        ),
        "repositories_audited": census.get("repository_count"),
        "antecedent_repositories": census.get("antecedent_audit", {}).get(
            "repository_count"
        ),
        "local_product_nodes": 1,
        "selected_capabilities": capability_source.get("aggregates", {}).get(
            "selected_count"
        ),
        "streamable_controllers": (
            1 if controller_catalog.get("only_streamable_agent") is True else 0
        ),
        "tests": _count_tests(repository),
    }
    census_evidence = {
        "antecedent_repository_count": census.get(
            "antecedent_audit", {}
        ).get("repository_count"),
        "audit_complete": census.get("repository_count")
        == census.get("aggregates", {}).get("audited_true"),
        "cutoff": census.get("existence_cutoff"),
        "cutoff_semantics": "inclusive repository existence boundary",
        "drift_review": {
            "post_window_drift_count": census.get("aggregates", {})
            .get("head_drift_counts", {})
            .get("post_window_drift", 0),
            "required_count": len(
                census.get("snapshot_comparison", {}).get(
                    "required_drift_reviews", []
                )
            ),
            "status": "complete",
        },
        "local_product": census.get("local_product"),
        "observation_window": census.get("observation_window"),
        "public_repository_count": census.get("repository_count"),
        "raw_inventory_sha256": census.get("raw_inventory", {}).get("sha256"),
        "snapshot_semantics": (
            "bounded non-atomic observation window; each head is paired "
            "with its own API response time"
        ),
    }
    status = {
        "api_version": API_VERSION,
        "canonical_url": PAGES_URL,
        "evidence": census_evidence,
        "journey": {
            "offline_end_to_end_local_attestation": "implemented",
            "live_copilot": "implemented_this_host",
            "live_imessage": "external_final_gate",
            "public_pages": (
                "released"
                if evidence.released
                else (
                    "candidate_verified"
                    if evidence.candidate
                    else "external_final_gate"
                )
            ),
        },
        "live_provider_host_proof": live_provider_status,
        "metrics": metrics,
        "release": release_value,
        "schema": API_SCHEMAS["status.json"],
        "sources": {
            "agents": (
                "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/"
                "agent-catalog.json"
            ),
            "capabilities": "CAPABILITY_MATRIX.json",
            "controllers": "cubbies/kody-w/catalog/controller-catalog.json",
            "repositories": "SOURCE_CENSUS.json",
            "tests": "tests/",
        },
        "status": publication_status,
        "trust": trust,
    }
    capability_api = {
        "api_version": API_VERSION,
        "capabilities": capabilities,
        "counts_by_implementation_state": dict(sorted(status_counts.items())),
        "evidence": census_evidence,
        "release": release_value,
        "schema": API_SCHEMAS["capabilities.json"],
        "selected_count": sum(item["selected"] for item in capabilities),
        "source": {
            "capability_matrix": "CAPABILITY_MATRIX.json",
            "implementation_matrix": (
                "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/"
                "implementation-matrix.json"
            ),
        },
        "status": publication_status,
        "total": len(capabilities),
    }
    architecture = {
        "aggregates": system_graph.get("aggregates"),
        "api_version": API_VERSION,
        "canonical_paths": system_graph.get("canonical_end_to_end_paths"),
        "collisions": system_graph.get("collisions"),
        "edges": [
            {
                "evidence_strength": item.get("evidence_strength"),
                "id": item.get("id"),
                "source_id": item.get("source_id"),
                "target_id": item.get("target_id"),
                "type": item.get("type"),
            }
            for item in system_graph.get("edges", [])
            if isinstance(item, dict)
        ],
        "evidence": census_evidence,
        "nodes": [
            {
                "audited": item.get("audited"),
                "classification": item.get("classification"),
                "current_head_sha": item.get("current_head_sha"),
                "evidence_head_sha": item.get("evidence_head_sha"),
                "head_drift": item.get("head_drift"),
                "id": item.get("id"),
                "name": item.get("name"),
                "node_type": item.get("node_type"),
                "primary_plane": item.get("primary_plane"),
                "rapp_relevance": item.get("rapp_relevance"),
            }
            for item in system_graph.get("repo_nodes", [])
            if isinstance(item, dict)
        ]
        + [
            {
                "description": item.get("description"),
                "antecedent_public_repository": item.get(
                    "antecedent_public_repository"
                ),
                "id": item.get("id"),
                "name": item.get("name"),
                "node_type": item.get("node_type"),
                "primary_plane": item.get("primary_plane"),
                "selected_for_cubby": item.get("selected_for_cubby"),
            }
            for item in system_graph.get("non_repo_nodes", [])
            if isinstance(item, dict)
        ],
        "product_chain": [
            "local product source (non-antecedent)",
            "rapp-cubby/1.0",
            "rapp-application/1.0",
            "brainstem-egg/2.3-cubby",
            "controller",
            "isolated installed twin",
            "signed twin-chat",
            "owner iMessage",
        ],
        "release": release_value,
        "schema": API_SCHEMAS["architecture.json"],
        "source": "SYSTEM_GRAPH.json",
        "status": publication_status,
    }
    context = {
        "aggregates": context_index.get("aggregates"),
        "api_version": API_VERSION,
        "authority_order": context_index.get("authority_order"),
        "bootstrap_reading_path": context_index.get("bootstrap_reading_path"),
        "capability_routes": context_index.get("capability_routes"),
        "entries": context_index.get("entries"),
        "evidence": census_evidence,
        "release": release_value,
        "schema": API_SCHEMAS["context.json"],
        "source": "CONTEXT_INDEX.json",
        "status": publication_status,
    }
    availability = evidence.state
    downloads = {
        "api_version": API_VERSION,
        "assets": [
            {
                "availability": (
                    "released"
                    if evidence.released
                    else (
                        "candidate"
                        if evidence.candidate and minimum_stage == "candidate"
                        else "pending"
                    )
                ),
                "filename": filename,
                "kind": kind,
                "label": label,
                "distribution": (
                    "actions-artifact"
                    if filename in EXTERNAL_EVIDENCE_NAMES
                    else "release-asset"
                ),
                "url": (
                    f"{PAGES_URL}evidence/{filename}"
                    if filename in EXTERNAL_EVIDENCE_NAMES
                    else (
                        f"{REPOSITORY_URL}/releases/download/"
                        f"{evidence.tag}/{filename}"
                    )
                ),
            }
            for filename, label, kind, minimum_stage in DOWNLOAD_ASSETS
        ],
        "evidence": census_evidence,
        "exact_hashes": (
            f"{REPOSITORY_URL}/releases/download/"
            f"{evidence.tag}/SHA256SUMS"
        ),
        "release": release_value,
        "schema": API_SCHEMAS["downloads.json"],
        "status": availability,
        "trust": trust,
    }
    prompts = {
        "api_version": API_VERSION,
        "count": 10,
        "evidence": census_evidence,
        "prompts": _prompt_records(repository),
        "release": release_value,
        "schema": API_SCHEMAS["prompts.json"],
        "source": PROMPTS_RELATIVE.as_posix(),
        "status": publication_status,
    }
    result = {
        "architecture.json": architecture,
        "capabilities.json": capability_api,
        "context.json": context,
        "downloads.json": downloads,
        "prompts.json": prompts,
        "status.json": status,
    }
    _validate_api_shape(result)
    return result


def _validate_api_shape(documents: Mapping[str, Mapping[str, Any]]) -> None:
    if set(documents) != set(API_SCHEMAS):
        raise PagesError("static API file set is invalid")
    for name, value in documents.items():
        if (
            value.get("schema") != API_SCHEMAS[name]
            or value.get("api_version") != API_VERSION
            or not isinstance(value.get("status"), str)
            or not value["status"]
        ):
            raise PagesError(f"{name}: schema/version/status is invalid")
    status = documents["status.json"]
    metrics = status.get("metrics")
    if (
        not isinstance(metrics, Mapping)
        or set(metrics)
        != {
            "actual_agents",
            "antecedent_repositories",
            "capabilities",
            "local_product_nodes",
            "repositories_audited",
            "selected_capabilities",
            "streamable_controllers",
            "tests",
        }
        or not all(
            isinstance(value, int) and not isinstance(value, bool) and value > 0
            for value in metrics.values()
        )
    ):
        raise PagesError("status.json metrics are invalid")
    capabilities = documents["capabilities.json"].get("capabilities")
    if (
        not isinstance(capabilities, list)
        or len(capabilities) != metrics["capabilities"]
        or [item.get("id") for item in capabilities]
        != sorted(item.get("id") for item in capabilities)
    ):
        raise PagesError("capabilities.json records are invalid")
    architecture = documents["architecture.json"]
    if (
        not isinstance(architecture.get("nodes"), list)
        or not isinstance(architecture.get("edges"), list)
        or not isinstance(architecture.get("canonical_paths"), list)
    ):
        raise PagesError("architecture.json graph is invalid")
    context = documents["context.json"]
    if (
        not isinstance(context.get("entries"), list)
        or not isinstance(context.get("capability_routes"), list)
    ):
        raise PagesError("context.json handoff is invalid")
    prompts = documents["prompts.json"]
    if prompts.get("count") != 10 or len(prompts.get("prompts", [])) != 10:
        raise PagesError("prompts.json must contain exactly ten prompts")
    downloads = documents["downloads.json"]
    if len(downloads.get("assets", [])) != len(DOWNLOAD_ASSETS):
        raise PagesError("downloads.json asset list is incomplete")
    if any("sha256" in item for item in downloads["assets"]):
        raise PagesError("downloads.json must not embed release artifact hashes")


def _render_facts(api: Mapping[str, Mapping[str, Any]]) -> str:
    status = api["status.json"]
    metrics = status["metrics"]
    release = status["release"]
    downloads = api["downloads.json"]["assets"]
    trust = api["downloads.json"]["trust"]
    census_evidence = status["evidence"]
    state = release["state"]
    state_label = {
        "candidate": "Candidate verified",
        "pending": "Release pending",
        "released": "Released",
    }[state]
    release_class = state
    if state in {"candidate", "released"}:
        asset_items = "\n".join(
            (
                '              <li><a href="{url}">{label}</a></li>'.format(**item)
                if item["availability"] != "pending"
                else f"              <li>{item['label']} <span>— pending final promotion</span></li>"
            )
            for item in downloads
        )
        if state == "released":
            release_detail = (
                "Pinned signatures, candidate and final publication scans, "
                "postflight, live proof, promotion, exact source, canonical "
                "checksums, public bytes, and GitHub attestations were verified. "
                f"Source commit <code>{release['source_commit']}</code>. "
                f'Use the release-side <a href="{api["downloads.json"]["exact_hashes"]}">'
                "SHA256SUMS</a>."
            )
            release_label = f"Release {release['version']}"
        else:
            release_detail = (
                "The exact prerelease, candidate scanner receipt, signatures, "
                "public postflight, source commit, checksums, bytes, and GitHub "
                "attestations were verified. Live proof and final promotion "
                f"remain external gates. Source commit <code>{release['source_commit']}</code>."
            )
            release_label = f"Candidate {release['version']}"
    else:
        asset_items = "\n".join(
            f"              <li>{item['label']} <span>— pending</span></li>"
            for item in downloads
        )
        release_detail = (
            "No public artifact is claimed. Exact hashes will live only in "
            "the release-side SHA256SUMS asset."
        )
        release_label = f"Candidate {release['version']}"
    return f"""{FACTS_START}
        <div class="metric-grid" aria-label="Direct evidence metrics">
          <article><strong>{metrics['repositories_audited']}</strong><span>repositories audited</span></article>
          <article><strong>{metrics['capabilities']}</strong><span>capabilities mapped</span></article>
          <article><strong>{metrics['actual_agents']}</strong><span>actual agents</span></article>
          <article><strong>{metrics['streamable_controllers']}</strong><span>streamable controller</span></article>
          <article><strong>{metrics['tests']}</strong><span>test methods</span></article>
        </div>
        <p class="evidence-cutoff">Public account evidence cutoff:
          <time datetime="{census_evidence['cutoff']}">{census_evidence['cutoff']}</time>.
          The {census_evidence['public_repository_count']} audited public
          repositories exclude this separate local product node.</p>
        <div class="release-state {release_class}" id="release-state">
          <p class="eyebrow">{release_label}</p>
          <h3>{state_label}</h3>
          <p>{release_detail}</p>
          <ul class="download-list">
{asset_items}
          </ul>
          <p>Release signer: <code>{trust['key_id']}</code>.
            <a href="{trust['source_url']}">View RELEASE_TRUST.json</a> ·
            <a href="{trust['download_url']}">Download public trust anchor</a>
          </p>
        </div>
{FACTS_END}"""


def _replace_generated_block(
    html: str,
    *,
    start_marker: str,
    end_marker: str,
    replacement: str,
) -> str:
    start = html.find(start_marker)
    end = html.find(end_marker)
    if start < 0 or end < 0 or end < start:
        raise PagesError("docs/index.html generated release markers are missing")
    end += len(end_marker)
    if (
        html.find(start_marker, start + 1) >= 0
        or html.find(end_marker, end) >= 0
    ):
        raise PagesError("docs/index.html generated release markers are duplicated")
    return html[:start] + replacement + html[end:]


def _render_public_proof(state: str) -> str:
    proof_state = state
    proof_label = {
        "candidate": "Candidate verified",
        "pending": "Unreleased",
        "released": "Released",
    }[state]
    proof_copy = (
        "Pinned signing, the exact source commit and Git tree, canonical "
        "checksums, scanner and promotion receipts, downloaded-byte equality, "
        "and GitHub attestations are verified for this release."
        if state == "released"
        else (
            "Candidate signing, source/history/Pages scanning, exact public "
            "inventory, postflight bytes, and GitHub attestations are verified; "
            "live proof and final promotion remain."
            if state == "candidate"
            else
        "Final exact-commit signing, live enrollment, publication, public-byte "
        "equality, and end-to-end host attestation remain release gates."
        )
    )
    return f"""{PUBLIC_PROOF_START}
      <div class="status-key" aria-label="Implementation status legend">
        <span class="status implemented">Implemented locally</span>
        <span class="status mapped">Mapped / reference-only</span>
        <span class="status {proof_state}">{proof_label}</span>
      </div>
      <div class="map-grid">
        <article>
          <p class="node-state implemented">Implemented locally</p>
          <h3>Source and context</h3>
          <p>The repository carries canonical profiles, decisions, schemas,
            runbooks, evidence matrices, package source, actual agents, controller,
            tests, locks, and deterministic generators.</p>
        </article>
        <article>
          <p class="node-state implemented">Implemented locally</p>
          <h3>Build and hatch</h3>
          <p>Locked inert dependencies enter a deterministic Store ZIP and CUBBY
            egg. Verification precedes offline hatch into a distinct installation.</p>
        </article>
        <article>
          <p class="node-state implemented">Implemented locally</p>
          <h3>Controller and twin</h3>
          <p>The sole streamable controller supervises isolated children. Signed
            requests and signed nonce-bound responses use durable replay handling.</p>
        </article>
        <article>
          <p class="node-state implemented">Implemented locally</p>
          <h3>Owner messaging edge</h3>
          <p>The bridge source accepts one enrolled owner direct conversation.
            Real enrollment, message content, identifiers, and state stay private.</p>
        </article>
        <article>
          <p class="node-state mapped">Mapped / reference-only</p>
          <h3>Neighborhood, fleet, cloud</h3>
          <p>Those ecosystem progressions are represented in the evidence graph.
            This candidate does not claim local deployment or hosted services.</p>
        </article>
        <article>
          <p class="node-state {proof_state}">{proof_label}</p>
          <h3>Public proof</h3>
          <p>{proof_copy}</p>
        </article>
      </div>
{PUBLIC_PROOF_END}"""


def _render_status_section(state: str) -> str:
    heading = (
        "Public release proof is verified"
        if state == "released"
        else (
            "Public candidate proof is verified"
            if state == "candidate"
            else "Local proof is not a release claim"
        )
    )
    release_cells = (
        "<td>Released</td><td>Trusted public assets and attestations verified</td>"
        if state == "released"
        else (
            "<td>Candidate</td><td>Postflight and candidate receipts verified; promotion pending</td>"
            if state == "candidate"
            else "<td>Pending</td><td>No public artifact or attestation claimed</td>"
        )
    )
    enrollment = (
        "Live private enrollment remains separate from public release"
        if state == "released"
        else (
            "Live private enrollment and promotion pending"
            if state == "candidate"
            else "Live private enrollment pending"
        )
    )
    return f"""{STATUS_START}
    <section class="section" aria-labelledby="status-title">
      <div class="section-heading">
        <p class="eyebrow">Current implementation status</p>
        <h2 id="status-title">{heading}</h2>
      </div>
      <div class="table-wrap" tabindex="0" role="region" aria-label="Implementation status table">
        <table>
          <caption>Source-derived product areas and their release meaning</caption>
          <thead><tr><th scope="col">Area</th><th scope="col">Now</th><th scope="col">Meaning</th></tr></thead>
          <tbody>
            <tr><th scope="row">Context, schemas, decisions</th><td>Implemented</td><td>Complete local working knowledge</td></tr>
            <tr><th scope="row">Runtime and actual agents</th><td>Implemented locally</td><td>Development profile; no hosted runtime</td></tr>
            <tr><th scope="row">Controller and isolation</th><td>Implemented locally</td><td>Guarded lifecycle and separate child roots</td></tr>
            <tr><th scope="row">Signed twin-chat</th><td>Implemented locally</td><td>Same-owner local trust profile</td></tr>
            <tr><th scope="row">Offline installed-byte attestation</th><td>Implemented</td><td>Network-free signed SelfTest, stop, and no-orphan proof</td></tr>
            <tr><th scope="row">Owner iMessage bridge</th><td>Source implemented</td><td>{enrollment}</td></tr>
            <tr><th scope="row">Pages handoff</th><td>Implemented locally</td><td>Static, checked deployment source</td></tr>
            <tr><th scope="row">Release</th>{release_cells}</tr>
          </tbody>
        </table>
      </div>
    </section>
{STATUS_END}"""


def _render_download_section(
    release: Mapping[str, Any],
    trust: Mapping[str, Any],
) -> str:
    if release["state"] == "released":
        copy = (
            "The trusted external release manifest, detached signature, "
            "RELEASE_TRUST.json, exact SHA256SUMS asset set, source checkout, "
            "and GitHub attestations were verified before these links were enabled."
        )
    elif release["state"] == "candidate":
        copy = (
            "Candidate scanner, signed public postflight, exact prerelease "
            "inventory, source binding, checksums, and attestations are verified. "
            "Final-only receipt links remain disabled until promotion."
        )
    else:
        copy = (
            "The generated release panel becomes linkable only after the local "
            "verify-release path validates an external manifest digest, detached "
            "signature, pinned trust, every asset, exact source, and attestations."
        )
    return f"""{DOWNLOAD_START}
    <section id="download" class="section download" aria-labelledby="download-title">
      <div class="section-heading">
        <p class="eyebrow">Release and download</p>
        <h2 id="download-title">Stable names, explicit availability</h2>
        <p>{copy}</p>
      </div>
      <p><a href="{REPOSITORY_URL}/releases">Release history</a> ·
        <a href="{PROJECT_BASE_PATH}api/v1/downloads.json">Download metadata API</a> ·
        <a href="{trust['source_url']}">RELEASE_TRUST.json</a> ·
        <a href="{REPOSITORY_URL}/blob/main/RELEASE_CHECKLIST.md">Release checklist</a></p>
    </section>
{DOWNLOAD_END}"""


def render_generated_files(
    root: str | Path,
    *,
    release_verification: Mapping[str, Any] | None = None,
    release_tag: str | None = None,
    evidence_overlay: Mapping[Path, bytes] | None = None,
) -> dict[Path, bytes]:
    """Render all generated bytes without changing the repository."""

    repository = Path(root).resolve(strict=True)
    api = build_static_api(
        repository,
        release_verification=release_verification,
        release_tag=release_tag,
    )
    try:
        index = (repository / DOCS_RELATIVE / "index.html").read_text(
            encoding="utf-8"
        )
    except (OSError, UnicodeError) as error:
        raise PagesError("docs/index.html cannot be read") from error
    rendered = {
        API_RELATIVE / name: _json_bytes(value)
        for name, value in sorted(api.items())
    }
    for relative, content in (evidence_overlay or {}).items():
        if (
            not isinstance(relative, Path)
            or relative.parent != PAGES_EVIDENCE_RELATIVE
            or relative.name not in {
                filename
                for filename, _label, _kind, _stage in DOWNLOAD_ASSETS
            }
            or not isinstance(content, bytes)
        ):
            raise PagesError("Pages evidence overlay is invalid")
        rendered[relative] = content
    index = _replace_generated_block(
        index,
        start_marker=FACTS_START,
        end_marker=FACTS_END,
        replacement=_render_facts(api),
    )
    index = _replace_generated_block(
        index,
        start_marker=PUBLIC_PROOF_START,
        end_marker=PUBLIC_PROOF_END,
        replacement=_render_public_proof(
            api["status.json"]["release"]["state"]
        ),
    )
    index = _replace_generated_block(
        index,
        start_marker=STATUS_START,
        end_marker=STATUS_END,
        replacement=_render_status_section(
            api["status.json"]["release"]["state"]
        ),
    )
    index = _replace_generated_block(
        index,
        start_marker=DOWNLOAD_START,
        end_marker=DOWNLOAD_END,
        replacement=_render_download_section(
            api["status.json"]["release"],
            api["status.json"]["trust"],
        ),
    )
    rendered[DOCS_RELATIVE / "index.html"] = index.encode("utf-8")
    rendered[PAGES_MANIFEST_RELATIVE] = _render_pages_manifest(
        repository, rendered
    )
    return rendered


def _pages_evidence_overlay(
    evidence: ReleaseEvidence,
    *,
    release_directory: Path | None,
    postflight_receipt: Path | None,
    postflight_signature: Path | None,
    promotion_evidence_directory: Path | None,
) -> dict[Path, bytes]:
    if not (evidence.candidate or evidence.released):
        return {}
    if (
        release_directory is None
        or postflight_receipt is None
        or postflight_signature is None
    ):
        raise PagesError("verified Pages evidence paths are unavailable")
    release = release_directory.resolve(strict=True)
    sources = {
        "candidate-publication-scan.json": (
            release / "candidate-publication-scan.json"
        ),
        "candidate-publication-scan.json.sig": (
            release / "candidate-publication-scan.json.sig"
        ),
        "postflight-success.json": postflight_receipt.resolve(strict=True),
        "postflight-success.json.sig": postflight_signature.resolve(strict=True),
    }
    if evidence.released:
        if promotion_evidence_directory is None:
            raise PagesError("released Pages promotion evidence is unavailable")
        promotion = promotion_evidence_directory.resolve(strict=True)
        for name in (
            "final-publication-scan.json",
            "final-publication-scan.json.sig",
            "live-proof-receipt.json",
            "live-proof-receipt.json.sig",
            "promotion-receipt.json",
            "promotion-receipt.json.sig",
        ):
            sources[name] = promotion / name
    result: dict[Path, bytes] = {}
    for name, path in sources.items():
        if not path.is_file() or path.is_symlink():
            raise PagesError(f"verified Pages evidence is invalid: {name}")
        result[PAGES_EVIDENCE_RELATIVE / name] = path.read_bytes()
    return result


def _site_kind(relative: str) -> str:
    if relative == ".nojekyll":
        return "deployment-marker"
    if relative == "pages-manifest.json":
        return "manifest"
    if relative == "robots.txt":
        return "robots"
    suffix = PurePosixPath(relative).suffix.casefold()
    return {
        ".css": "css",
        ".html": "html",
        ".js": "javascript",
        ".json": "json",
        ".md": "markdown",
        ".sig": "json",
        ".svg": "svg",
        ".txt": "text",
        ".xml": "xml",
    }.get(suffix, "unknown")


def _render_pages_manifest(
    repository: Path,
    overlay: Mapping[Path, bytes],
) -> bytes:
    docs = repository / DOCS_RELATIVE
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in sorted(docs.rglob("*")):
        relative = path.relative_to(docs).as_posix()
        if relative == PAGES_MANIFEST_RELATIVE.name:
            continue
        if path.is_symlink():
            raise PagesError(f"docs/{relative}: symbolic links are forbidden")
        if not path.is_file():
            continue
        source_relative = DOCS_RELATIVE / relative
        try:
            content = overlay.get(source_relative, path.read_bytes())
        except OSError as error:
            raise PagesError(f"docs/{relative}: cannot be inventoried") from error
        kind = _site_kind(relative)
        if kind == "unknown":
            raise PagesError(f"docs/{relative}: unexpected public file type")
        seen.add(relative)
        records.append(
            {
                "kind": kind,
                "path": relative,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    for relative_path in overlay:
        if relative_path == PAGES_MANIFEST_RELATIVE:
            continue
        try:
            relative = relative_path.relative_to(DOCS_RELATIVE).as_posix()
        except ValueError as error:
            raise PagesError("generated Pages file is outside docs/") from error
        if relative not in seen:
            content = overlay[relative_path]
            records.append(
                {
                    "kind": _site_kind(relative),
                    "path": relative,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size": len(content),
                }
            )
    records.sort(key=lambda item: item["path"].encode("utf-8"))
    self_record = {
        "kind": "manifest",
        "path": "pages-manifest.json",
        "sha256": "0" * 64,
        "size": 0,
    }
    all_records = records + [self_record]
    all_records.sort(key=lambda item: item["path"].encode("utf-8"))
    manifest = {
        "base_path": PROJECT_BASE_PATH,
        "file_count": len(all_records),
        "files": all_records,
        "schema": PAGES_MANIFEST_SCHEMA,
        "self_hash": PAGES_MANIFEST_SELF_HASH,
    }
    for _attempt in range(16):
        placeholder = _json_bytes(manifest)
        size = len(placeholder)
        if self_record["size"] == size:
            break
        self_record["size"] = size
    else:
        raise PagesError("pages manifest size did not converge")
    placeholder = _json_bytes(manifest)
    self_record["sha256"] = hashlib.sha256(placeholder).hexdigest()
    result = _json_bytes(manifest)
    if len(result) != self_record["size"]:
        raise PagesError("pages manifest self record is unstable")
    return result


def build_pages(
    root: str | Path,
    *,
    released: bool = False,
    candidate: bool = False,
    final: bool = False,
    release_directory: Path | None = None,
    release_manifest: Path | None = None,
    release_manifest_sha256: str | None = None,
    release_signature: Path | None = None,
    release_trust: Path | None = None,
    checksums: Path | None = None,
    source_root: Path | None = None,
    github_attestation: Path | None = None,
    publication_attestation: Path | None = None,
    postflight_attestation: Path | None = None,
    promotion_attestation: Path | None = None,
    promotion_evidence_directory: Path | None = None,
    promotion_run_id: str | None = None,
    release_metadata: Path | None = None,
    candidate_publication_scan: Path | None = None,
    candidate_publication_scan_signature: Path | None = None,
    postflight_receipt: Path | None = None,
    postflight_signature: Path | None = None,
    promotion_receipt_sha256: str | None = None,
    release_tag: str | None = None,
) -> tuple[Path, ...]:
    """Write generated APIs, release prose, and the exact static inventory."""

    repository = Path(root).resolve(strict=True)
    evidence, verification = _verify_released_pages(
        repository,
        released=released,
        candidate=candidate,
        final=final,
        release_directory=release_directory,
        release_manifest=release_manifest,
        release_manifest_sha256=release_manifest_sha256,
        release_signature=release_signature,
        release_trust=release_trust,
        checksums=checksums,
        source_root=source_root,
        github_attestation=github_attestation,
        publication_attestation=publication_attestation,
        postflight_attestation=postflight_attestation,
        promotion_attestation=promotion_attestation,
        promotion_evidence_directory=promotion_evidence_directory,
        promotion_run_id=promotion_run_id,
        release_metadata=release_metadata,
        candidate_publication_scan=candidate_publication_scan,
        candidate_publication_scan_signature=(
            candidate_publication_scan_signature
        ),
        postflight_receipt=postflight_receipt,
        postflight_signature=postflight_signature,
        promotion_receipt_sha256=promotion_receipt_sha256,
        release_tag=release_tag,
    )
    rendered = render_generated_files(
        repository,
        release_verification=verification,
        release_tag=release_tag,
        evidence_overlay=_pages_evidence_overlay(
            evidence,
            release_directory=release_directory,
            postflight_receipt=postflight_receipt,
            postflight_signature=postflight_signature,
            promotion_evidence_directory=promotion_evidence_directory,
        ),
    )
    written: list[Path] = []
    for relative, content in sorted(rendered.items(), key=lambda item: str(item[0])):
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        written.append(destination)
    return tuple(written)


def check_pages(
    root: str | Path,
    *,
    released: bool = False,
    candidate: bool = False,
    final: bool = False,
    release_directory: Path | None = None,
    release_manifest: Path | None = None,
    release_manifest_sha256: str | None = None,
    release_signature: Path | None = None,
    release_trust: Path | None = None,
    checksums: Path | None = None,
    source_root: Path | None = None,
    github_attestation: Path | None = None,
    publication_attestation: Path | None = None,
    postflight_attestation: Path | None = None,
    promotion_attestation: Path | None = None,
    promotion_evidence_directory: Path | None = None,
    promotion_run_id: str | None = None,
    release_metadata: Path | None = None,
    candidate_publication_scan: Path | None = None,
    candidate_publication_scan_signature: Path | None = None,
    postflight_receipt: Path | None = None,
    postflight_signature: Path | None = None,
    promotion_receipt_sha256: str | None = None,
    release_tag: str | None = None,
) -> PagesCheckResult:
    """Validate generated parity and every byte in the deployable docs tree."""

    repository = Path(root).resolve(strict=True)
    errors: list[str] = []
    try:
        evidence, verification = _verify_released_pages(
            repository,
            released=released,
            candidate=candidate,
            final=final,
            release_directory=release_directory,
            release_manifest=release_manifest,
            release_manifest_sha256=release_manifest_sha256,
            release_signature=release_signature,
            release_trust=release_trust,
            checksums=checksums,
            source_root=source_root,
            github_attestation=github_attestation,
            publication_attestation=publication_attestation,
            postflight_attestation=postflight_attestation,
            promotion_attestation=promotion_attestation,
            promotion_evidence_directory=promotion_evidence_directory,
            promotion_run_id=promotion_run_id,
            release_metadata=release_metadata,
            candidate_publication_scan=candidate_publication_scan,
            candidate_publication_scan_signature=(
                candidate_publication_scan_signature
            ),
            postflight_receipt=postflight_receipt,
            postflight_signature=postflight_signature,
            promotion_receipt_sha256=promotion_receipt_sha256,
            release_tag=release_tag,
        )
        rendered = render_generated_files(
            repository,
            release_verification=verification,
            release_tag=release_tag,
            evidence_overlay=_pages_evidence_overlay(
                evidence,
                release_directory=release_directory,
                postflight_receipt=postflight_receipt,
                postflight_signature=postflight_signature,
                promotion_evidence_directory=promotion_evidence_directory,
            ),
        )
    except PagesError as error:
        return PagesCheckResult((str(error),), 0, 0, 0)
    for relative, expected in rendered.items():
        try:
            actual = (repository / relative).read_bytes()
        except OSError:
            errors.append(f"{relative.as_posix()}: generated file is missing")
            continue
        if actual != expected:
            errors.append(f"{relative.as_posix()}: generated content is stale")

    docs = repository / DOCS_RELATIVE
    file_count = 0
    total_bytes = 0
    observed_static: set[str] = set()
    observed_files: set[str] = set()
    for path in sorted(docs.rglob("*")):
        relative = path.relative_to(docs).as_posix()
        if path.is_symlink():
            errors.append(f"docs/{relative}: symbolic links are forbidden")
            continue
        if not path.is_file():
            continue
        observed_files.add(relative)
        file_count += 1
        size = path.stat().st_size
        total_bytes += size
        if size > MAX_SITE_FILE_BYTES:
            errors.append(f"docs/{relative}: exceeds the per-file size limit")
        if path.suffix.casefold() not in _ALLOWED_SITE_SUFFIXES:
            errors.append(f"docs/{relative}: unexpected public file type")
        try:
            content = path.read_bytes()
            text = content.decode("utf-8")
        except UnicodeError:
            errors.append(f"docs/{relative}: unexpected binary or non-UTF-8 data")
            continue
        except OSError:
            errors.append(f"docs/{relative}: cannot be read")
            continue
        if b"\x00" in content:
            errors.append(f"docs/{relative}: NUL bytes are forbidden")
        if relative.endswith(".map"):
            errors.append(f"docs/{relative}: source maps are forbidden")
        if any(
            part.startswith(".") and part != ".nojekyll"
            for part in PurePosixPath(relative).parts
        ):
            errors.append(f"docs/{relative}: unexpected hidden content")
        errors.extend(_privacy_errors(relative, text))
        kind = _site_kind(relative)
        if kind == "html":
            errors.extend(_html_errors(docs, path))
        elif kind == "svg":
            errors.extend(_svg_errors(path))
        elif kind == "css":
            errors.extend(_css_errors(path))
        elif kind == "json":
            errors.extend(_json_file_errors(path))
        elif kind == "xml":
            errors.extend(_xml_errors(path))
        elif kind == "javascript":
            errors.extend(_javascript_errors(path))
        elif kind == "robots" and relative != "robots.txt":
            errors.append(f"docs/{relative}: invalid robots file location")
        if relative in _EXPECTED_STATIC_FILES:
            observed_static.add(relative)
    if total_bytes > MAX_SITE_TOTAL_BYTES:
        errors.append("docs/: total deployment size exceeds the limit")
    missing_static = sorted(_EXPECTED_STATIC_FILES - observed_static)
    if missing_static:
        errors.append("docs/: missing static files: " + ", ".join(missing_static))
    unexpected_api = {
        path.name for path in (docs / "api/v1").glob("*.json")
    } - set(API_SCHEMAS)
    if unexpected_api:
        errors.append(
            "docs/api/v1/: unexpected API files: "
            + ", ".join(sorted(unexpected_api))
        )

    errors.extend(_pages_manifest_errors(docs, observed_files))
    errors.extend(_routing_file_errors(docs))
    if evidence.released:
        try:
            released_html = (docs / "index.html").read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            errors.append("docs/index.html: cannot check released wording")
        else:
            if _RELEASE_PROOF_WORDS.search(released_html):
                errors.append("docs/index.html: released page contradicts release proof")
            for name in API_SCHEMAS:
                try:
                    value = _read_json_object(docs / "api/v1" / name)
                except PagesError as error:
                    errors.append(str(error))
                    continue
                if value.get("status") not in {"released"}:
                    errors.append(f"docs/api/v1/{name}: released status is stale")
    try:
        workflows = check_workflows(repository)
    except PagesError as error:
        errors.append(str(error))
        workflow_count = 0
    else:
        errors.extend(workflows)
        workflow_count = 4
    return PagesCheckResult(
        errors=tuple(sorted(set(errors))),
        api_count=len(API_SCHEMAS),
        file_count=file_count,
        workflow_count=workflow_count,
    )


def _pages_manifest_errors(docs: Path, observed: set[str]) -> list[str]:
    path = docs / "pages-manifest.json"
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return ["docs/pages-manifest.json: cannot read exact inventory"]
    errors: list[str] = []
    if not isinstance(value, dict) or set(value) != {
        "base_path",
        "file_count",
        "files",
        "schema",
        "self_hash",
    }:
        return ["docs/pages-manifest.json: fields are invalid"]
    files = value.get("files")
    if (
        value.get("schema") != PAGES_MANIFEST_SCHEMA
        or value.get("base_path") != PROJECT_BASE_PATH
        or value.get("self_hash") != PAGES_MANIFEST_SELF_HASH
        or not isinstance(files, list)
        or value.get("file_count") != len(files)
        or _json_bytes(value) != raw
    ):
        errors.append("docs/pages-manifest.json: encoding or header is invalid")
    if not isinstance(files, list):
        return errors
    records: dict[str, dict[str, Any]] = {}
    ordered_paths: list[str] = []
    for index, item in enumerate(files):
        if not isinstance(item, dict) or set(item) != {
            "kind",
            "path",
            "sha256",
            "size",
        }:
            errors.append(
                f"docs/pages-manifest.json: file record {index} is invalid"
            )
            continue
        relative = item.get("path")
        if (
            not isinstance(relative, str)
            or not relative
            or relative in records
            or relative.startswith("/")
            or "\\" in relative
            or ".." in PurePosixPath(relative).parts
        ):
            errors.append("docs/pages-manifest.json: unsafe or duplicate path")
            continue
        if any(
            part.startswith(".") and part != ".nojekyll"
            for part in PurePosixPath(relative).parts
        ):
            errors.append(
                f"docs/pages-manifest.json: hidden path is forbidden: {relative}"
            )
        if (
            item.get("kind") != _site_kind(relative)
            or item["kind"] == "unknown"
            or not isinstance(item.get("sha256"), str)
            or _HEX_64_RE.fullmatch(item["sha256"]) is None
            or not isinstance(item.get("size"), int)
            or isinstance(item["size"], bool)
            or item["size"] < 0
        ):
            errors.append(
                f"docs/pages-manifest.json: identity is invalid: {relative}"
            )
            continue
        records[relative] = item
        ordered_paths.append(relative)
    if ordered_paths != sorted(ordered_paths, key=lambda item: item.encode("utf-8")):
        errors.append("docs/pages-manifest.json: records are not canonical")
    expected = set(records)
    if expected != observed:
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        if missing:
            errors.append(
                "docs/: inventory files are missing: " + ", ".join(missing)
            )
        if extra:
            errors.append(
                "docs/: unexpected files outside inventory: " + ", ".join(extra)
            )
    for relative, record in records.items():
        file_path = docs / relative
        try:
            content = file_path.read_bytes()
        except OSError:
            continue
        if len(content) != record["size"]:
            errors.append(f"docs/{relative}: inventory size mismatch")
            continue
        if relative == "pages-manifest.json":
            normalized = json.loads(content)
            normalized_records = normalized.get("files", [])
            self_records = [
                item
                for item in normalized_records
                if isinstance(item, dict)
                and item.get("path") == "pages-manifest.json"
            ]
            if len(self_records) != 1:
                errors.append(
                    "docs/pages-manifest.json: self record must be unique"
                )
                continue
            self_records[0]["sha256"] = "0" * 64
            digest = hashlib.sha256(_json_bytes(normalized)).hexdigest()
        else:
            digest = hashlib.sha256(content).hexdigest()
        if digest != record["sha256"]:
            errors.append(f"docs/{relative}: inventory SHA-256 mismatch")
    return errors


def _json_file_errors(path: Path) -> list[str]:
    relative = path.as_posix().split("/docs/", 1)[-1]
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return [f"docs/{relative}: invalid JSON"]
    if not isinstance(value, (dict, list)) or _json_bytes(value) != raw:
        return [f"docs/{relative}: JSON is not canonical"]
    return []


def _xml_errors(path: Path) -> list[str]:
    relative = path.as_posix().split("/docs/", 1)[-1]
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        root = ElementTree.fromstring(raw)
    except (OSError, UnicodeError, ElementTree.ParseError):
        return [f"docs/{relative}: invalid XML"]
    errors: list[str] = []
    declaration = '<?xml version="1.0" encoding="UTF-8"?>\n'
    remainder = text[len(declaration):] if text.startswith(declaration) else text
    if "<?" in remainder:
        errors.append(f"docs/{relative}: XML processing instructions are forbidden")
    if re.search(r"<!DOCTYPE|<!ENTITY", text, re.IGNORECASE):
        errors.append(f"docs/{relative}: XML entities and doctypes are forbidden")
    for element in root.iter():
        for name, value in element.attrib.items():
            if name.casefold().endswith("href") and urllib.parse.urlsplit(value).scheme:
                errors.append(f"docs/{relative}: external XML reference is forbidden")
    return errors


def _svg_errors(path: Path) -> list[str]:
    relative = path.as_posix().split("/docs/", 1)[-1]
    try:
        text = path.read_text(encoding="utf-8")
        root = ElementTree.fromstring(text)
    except (OSError, UnicodeError, ElementTree.ParseError):
        return [f"docs/{relative}: invalid SVG"]
    errors: list[str] = []
    if "<?" in text:
        errors.append(f"docs/{relative}: SVG processing instructions are forbidden")
    if root.tag.rsplit("}", 1)[-1] != "svg":
        errors.append(f"docs/{relative}: root is not SVG")
    forbidden = {
        "animate",
        "animateMotion",
        "animateTransform",
        "discard",
        "foreignObject",
        "script",
        "set",
    }
    for element in root.iter():
        local = element.tag.rsplit("}", 1)[-1]
        if local in forbidden:
            errors.append(f"docs/{relative}: active SVG element is forbidden")
        for name, value in element.attrib.items():
            local_name = name.rsplit("}", 1)[-1].casefold()
            if local_name.startswith("on"):
                errors.append(f"docs/{relative}: SVG event handler is forbidden")
            if local_name == "href" and value and not value.startswith("#"):
                errors.append(f"docs/{relative}: external SVG reference is forbidden")
            if re.search(r"url\(\s*['\"]?(?:https?:|//|data:)", value, re.I):
                errors.append(f"docs/{relative}: external SVG URL is forbidden")
    if re.search(r"<!DOCTYPE|<!ENTITY", text, re.IGNORECASE):
        errors.append(f"docs/{relative}: SVG entities and doctypes are forbidden")
    return errors


def _javascript_errors(path: Path) -> list[str]:
    relative = path.as_posix().split("/docs/", 1)[-1]
    return [f"docs/{relative}: executable JavaScript files are forbidden"]


def _privacy_errors(relative: str, text: str) -> list[str]:
    errors: list[str] = []
    for name, pattern in (
        ("absolute workstation path", _LOCAL_PATH_RE),
        ("phone-like identifier", _PHONE_RE),
        ("email-like private identifier", _EMAIL_RE),
        ("secret-like value", _SECRET_RE),
    ):
        if pattern.search(text):
            errors.append(f"docs/{relative}: contains {name}")
    if relative.endswith((".html", ".js")):
        for name, pattern in _FORBIDDEN_BROWSER_PATTERNS.items():
            if pattern.search(text):
                errors.append(f"docs/{relative}: contains forbidden {name}")
    if re.search(
        r"(?:https?|wss?)://(?:localhost|127(?:\.[0-9]+){3}|\[?::1\]?)"
        r"(?::[0-9]+)?(?:[/\"'\s]|$)",
        text,
        re.IGNORECASE,
    ):
        errors.append(f"docs/{relative}: contains a loopback request")
    return errors


def _html_errors(docs: Path, path: Path) -> list[str]:
    errors: list[str] = []
    relative = path.relative_to(docs).as_posix()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return [f"docs/{relative}: cannot parse HTML"]
    parser = _DocumentParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception as error:
        return [f"docs/{relative}: invalid HTML ({type(error).__name__})"]
    tags = [tag for tag, _attrs in parser.tags]
    if parser.doctype_count != 1 or not text.startswith("<!doctype html>\n"):
        errors.append(f"docs/{relative}: canonical HTML doctype is required")
    if parser.stack:
        parser.errors.append(
            "unclosed elements: " + ", ".join(parser.stack)
        )
    if parser.errors:
        errors.extend(
            f"docs/{relative}: malformed HTML ({error})"
            for error in parser.errors
        )
    if parser.h1_count != 1:
        errors.append(f"docs/{relative}: requires exactly one h1")
    if "main" not in tags or "header" not in tags or "footer" not in tags:
        errors.append(f"docs/{relative}: semantic landmarks are incomplete")
    if any(tag in {"form", "input", "textarea", "select", "button"} for tag in tags):
        errors.append(f"docs/{relative}: data-entry controls are forbidden")
    if any(tag in _ACTIVE_HTML_TAGS for tag in tags):
        errors.append(f"docs/{relative}: active embedded content is forbidden")
    if any(
        attribute.casefold().startswith("on")
        or attribute.casefold() in {"formaction", "srcdoc"}
        or attribute.casefold() == "hidden"
        for _tag, attribute, _value in parser.attributes
    ):
        errors.append(f"docs/{relative}: hidden or active attributes are forbidden")
    if any(
        tag == "meta"
        and attribute.casefold() == "http-equiv"
        and value.casefold() == "refresh"
        for tag, attribute, value in parser.attributes
    ):
        errors.append(f"docs/{relative}: meta refresh is forbidden")
    title = re.search(r"<title>[^<]{8,}</title>", text, re.IGNORECASE)
    description = re.search(
        r'<meta\s+name="description"\s+content="[^"]{20,}"', text, re.IGNORECASE
    )
    csp = re.search(
        r'<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"',
        text,
        re.IGNORECASE,
    )
    if title is None or description is None:
        errors.append(f"docs/{relative}: title or description metadata is missing")
    if (
        csp is None
        or "default-src 'none'" not in csp.group(1)
        or "script-src 'none'" not in csp.group(1)
        or "connect-src 'none'" not in csp.group(1)
        or "form-action 'none'" not in csp.group(1)
        or re.search(r"unsafe-(?:inline|eval)", csp.group(1), re.IGNORECASE)
    ):
        errors.append(f"docs/{relative}: restrictive CSP metadata is missing")
    if relative == "index.html":
        required_tags = {"nav", "section"}
        if not required_tags <= set(tags):
            errors.append("docs/index.html: navigation or sections are missing")
        if parser.h1_count == 1 and "main-content" not in parser.ids:
            errors.append("docs/index.html: skip-link main target is missing")
        if not re.search(
            r'<a\s+class="skip-link"\s+href="#main-content">', text
        ):
            errors.append("docs/index.html: skip link is missing")
        for token in (
            "RAPP Stack CUBBY — the whole RAPP product in one repository.",
            "One idea to public product.",
            "Owner iMessage tutorial",
            "Implemented locally",
            "Mapped / reference-only",
        ):
            if token not in text:
                errors.append(f"docs/index.html: core content is missing: {token}")
        prompt_ids = re.findall(r'data-prompt-id="(prompt-[0-9]{2})"', text)
        if prompt_ids != [f"prompt-{value:02d}" for value in range(1, 11)]:
            errors.append("docs/index.html: showcase prompt list is not exact")
        if (
            f'{REPOSITORY_URL}/blob/main/docs/operations/'
            "IMESSAGE_ONBOARDING.md"
        ) not in text:
            errors.append("docs/index.html: fresh-fork tutorial link is missing")
        for property_name in ("og:title", "og:description", "og:url", "og:type"):
            if f'property="{property_name}"' not in text:
                errors.append(
                    f"docs/index.html: Open Graph metadata missing {property_name}"
                )
    if relative == "404.html":
        for target in (
            f"{PROJECT_BASE_PATH}assets/favicon.svg",
            f"{PROJECT_BASE_PATH}assets/styles.css",
            PROJECT_BASE_PATH,
        ):
            if f'"{target}"' not in text:
                errors.append(
                    f"docs/404.html: deep-route-safe path is missing: {target}"
                )
    for tag, attribute, target in parser.links:
        errors.extend(
            _link_errors(
                docs,
                path,
                parser.ids,
                tag=tag,
                attribute=attribute,
                target=target,
            )
        )
    return errors


def _link_errors(
    docs: Path,
    source: Path,
    ids: set[str],
    *,
    tag: str,
    attribute: str,
    target: str,
) -> list[str]:
    relative = source.relative_to(docs).as_posix()
    errors: list[str] = []
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme:
        if parsed.scheme != "https":
            return [f"docs/{relative}: non-HTTPS link is forbidden: {target}"]
        allowed = (
            target.startswith(REPOSITORY_URL)
            or target.startswith("https://docs.github.com/")
            or target.startswith("https://learn.microsoft.com/")
            or target.startswith(PAGES_URL)
        )
        if not allowed:
            errors.append(f"docs/{relative}: external link is not allowlisted")
        if attribute == "src" or (
            tag == "link"
            and target.endswith((".css", ".js"))
        ):
            errors.append(f"docs/{relative}: external executable resource")
        if target.startswith(f"{REPOSITORY_URL}/blob/main/"):
            repository = docs.parent
            linked = target.removeprefix(f"{REPOSITORY_URL}/blob/main/")
            if not (repository / linked).is_file():
                errors.append(
                    f"docs/{relative}: repository document link is missing: {linked}"
                )
        return errors
    if target.startswith("//"):
        return [f"docs/{relative}: protocol-relative path is forbidden"]
    local_path = urllib.parse.unquote(parsed.path)
    if target.startswith("/"):
        if not local_path.startswith(PROJECT_BASE_PATH):
            return [
                f"docs/{relative}: root path must use {PROJECT_BASE_PATH}"
            ]
        local_path = local_path.removeprefix(PROJECT_BASE_PATH)
    if not local_path:
        if parsed.fragment and parsed.fragment not in ids:
            errors.append(
                f"docs/{relative}: missing fragment target #{parsed.fragment}"
            )
        return errors
    pure = PurePosixPath(local_path)
    if ".." in pure.parts:
        return [f"docs/{relative}: parent-relative Pages link is forbidden"]
    destination = (
        docs / pure
        if target.startswith("/")
        else source.parent / pure
    )
    if local_path.endswith("/") or destination.is_dir():
        destination = destination / "index.html"
    try:
        resolved = destination.resolve()
        root = docs.resolve()
    except OSError:
        return [f"docs/{relative}: cannot resolve local link {target}"]
    if resolved != root and root not in resolved.parents:
        errors.append(f"docs/{relative}: local link escapes docs")
    elif not resolved.is_file():
        errors.append(f"docs/{relative}: missing local link {target}")
    elif parsed.fragment and resolved.suffix == ".html":
        linked_parser = _DocumentParser()
        try:
            linked_parser.feed(resolved.read_text(encoding="utf-8"))
        except (OSError, UnicodeError):
            errors.append(f"docs/{relative}: linked HTML cannot be read")
        else:
            if parsed.fragment not in linked_parser.ids:
                errors.append(
                    f"docs/{relative}: linked fragment is missing: {target}"
                )
    return errors


def _css_errors(path: Path) -> list[str]:
    relative = path.as_posix().split("/docs/", 1)[-1]
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return [f"docs/{relative}: cannot be read"]
    errors: list[str] = []
    if relative == "assets/styles.css":
        for token in (
            ":focus-visible",
            "@media (prefers-reduced-motion: reduce)",
            "@media print",
        ):
            if token not in text:
                errors.append(f"docs/{relative}: missing {token}")
    if re.search(r"@import\b", text, re.IGNORECASE):
        errors.append(f"docs/{relative}: CSS imports are forbidden")
    for match in re.finditer(r"url\(\s*(['\"]?)(.*?)\1\s*\)", text, re.I):
        target = match.group(2).strip()
        parsed = urllib.parse.urlsplit(target)
        if (
            parsed.scheme
            or target.startswith("//")
            or target.casefold().startswith(("data:", "javascript:"))
        ):
            errors.append(f"docs/{relative}: external CSS URLs are forbidden")
    return errors


def _routing_file_errors(docs: Path) -> list[str]:
    errors: list[str] = []
    try:
        robots = (docs / "robots.txt").read_text(encoding="utf-8")
        sitemap = (docs / "sitemap.xml").read_bytes()
        nojekyll = (docs / ".nojekyll").read_bytes()
    except (OSError, UnicodeError):
        return ["docs/: robots, sitemap, or .nojekyll cannot be read"]
    if robots != f"User-agent: *\nAllow: /\nSitemap: {PAGES_URL}sitemap.xml\n":
        errors.append("docs/robots.txt: content is not canonical")
    if sitemap != SITEMAP_BYTES:
        errors.append("docs/sitemap.xml: bytes are not canonical")
    if nojekyll:
        errors.append("docs/.nojekyll: file must be empty")
    return errors


def check_pages_artifact(root: str | Path, artifact: str | Path) -> tuple[str, ...]:
    """Verify that a produced Pages tar is exactly the checked docs inventory."""

    repository = Path(root).resolve(strict=True)
    archive = Path(artifact).resolve(strict=True)
    errors: list[str] = []
    members: dict[str, bytes] = {}
    try:
        with tarfile.open(archive, mode="r:*") as value:
            for member in value.getmembers():
                name = member.name
                while name.startswith("./"):
                    name = name[2:]
                name = name.rstrip("/")
                if not name:
                    continue
                pure = PurePosixPath(name)
                if (
                    member.issym()
                    or member.islnk()
                    or member.isdev()
                    or member.isfifo()
                    or name.startswith("/")
                    or ".." in pure.parts
                ):
                    errors.append(f"Pages artifact has unsafe member: {name}")
                    continue
                if member.isdir():
                    continue
                if not member.isfile() or name in members:
                    errors.append(f"Pages artifact has invalid member: {name}")
                    continue
                if member.size > MAX_SITE_FILE_BYTES:
                    errors.append(f"Pages artifact member is too large: {name}")
                    continue
                extracted = value.extractfile(member)
                if extracted is None:
                    errors.append(f"Pages artifact member cannot be read: {name}")
                    continue
                content = extracted.read(MAX_SITE_FILE_BYTES + 1)
                if len(content) != member.size:
                    errors.append(f"Pages artifact member size changed: {name}")
                    continue
                members[name] = content
    except (OSError, tarfile.TarError):
        return ("Pages artifact cannot be read",)
    manifest_bytes = members.get("pages-manifest.json")
    if manifest_bytes is None:
        errors.append("Pages artifact omits pages-manifest.json")
        return tuple(sorted(set(errors)))
    try:
        manifest = json.loads(manifest_bytes)
        records = manifest["files"]
    except (UnicodeError, json.JSONDecodeError, KeyError, TypeError):
        errors.append("Pages artifact inventory is invalid")
        return tuple(sorted(set(errors)))
    if not isinstance(records, list):
        errors.append("Pages artifact inventory records are invalid")
        return tuple(sorted(set(errors)))
    expected = {
        item.get("path")
        for item in records
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    if len(expected) != len(records) or set(members) != expected:
        errors.append("Pages artifact file set does not match exact inventory")
    docs = repository / DOCS_RELATIVE
    for item in records:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("path"), str)
            or not isinstance(item.get("size"), int)
            or not isinstance(item.get("sha256"), str)
        ):
            errors.append("Pages artifact inventory record is invalid")
            continue
        name = item["path"]
        content = members.get(name)
        if content is None:
            continue
        if len(content) != item["size"]:
            errors.append(f"Pages artifact inventory size mismatch: {name}")
        if name == "pages-manifest.json":
            normalized = json.loads(content)
            self_records = [
                record
                for record in normalized.get("files", [])
                if isinstance(record, dict)
                and record.get("path") == "pages-manifest.json"
            ]
            if len(self_records) == 1:
                self_records[0]["sha256"] = "0" * 64
                digest = hashlib.sha256(_json_bytes(normalized)).hexdigest()
            else:
                digest = ""
        else:
            digest = hashlib.sha256(content).hexdigest()
        if digest != item["sha256"]:
            errors.append(f"Pages artifact inventory hash mismatch: {name}")
        try:
            source = (docs / name).read_bytes()
        except OSError:
            errors.append(f"Pages source file is unavailable: {name}")
            continue
        if source != content:
            errors.append(f"Pages artifact bytes differ from docs: {name}")
    if sum(len(content) for content in members.values()) > MAX_SITE_TOTAL_BYTES:
        errors.append("Pages artifact exceeds the total size limit")
    return tuple(sorted(set(errors)))


def check_workflows(root: str | Path) -> tuple[str, ...]:
    """Validate pinned actions, events, permissions, and release behavior."""

    repository = Path(root).resolve(strict=True)
    lock = _read_json_object(repository / ACTION_LOCK_RELATIVE)
    if lock.get("schema") != "rapp-github-actions-lock/1.0":
        raise PagesError("GITHUB_ACTIONS_LOCK.json schema is invalid")
    actions = lock.get("actions")
    if not isinstance(actions, list):
        raise PagesError("GITHUB_ACTIONS_LOCK.json actions are invalid")
    pins = {
        item.get("uses"): (item.get("commit"), item.get("tag"))
        for item in actions
        if isinstance(item, dict) and isinstance(item.get("uses"), str)
    }
    workflow_dir = repository / ".github/workflows"
    paths = sorted(workflow_dir.glob("*.yml"))
    expected_names = ["ci.yml", "pages.yml", "promote.yml", "release.yml"]
    if [path.name for path in paths] != expected_names:
        return (
            "workflow file set must be exactly ci.yml, pages.yml, promote.yml, release.yml",
        )
    errors: list[str] = []
    uses_seen: set[str] = set()
    for path in paths:
        if path.is_symlink() or not path.is_file():
            errors.append(f".github/workflows/{path.name}: must be a regular file")
            continue
        text = path.read_text(encoding="utf-8")
        if "macos-15-arm64" in text:
            errors.append(f"{path.name}: unsupported runner label is forbidden")
        if re.search(r"(?m)^\s*cache:\s*false\s*$", text):
            errors.append(f"{path.name}: setup-python cache false is not an input")
        if "pull_request_target:" in text:
            errors.append(f"{path.name}: pull_request_target is forbidden")
        if re.search(r"(?m)^\s*(?:repository_dispatch|issue_comment):", text):
            errors.append(f"{path.name}: dangerous event is forbidden")
        for line in text.splitlines():
            if "${{ inputs." in line and re.fullmatch(
                r"\s+[A-Z][A-Z0-9_]*:\s*\$\{\{\s*inputs\."
                r"[A-Za-z0-9_]+\s*\}\}\s*",
                line,
            ) is None:
                errors.append(
                    f"{path.name}: workflow inputs may enter shell only through env"
                )
        for match in re.finditer(
            r"(?m)^\s*uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
            r"@([0-9a-f]{40})(?:\s+#\s*(v[0-9]+\.[0-9]+\.[0-9]+))?\s*$",
            text,
        ):
            uses, commit, tag = match.groups()
            uses_seen.add(uses)
            if pins.get(uses) != (commit, tag):
                errors.append(f"{path.name}: action pin does not match lock: {uses}")
        all_uses = re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", text)
        matched_uses = re.findall(
            r"(?m)^\s*uses:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
            r"@[0-9a-f]{40}(?:\s+#\s*v[0-9]+\.[0-9]+\.[0-9]+)?\s*$",
            text,
        )
        if len(all_uses) != len(matched_uses):
            errors.append(f"{path.name}: every action must use a full SHA and tag comment")
        if "persist-credentials: false" not in text:
            errors.append(f"{path.name}: checkout credentials must not persist")
        if f"runs-on: {lock.get('runner', {}).get('label')}" not in text:
            errors.append(f"{path.name}: runner does not match the action lock")
    missing_pins = set(pins) - uses_seen
    if missing_pins:
        errors.append("locked actions are unused: " + ", ".join(sorted(missing_pins)))

    ci = (workflow_dir / "ci.yml").read_text(encoding="utf-8")
    if "permissions:\n  contents: read" not in ci:
        errors.append("ci.yml: permissions must be contents: read only")
    if "secrets." in ci:
        errors.append("ci.yml: PR-capable workflow must not reference secrets")
    for token in (
        "scripts/check-toolchain.sh",
        "scripts/context-check.sh",
        "scripts/check.sh",
        "scripts/pages-check.sh",
        "requirements-ci.lock",
        "RAPP_SOURCE_REVISION: ${{ github.sha }}",
        "build-one",
        "build-two",
        "diff -rq",
        "check-artifact",
    ):
        if token not in ci:
            errors.append(f"ci.yml: missing deterministic gate: {token}")

    pages = (workflow_dir / "pages.yml").read_text(encoding="utf-8")
    for token in (
        "release_commit:",
        "release_manifest_sha256:",
        "contents: read",
        "attestations: read",
        "pages: write",
        "id-token: write",
        "environment:",
        "name: github-pages",
        "path: ./docs",
        "include-hidden-files: true",
        "preserving the trusted released site",
        "scripts/resolve-release-tag.sh",
        "scripts/verify-github-attestations.sh",
        "scripts/pages-build.sh",
        "scripts/pages-check.sh",
        "--final",
        "--release-manifest-sha256",
        "--release-signature",
        "--release-trust",
        "--source-root",
        "--github-attestation",
        "--publication-attestation",
        "--candidate-publication-scan",
        "--postflight-receipt",
        "--promotion-receipt-sha256",
        "--promotion-evidence-directory",
        "--promotion-run-id",
        "check-artifact",
    ):
        if token not in pages:
            errors.append(f"pages.yml: missing Pages requirement: {token}")
    if re.search(r"(?m)^\s*path:\s*\.(?:/)?\s*$", pages):
        errors.append("pages.yml: only docs/ may be uploaded")
    if re.search(r"--pattern\s+['\"]?[^ \n]*[*?\[]", pages):
        errors.append("pages.yml: release downloads must not use wildcard patterns")
    if "gh release download" not in pages or "--dir" not in pages:
        errors.append("pages.yml: complete release download is missing")

    release = (workflow_dir / "release.yml").read_text(encoding="utf-8")
    for token in (
        "workflow_dispatch:",
        "name: release",
        "contents: write",
        "checks: read",
        "attestations: write",
        "id-token: write",
        "scripts/prepare-release.sh",
        "scripts/resolve-release-tag.sh",
        "scripts/check-toolchain.sh",
        "scripts/check.sh",
        "scripts/pages-check.sh",
        "scripts/fetch-dependencies.sh",
        "diff -rq",
        "hatch.sh",
        "check-runs",
        '.conclusion == "success"',
        "gh release create",
        "--verify-tag",
        "--prerelease",
        "scripts/postflight-release.sh",
        'refs/tags/${INPUT_TAG}',
        'test "${DISPATCH_SHA}" = "${INPUT_COMMIT}"',
        "candidate-publication-scan.json",
        "postflight-success.json",
    ):
        if token not in release:
            errors.append(f"release.yml: missing exact-release behavior: {token}")
    if re.search(r"\bgit\s+(?:commit|push)\b", release):
        errors.append("release.yml: follow-up source commits/pushes are forbidden")
    if re.search(r"(?m)^\s+push:\s*$", release) or re.search(
        r"(?m)^\s+tags:\s*$", release
    ):
        errors.append("release.yml: automatic tag/push release triggers are forbidden")
    promotion = (workflow_dir / "promote.yml").read_text(encoding="utf-8")
    for token in (
        "name: promotion",
        "scripts/promote-release.sh",
        "refs/tags/${INPUT_TAG}",
        "DISPATCH_SHA",
        "scripts/verify-github-attestations.sh",
        "final-publication-scan.json",
        "live-proof-receipt.json",
        "promotion-receipt.json",
        "actions: write",
        "attestations: write",
        "id-token: write",
        "gh workflow run pages.yml",
        '--ref "${RELEASE_TAG}"',
        "final-promotion-evidence",
    ):
        if token not in promotion:
            errors.append(f"promote.yml: missing final-promotion behavior: {token}")
    if re.search(r"\bgit\s+(?:commit|push)\b", promotion):
        errors.append("promote.yml: source commits and pushes are forbidden")
    if "gh release upload" in release or "gh release upload" in promotion:
        errors.append("immutable published releases must not receive later assets")
    if "secrets." in pages or "secrets." in ci:
        errors.append("PR/Pages workflows must not reference protected secrets")
    if release.count("scripts/resolve-release-tag.sh") < 2:
        errors.append("release.yml: remote tag must be resolved before and after build")
    if re.search(r"\b(?:gh release create|gh release download)[^\n]*[*?\[]", release):
        errors.append("release.yml: release commands must use explicit assets")
    combined_release = release + "\n" + promotion
    for filename, _label, _kind, _minimum_stage in DOWNLOAD_ASSETS:
        if filename not in combined_release:
            errors.append(
                f"release/promotion workflows omit explicit asset: {filename}"
            )
    return tuple(sorted(set(errors)))


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "check", "check-artifact"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--released", action="store_true")
    parser.add_argument("--candidate", action="store_true")
    parser.add_argument("--final", action="store_true")
    parser.add_argument("--release-directory", type=Path)
    parser.add_argument("--release-manifest", type=Path)
    parser.add_argument("--release-manifest-sha256")
    parser.add_argument("--release-signature", type=Path)
    parser.add_argument("--release-trust", type=Path)
    parser.add_argument("--checksums", type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--github-attestation", type=Path)
    parser.add_argument("--publication-attestation", type=Path)
    parser.add_argument("--postflight-attestation", type=Path)
    parser.add_argument("--promotion-attestation", type=Path)
    parser.add_argument("--promotion-evidence-directory", type=Path)
    parser.add_argument("--promotion-run-id")
    parser.add_argument("--release-metadata", type=Path)
    parser.add_argument("--candidate-publication-scan", type=Path)
    parser.add_argument("--candidate-publication-scan-signature", type=Path)
    parser.add_argument("--postflight-receipt", type=Path)
    parser.add_argument("--postflight-signature", type=Path)
    parser.add_argument("--promotion-receipt-sha256")
    parser.add_argument("--release-tag")
    parser.add_argument("--artifact", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _build_argument_parser().parse_args(argv)
    try:
        if arguments.command == "check-artifact":
            if arguments.artifact is None:
                raise PagesError("check-artifact requires --artifact")
            errors = check_pages_artifact(arguments.root, arguments.artifact)
            if errors:
                for error in errors:
                    print(f"error: {error}", file=sys.stderr)
                return 1
            print("PASS Pages artifact: exact static inventory")
            return 0
        common = {
            "released": arguments.released,
            "candidate": arguments.candidate,
            "final": arguments.final,
            "release_directory": arguments.release_directory,
            "release_manifest": arguments.release_manifest,
            "release_manifest_sha256": arguments.release_manifest_sha256,
            "release_signature": arguments.release_signature,
            "release_trust": arguments.release_trust,
            "checksums": arguments.checksums,
            "source_root": arguments.source_root,
            "github_attestation": arguments.github_attestation,
            "publication_attestation": arguments.publication_attestation,
            "postflight_attestation": arguments.postflight_attestation,
            "promotion_attestation": arguments.promotion_attestation,
            "promotion_evidence_directory": (
                arguments.promotion_evidence_directory
            ),
            "promotion_run_id": arguments.promotion_run_id,
            "release_metadata": arguments.release_metadata,
            "candidate_publication_scan": arguments.candidate_publication_scan,
            "candidate_publication_scan_signature": (
                arguments.candidate_publication_scan_signature
            ),
            "postflight_receipt": arguments.postflight_receipt,
            "postflight_signature": arguments.postflight_signature,
            "promotion_receipt_sha256": arguments.promotion_receipt_sha256,
            "release_tag": arguments.release_tag,
        }
        if arguments.command == "build":
            written = build_pages(arguments.root, **common)
            print(f"PASS Pages build: {len(written)} generated files")
            return 0
        result = check_pages(arguments.root, **common)
    except (OSError, PagesError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    if result.ok:
        print(
            "PASS Pages check: "
            f"{result.file_count} files; {result.api_count} APIs; "
            f"{result.workflow_count} workflows"
        )
        return 0
    for error in result.errors:
        print(f"error: {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
