"""Command-line interface for repository checks and the isolated runtime."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Sequence

from .constants import DISTRIBUTION_NAME, __version__
from .errors import RappStackCubbyError
from .paths import find_repository_root
from .runtime.config import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_PROVIDER_TIMEOUT,
    DEFAULT_REQUEST_TIMEOUT,
    RuntimeConfig,
)
from .verification import census_summary, verify_repository


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=DISTRIBUTION_NAME,
        description="Verify the CUBBY or run its isolated loopback runtime.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("version", help="print the development version")

    verify_parser = subparsers.add_parser(
        "verify", help="validate repository contracts"
    )
    _add_root_argument(verify_parser)
    verify_parser.add_argument(
        "--json", action="store_true", help="emit structured JSON"
    )

    census_parser = subparsers.add_parser(
        "census", help="summarize the validated source census"
    )
    _add_root_argument(census_parser)
    census_parser.add_argument(
        "--json", action="store_true", help="emit structured JSON"
    )

    refresh_census_parser = subparsers.add_parser(
        "refresh-census",
        help="write an authenticated candidate census without promotion",
    )
    _add_root_argument(refresh_census_parser)
    refresh_census_parser.add_argument("--owner", default="kody-w")
    refresh_census_parser.add_argument(
        "--cutoff",
        required=True,
        help="inclusive exact UTC RFC3339 repository-existence cutoff",
    )
    refresh_census_parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="explicit repository-local candidate JSON path",
    )

    context_parser = subparsers.add_parser(
        "context", help="summarize the validated repository-local RAPP context"
    )
    _add_root_argument(context_parser)
    context_parser.add_argument(
        "--json", action="store_true", help="emit structured JSON"
    )

    doctor_parser = subparsers.add_parser(
        "doctor",
        help="check explicit development, live, or iMessage readiness",
    )
    _add_root_argument(doctor_parser)
    for flag in (
        "python",
        "work-dir",
        "dependency-cache",
        "install-dir",
        "controller-dir",
    ):
        doctor_parser.add_argument(
            f"--{flag}", required=True, type=Path
        )
    doctor_parser.add_argument("--live", action="store_true")
    doctor_parser.add_argument("--model")
    doctor_parser.add_argument("--github-token-file", type=Path)
    doctor_parser.add_argument("--imessage", action="store_true")
    doctor_parser.add_argument("--imessage-config", type=Path)
    doctor_parser.add_argument("--json", action="store_true")

    demo_parser = subparsers.add_parser(
        "demo",
        help="run the complete offline signed development product journey",
    )
    _add_root_argument(demo_parser)
    for flag in (
        "python",
        "work-dir",
        "dependency-cache",
        "install-dir",
        "controller-dir",
        "receipt",
    ):
        demo_parser.add_argument(f"--{flag}", required=True, type=Path)
    demo_parser.add_argument(
        "--source-date-epoch", type=int, default=1700000000
    )
    demo_parser.add_argument("--cleanup", action="store_true")
    demo_parser.add_argument("--json", action="store_true")

    command_manifest_parser = subparsers.add_parser(
        "command-manifest",
        help="write or validate the generated argparse command manifest",
    )
    _add_root_argument(command_manifest_parser)
    command_manifest_parser.add_argument("--check", action="store_true")
    command_manifest_parser.add_argument(
        "--check-docs", action="store_true"
    )

    installed_attestation_parser = subparsers.add_parser(
        "attest-installed",
        help="run the signed offline SelfTest against installed bytes",
    )
    installed_attestation_parser.add_argument(
        "--install-root", required=True, type=Path
    )
    installed_attestation_parser.add_argument(
        "--host-python", required=True, type=Path
    )
    installed_attestation_parser.add_argument(
        "--controller-dir", required=True, type=Path
    )
    installed_attestation_parser.add_argument(
        "--receipt", required=True, type=Path
    )

    pages_build_parser = subparsers.add_parser(
        "pages-build", help="generate deterministic static Pages data"
    )
    _add_root_argument(pages_build_parser)
    _add_pages_release_arguments(pages_build_parser)

    pages_check_parser = subparsers.add_parser(
        "pages-check", help="validate the complete static Pages surface"
    )
    _add_root_argument(pages_check_parser)
    _add_pages_release_arguments(pages_check_parser)

    serve_parser = subparsers.add_parser(
        "serve", help="serve the isolated runtime on loopback"
    )
    serve_parser.add_argument("--soul", required=True, type=Path)
    serve_parser.add_argument(
        "--agents-dir",
        required=True,
        action="append",
        type=Path,
        help="trusted local agents directory (repeatable)",
    )
    serve_parser.add_argument("--data-dir", required=True, type=Path)
    serve_parser.add_argument("--instance-id", required=True)
    serve_parser.add_argument(
        "--root",
        required=True,
        type=Path,
        help="explicit source/product root exposed to actual agents",
    )
    serve_parser.add_argument(
        "--principal",
        required=True,
        help="isolated principal namespace for this dedicated process",
    )
    serve_parser.add_argument("--host", default=DEFAULT_HOST)
    serve_parser.add_argument("--port", default=DEFAULT_PORT, type=int)
    serve_parser.add_argument(
        "--model",
        help=(
            "exact provider model; omitted only for the deterministic "
            "controller-only route"
        ),
    )
    serve_parser.add_argument(
        "--attestation-mode",
        choices=("offline-self-test",),
        help="explicit offline signed-child SelfTest provider mode",
    )
    serve_parser.add_argument(
        "--generated-agents-dir",
        type=Path,
        help="optional private generated-agent directory",
    )
    serve_parser.add_argument(
        "--allow-agent-writes",
        action="store_true",
        help="enable guarded Memory and AgentFactory writes",
    )
    serve_parser.add_argument(
        "--imessage-status",
        type=Path,
        help="optional mode-0600 redacted iMessage status file",
    )
    serve_parser.add_argument(
        "--request-timeout",
        default=DEFAULT_REQUEST_TIMEOUT,
        type=float,
    )
    serve_parser.add_argument(
        "--provider-timeout",
        default=DEFAULT_PROVIDER_TIMEOUT,
        type=float,
    )
    serve_parser.add_argument(
        "--twin-rappid",
        "--signed-ingress-twin-rappid",
        dest="twin_rappid",
    )
    serve_parser.add_argument(
        "--child-private-key",
        "--signed-ingress-child-private-key",
        dest="child_private_key",
        type=Path,
    )
    serve_parser.add_argument(
        "--paired-controller-public-jwk",
        "--signed-ingress-controller-public-jwk",
        dest="paired_controller_public_jwk",
        type=Path,
    )
    serve_parser.add_argument(
        "--paired-controller-rappid",
        "--signed-ingress-controller-rappid",
        dest="paired_controller_rappid",
    )
    serve_parser.add_argument(
        "--replay-db",
        "--signed-ingress-replay-db",
        dest="replay_db",
        type=Path,
    )
    serve_parser.add_argument(
        "--signed-ingress-freshness-seconds",
        type=int,
        default=300,
    )
    serve_parser.add_argument(
        "--signed-ingress-key-epoch",
        type=int,
        default=1,
        help="current monotonic child transport key epoch",
    )
    serve_parser.add_argument(
        "--signed-only",
        action="store_true",
        help="reject every unsigned plain-chat request",
    )
    serve_parser.add_argument(
        "--controller-route",
        action="store_true",
        help="enable the exact deterministic controller route through /chat",
    )
    serve_parser.add_argument(
        "--controller-loadout-root",
        type=Path,
        help="verified controller-only loadout required by --controller-route",
    )
    serve_parser.add_argument(
        "--auth-token-file",
        type=Path,
        help="explicit mode-0600 32-byte bearer token for local HTTP IPC",
    )
    serve_parser.add_argument(
        "--github-token-file",
        type=Path,
        help="explicit private mode-0600 GitHub OAuth JSON for Copilot",
    )

    health_parser = subparsers.add_parser(
        "health", help="query a local isolated-runtime health endpoint"
    )
    health_parser.add_argument("url", nargs="?")
    health_parser.add_argument("--url", dest="url_option")
    health_parser.add_argument("--timeout", type=float, default=5.0)
    health_parser.add_argument("--auth-token-file", type=Path)

    models_parser = subparsers.add_parser(
        "models",
        aliases=["provider-preflight"],
        help="list entitled chat-completions models and validate a selection",
    )
    models_parser.add_argument(
        "--model",
        help="exact model identifier to validate against the live catalog",
    )
    models_parser.add_argument(
        "--timeout", type=float, default=DEFAULT_PROVIDER_TIMEOUT
    )
    models_parser.add_argument("--github-token-file", type=Path)
    models_parser.add_argument(
        "--json", action="store_true", help="emit structured JSON"
    )

    login_parser = subparsers.add_parser(
        "provider-login",
        help="create an explicit private Copilot-compatible token file",
    )
    login_parser.add_argument("--token-file", required=True, type=Path)
    login_parser.add_argument("--timeout", type=float, default=900.0)
    login_parser.add_argument("--json", action="store_true")

    refresh_parser = subparsers.add_parser(
        "provider-refresh",
        help="refresh an explicit private provider token file",
    )
    refresh_parser.add_argument("--token-file", required=True, type=Path)
    refresh_parser.add_argument(
        "--timeout", type=float, default=DEFAULT_PROVIDER_TIMEOUT
    )
    refresh_parser.add_argument("--json", action="store_true")

    smoke_parser = subparsers.add_parser(
        "provider-smoke",
        help="run one content-free live completion and tool loop",
    )
    smoke_parser.add_argument("--model", required=True)
    smoke_parser.add_argument("--github-token-file", required=True, type=Path)
    smoke_parser.add_argument(
        "--timeout", type=float, default=DEFAULT_PROVIDER_TIMEOUT
    )
    smoke_parser.add_argument("--json", action="store_true")

    loadout_parser = subparsers.add_parser(
        "controller-loadout",
        help="build the verified controller-only loadout in an external directory",
    )
    _add_root_argument(loadout_parser)
    loadout_parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="explicit absolute external output directory",
    )

    auth_parser = subparsers.add_parser(
        "controller-auth",
        help="atomically create or verify the private controller bearer token",
    )
    auth_parser.add_argument("--private-dir", required=True, type=Path)
    auth_parser.add_argument("--verify-only", action="store_true")

    controller_parser = subparsers.add_parser(
        "controller",
        help="send one deterministic controller request through POST /chat",
    )
    controller_parser.add_argument(
        "--url",
        default=f"http://{DEFAULT_HOST}:{DEFAULT_PORT}/chat",
        help="explicit local /chat URL",
    )
    controller_parser.add_argument("--timeout", type=float, default=30.0)
    controller_parser.add_argument(
        "--auth-token-file",
        required=True,
        type=Path,
    )
    controller_parser.add_argument("--idempotency-key", required=True)
    controller_actions = controller_parser.add_subparsers(
        dest="controller_action", required=True
    )
    controller_actions.add_parser("inspect")
    verify_controller = controller_actions.add_parser("verify")
    verify_controller.add_argument("--repository-url")
    verify_controller.add_argument("--commit")
    adopt_controller = controller_actions.add_parser("adopt")
    adopt_controller.add_argument(
        "--install-root", required=True, type=Path
    )
    adopt_controller.add_argument("--model")
    adopt_controller.add_argument(
        "--attestation-mode",
        choices=("offline-self-test",),
    )
    adopt_controller.add_argument(
        "--trusted-development",
        action="store_true",
        help="adopt only a verified signed development install",
    )
    hatch_controller = controller_actions.add_parser("hatch")
    hatch_controller.add_argument("--repository-url", required=True)
    hatch_controller.add_argument("--commit", required=True)
    hatch_controller.add_argument("--expected-tree-digest")
    hatch_controller.add_argument("--product-rappid")
    for name in (
        "start",
        "status",
        "self-test",
        "stop",
        "archive",
        "unarchive",
        "rotate",
        "purge",
    ):
        action_parser = controller_actions.add_parser(name)
        action_parser.add_argument("--rappid", required=True)
        if name == "start":
            action_parser.add_argument("--model", required=True)
            action_parser.add_argument(
                "--github-token-file",
                type=Path,
            )
            action_parser.add_argument(
                "--attestation-mode",
                choices=("offline-self-test",),
            )
            action_parser.add_argument("--port", type=int)
        if name == "purge":
            action_parser.add_argument("--confirmation", required=True)

    source_manifest_parser = subparsers.add_parser(
        "source-manifest",
        help="write or verify the self-excluding product source manifest",
    )
    _add_root_argument(source_manifest_parser)
    source_manifest_parser.add_argument(
        "--check", action="store_true", help="verify without writing"
    )

    fetch_parser = subparsers.add_parser(
        "fetch-dependencies",
        help="fetch only locked inert dependency archives",
    )
    _add_root_argument(fetch_parser)
    fetch_parser.add_argument("--cache", required=True, type=Path)

    build_release_parser = subparsers.add_parser(
        "build",
        help="build the deterministic Store ZIP and cubby egg",
    )
    _add_root_argument(build_release_parser)
    build_release_parser.add_argument(
        "--dependency-cache", required=True, type=Path
    )
    build_release_parser.add_argument("--output", required=True, type=Path)
    build_release_parser.add_argument(
        "--source-date-epoch", required=True, type=int
    )
    build_release_parser.add_argument("--source-revision", required=True)
    build_release_parser.add_argument("--signing-key", type=Path)
    build_release_parser.add_argument("--signing-trust", type=Path)

    artifact_parser = subparsers.add_parser(
        "verify-artifact",
        help="verify every member of a Store ZIP or cubby egg",
    )
    artifact_parser.add_argument("--artifact", required=True, type=Path)
    artifact_parser.add_argument("--sha256")

    release_verify_parser = subparsers.add_parser(
        "verify-release",
        help="verify the pinned signed release manifest and exact asset set",
    )
    release_verify_parser.add_argument(
        "--release-manifest", required=True, type=Path
    )
    release_verify_parser.add_argument(
        "--release-manifest-sha256", required=True
    )
    release_verify_parser.add_argument("--trust", required=True, type=Path)
    release_verify_parser.add_argument("--signature", type=Path)
    release_verify_parser.add_argument("--checksums", type=Path)
    release_verify_parser.add_argument("--source-root", type=Path)
    release_verify_parser.add_argument("--github-attestation", type=Path)

    publication_scan_parser = subparsers.add_parser(
        "publication-scan",
        help="scan explicit publication candidates without executing them",
    )
    _add_root_argument(publication_scan_parser)
    publication_scan_parser.add_argument("--policy", type=Path)
    publication_scan_parser.add_argument("--pages", type=Path)
    publication_scan_parser.add_argument("--release-assets", type=Path)
    publication_scan_parser.add_argument("--public-redownload", type=Path)
    publication_scan_parser.add_argument(
        "--actions-log",
        action="append",
        default=[],
        metavar="RUN_ID=ABSOLUTE_ZIP",
    )
    publication_scan_parser.add_argument(
        "--phase",
        choices=("candidate", "development", "final"),
        default="development",
    )
    publication_scan_parser.add_argument(
        "--timestamp", default="1970-01-01T00:00:00Z"
    )
    publication_scan_parser.add_argument(
        "--output", required=True, type=Path
    )
    publication_scan_parser.add_argument("--signing-key", type=Path)
    publication_scan_parser.add_argument("--signing-trust", type=Path)
    publication_scan_parser.add_argument("--signature-output", type=Path)

    publication_verify_parser = subparsers.add_parser(
        "verify-publication-scan",
        help="verify a publication scan receipt and detached release signature",
    )
    publication_verify_parser.add_argument(
        "--receipt", required=True, type=Path
    )
    publication_verify_parser.add_argument(
        "--policy", required=True, type=Path
    )
    publication_verify_parser.add_argument(
        "--phase",
        required=True,
        choices=("candidate", "development", "final"),
    )
    publication_verify_parser.add_argument("--signature", type=Path)
    publication_verify_parser.add_argument("--trust", type=Path)
    publication_verify_parser.add_argument("--source-commit")

    evidence_sign_parser = subparsers.add_parser(
        "sign-evidence",
        help="sign canonical external release evidence with pinned trust",
    )
    _add_root_argument(evidence_sign_parser)
    evidence_sign_parser.add_argument("--artifact", required=True, type=Path)
    evidence_sign_parser.add_argument("--signature", required=True, type=Path)
    evidence_sign_parser.add_argument("--signing-key", required=True, type=Path)
    evidence_sign_parser.add_argument("--trust", required=True, type=Path)

    promotion_verify_parser = subparsers.add_parser(
        "verify-promotion",
        help="verify the exact signed same-commit promotion evidence set",
    )
    _add_root_argument(promotion_verify_parser)
    promotion_verify_parser.add_argument(
        "--evidence-directory", required=True, type=Path
    )
    promotion_verify_parser.add_argument("--policy", type=Path)
    promotion_verify_parser.add_argument("--trust", type=Path)
    promotion_verify_parser.add_argument("--tag", required=True)
    promotion_verify_parser.add_argument("--commit", required=True)
    promotion_verify_parser.add_argument("--live-proof-sha256")

    hatch_parser = subparsers.add_parser(
        "hatch-egg",
        help="verify and atomically create an isolated installed twin",
    )
    hatch_parser.add_argument("--egg", required=True, type=Path)
    hatch_parser.add_argument("--install-root", required=True, type=Path)
    hatch_parser.add_argument("--python", required=True, type=Path)
    hatch_parser.add_argument("--egg-sha256", required=True)
    hatch_parser.add_argument(
        "--release-manifest", required=True, type=Path
    )
    hatch_parser.add_argument(
        "--release-manifest-sha256", required=True
    )
    hatch_parser.add_argument("--release-trust", required=True, type=Path)
    hatch_parser.add_argument("--release-signature", type=Path)
    hatch_parser.add_argument("--release-checksums", type=Path)
    hatch_parser.add_argument("--github-attestation", type=Path)
    hatch_parser.add_argument("--controller-loadout-root", type=Path)
    hatch_parser.add_argument(
        "--trusted-development",
        action="store_true",
        help="allow only a verified signed WORKTREE development release",
    )

    verify_install_parser = subparsers.add_parser(
        "verify-install",
        help="verify an isolated installed twin without starting it",
    )
    verify_install_parser.add_argument(
        "--install-root", required=True, type=Path
    )

    uninstall_parser = subparsers.add_parser(
        "uninstall-preview",
        help="preview an installed-twin removal without deleting it",
    )
    uninstall_parser.add_argument("--install-root", required=True, type=Path)

    uninstall_twin_parser = subparsers.add_parser(
        "uninstall-twin",
        help="identity-check, quarantine, and delete an installed twin",
    )
    uninstall_twin_parser.add_argument(
        "--install-root", required=True, type=Path
    )
    uninstall_twin_parser.add_argument(
        "--controller-root", required=True, type=Path
    )
    uninstall_twin_parser.add_argument("--product-rappid", required=True)
    uninstall_twin_parser.add_argument("--instance-rappid", required=True)
    uninstall_twin_parser.add_argument("--confirmation", required=True)
    uninstall_twin_parser.add_argument("--dry-run", action="store_true")

    super_rar_parser = subparsers.add_parser(
        "super-rar",
        help="validate and print the committed source super-RAR index",
    )
    _add_root_argument(super_rar_parser)

    from .imessage.cli import add_imessage_parser

    add_imessage_parser(subparsers)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "version":
        print(f"{DISTRIBUTION_NAME} {__version__}")
        return 0

    try:
        if args.command == "verify":
            root = _selected_root(args.root)
            return _verify_command(root, args.json)
        if args.command == "census":
            root = _selected_root(args.root)
            return _census_command(root, args.json)
        if args.command == "refresh-census":
            return _refresh_census_command(
                _selected_root(args.root),
                args.output,
                owner=args.owner,
                cutoff=args.cutoff,
            )
        if args.command == "context":
            root = _selected_root(args.root)
            return _context_command(root, args.json)
        if args.command == "doctor":
            return _doctor_command(args)
        if args.command == "demo":
            return _demo_command(args)
        if args.command == "command-manifest":
            return _command_manifest_command(args)
        if args.command == "attest-installed":
            return _attest_installed_command(args)
        if args.command == "pages-build":
            return _pages_build_command(args)
        if args.command == "pages-check":
            return _pages_check_command(args)
        if args.command == "serve":
            return _serve_command(args)
        if args.command == "health":
            return _health_command(
                _select_health_url(args.url, args.url_option),
                args.timeout,
                args.auth_token_file,
            )
        if args.command in {"models", "provider-preflight"}:
            return _models_command(
                args.model,
                args.timeout,
                args.json,
                args.github_token_file,
            )
        if args.command == "provider-login":
            return _provider_login_command(args)
        if args.command == "provider-refresh":
            return _provider_refresh_command(args)
        if args.command == "provider-smoke":
            return _provider_smoke_command(args)
        if args.command == "controller-loadout":
            root = _selected_root(args.root)
            return _controller_loadout_command(root, args.output_dir)
        if args.command == "controller-auth":
            return _controller_auth_command(
                args.private_dir,
                verify_only=args.verify_only,
            )
        if args.command == "controller":
            return _controller_command(args)
        if args.command == "source-manifest":
            return _source_manifest_command(
                _selected_root(args.root), check=args.check
            )
        if args.command == "fetch-dependencies":
            return _fetch_dependencies_command(
                _selected_root(args.root), args.cache
            )
        if args.command == "build":
            return _build_release_command(
                _selected_root(args.root),
                args.dependency_cache,
                args.output,
                args.source_date_epoch,
                args.source_revision,
                args.signing_key,
                args.signing_trust,
            )
        if args.command == "verify-artifact":
            return _verify_artifact_command(args.artifact, args.sha256)
        if args.command == "verify-release":
            return _verify_release_command(
                args.release_manifest,
                args.release_manifest_sha256,
                args.trust,
                args.signature,
                args.checksums,
                args.source_root,
                args.github_attestation,
            )
        if args.command == "publication-scan":
            return _publication_scan_command(args)
        if args.command == "verify-publication-scan":
            return _verify_publication_scan_command(args)
        if args.command == "sign-evidence":
            return _sign_evidence_command(args)
        if args.command == "verify-promotion":
            return _verify_promotion_command(args)
        if args.command == "hatch-egg":
            return _hatch_egg_command(
                args.egg,
                args.install_root,
                args.python,
                args.egg_sha256,
                args.release_manifest,
                args.release_manifest_sha256,
                args.release_trust,
                args.release_signature,
                args.release_checksums,
                args.github_attestation,
                args.controller_loadout_root,
                args.trusted_development,
            )
        if args.command == "verify-install":
            return _verify_install_command(args.install_root)
        if args.command == "uninstall-preview":
            return _uninstall_preview_command(args.install_root)
        if args.command == "uninstall-twin":
            return _uninstall_twin_command(
                args.install_root,
                args.controller_root,
                args.product_rappid,
                args.instance_rappid,
                args.confirmation,
                args.dry_run,
            )
        if args.command == "super-rar":
            return _super_rar_command(_selected_root(args.root))
        if args.command == "imessage":
            return _imessage_command(args)
    except (RappStackCubbyError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    raise AssertionError(f"unhandled command: {args.command}")


def _add_root_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--root",
        type=Path,
        help="repository root (defaults to discovery from the working directory)",
    )


def _add_pages_release_arguments(parser: argparse.ArgumentParser) -> None:
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
    parser.add_argument("--release-tag", help="exact candidate release tag")


def _selected_root(value: Path | None) -> Path:
    if value is not None:
        return value.expanduser().resolve()
    return find_repository_root()


def _verify_command(root: Path, as_json: bool) -> int:
    result = verify_repository(root)
    if as_json:
        print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
    else:
        for check in result.checks:
            state = "PASS" if check.passed else "FAIL"
            print(f"{state} {check.name}")
            for error in check.errors:
                print(f"  - {error}")
        if result.ok:
            print(f"Repository verification passed: {len(result.checks)} checks.")
        else:
            print(
                "Repository verification failed: "
                f"{len(result.failed_checks)} checks, {result.error_count} errors."
            )
    return 0 if result.ok else 1


def _census_command(root: Path, as_json: bool) -> int:
    summary = census_summary(root)
    if as_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"SOURCE_CENSUS {summary['schema']}")
        print(f"owner: {summary['owner']}")
        print(f"audited: {summary['audited_at']}")
        print(f"repositories: {summary['repository_count']}")
        counts = summary["classification_counts"]
        ordered = " ".join(f"{key}={counts[key]}" for key in sorted(counts))
        print(f"classifications: {ordered}")
    return 0


def _refresh_census_command(
    root: Path,
    output: Path,
    *,
    owner: str,
    cutoff: str,
) -> int:
    from .census_refresh import write_refresh_candidate

    candidate = write_refresh_candidate(
        root,
        output,
        owner=owner,
        cutoff=cutoff,
    )
    difference = candidate["diff"]
    print(
        "PASS census refresh candidate: "
        f"{candidate['raw_inventory']['repository_count']} repositories; "
        f"added={len(difference['added'])} "
        f"removed={len(difference['removed'])} "
        f"renamed={len(difference['renamed'])}"
    )
    return 0


def _context_command(root: Path, as_json: bool) -> int:
    from .context import context_summary

    summary = context_summary(root)
    if as_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"LOCAL RAPP CONTEXT {summary['schema']}")
        print(f"entries: {summary['entries']}")
        print(f"canonical profiles: {summary['canonical_profiles']}")
        print(f"schemas: {summary['schemas']}")
        print(f"decisions: {summary['decisions']}")
        print(f"runbooks: {summary['runbooks']}")
        print(f"selected capabilities: {summary['selected_capabilities']}")
        print(f"future owners: {summary['future_owners']}")
        print("bootstrap:")
        for path in summary["bootstrap"]:
            print(f"  - {path}")
    return 0


def _doctor_command(args: argparse.Namespace) -> int:
    from .doctor import DoctorError, run_doctor

    try:
        result = run_doctor(
            _selected_root(args.root),
            python=args.python,
            work_dir=args.work_dir,
            dependency_cache=args.dependency_cache,
            install_dir=args.install_dir,
            controller_dir=args.controller_dir,
            live=args.live,
            model=args.model,
            github_token_file=args.github_token_file,
            imessage=args.imessage,
            imessage_config=args.imessage_config,
        )
    except DoctorError as error:
        raise RappStackCubbyError(str(error)) from error
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for name, passed in (
            ("python-3.11", result["python"]["python311"]),
            ("exact-packages", result["python"]["exact_packages"]),
            ("git", result["tools"]["git"]),
            ("gh", result["tools"]["gh"]),
            ("source-manifest", result["source_manifest"]["verified"]),
            ("dependency-cache", result["dependency_cache"]["verified"]),
            (
                "external-private-directories",
                all(result["external_directories"].values()),
            ),
        ):
            print(f"{'PASS' if passed else 'FAIL'} {name}")
        print(
            "INFO repository-clean="
            + str(result["repository"]["clean"]).lower()
        )
        if args.live:
            print(
                f"{'PASS' if result['live']['model_valid'] else 'FAIL'} "
                "live-provider-preflight"
            )
        if args.imessage:
            print(
                f"{'PASS' if result['imessage']['tool_verified'] else 'FAIL'} "
                "imessage-tool-fda"
            )
    return 0 if result["ok"] else 1


def _demo_command(args: argparse.Namespace) -> int:
    from .demo import DemoError, run_demo

    try:
        result = run_demo(
            _selected_root(args.root),
            python=args.python,
            work_dir=args.work_dir,
            dependency_cache=args.dependency_cache,
            install_dir=args.install_dir,
            controller_dir=args.controller_dir,
            receipt_path=args.receipt,
            source_date_epoch=args.source_date_epoch,
            cleanup=args.cleanup,
        )
    except DemoError as error:
        raise RappStackCubbyError(str(error)) from error
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for name, passed in result["stages"].items():
            print(f"{'PASS' if passed else 'SKIP'} {name}")
        print("PASS offline product demo")
    return 0


def _command_manifest_command(args: argparse.Namespace) -> int:
    from .command_manifest import (
        validate_command_manifest,
        validate_documented_commands,
        write_command_manifest,
    )

    root = _selected_root(args.root)
    value = (
        validate_command_manifest(root)
        if args.check
        else write_command_manifest(root)
    )
    if args.check_docs:
        errors = validate_documented_commands(root)
        if errors:
            raise RappStackCubbyError("; ".join(errors))
    print(
        f"PASS command manifest: {len(value['commands'])} command parsers"
    )
    return 0


def _attest_installed_command(args: argparse.Namespace) -> int:
    from .demo import (
        DemoError,
        InstalledAttestationError,
        run_installed_attestation,
    )

    try:
        value = run_installed_attestation(
            args.install_root,
            args.controller_dir,
            host_controller_python=args.host_python,
            receipt_path=args.receipt,
        )
    except InstalledAttestationError as error:
        print(
            json.dumps(error.diagnostics, separators=(",", ":"), sort_keys=True),
            file=sys.stderr,
        )
        return 2
    except DemoError as error:
        raise RappStackCubbyError(str(error)) from error
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def _pages_build_command(args: argparse.Namespace) -> int:
    from .pages import build_pages

    written = build_pages(
        _selected_root(args.root),
        **_pages_release_values(args),
    )
    print(f"PASS Pages build: {len(written)} generated files")
    return 0


def _pages_check_command(args: argparse.Namespace) -> int:
    from .pages import check_pages

    result = check_pages(
        _selected_root(args.root),
        **_pages_release_values(args),
    )
    if not result.ok:
        raise RappStackCubbyError("; ".join(result.errors))
    print(
        "PASS Pages check: "
        f"{result.file_count} files; {result.api_count} APIs; "
        f"{result.workflow_count} workflows"
    )
    return 0


def _pages_release_values(args: argparse.Namespace) -> dict[str, object]:
    return {
        "released": args.released,
        "candidate": args.candidate,
        "final": args.final,
        "release_directory": args.release_directory,
        "release_manifest": args.release_manifest,
        "release_manifest_sha256": args.release_manifest_sha256,
        "release_signature": args.release_signature,
        "release_trust": args.release_trust,
        "checksums": args.checksums,
        "source_root": args.source_root,
        "github_attestation": args.github_attestation,
        "publication_attestation": args.publication_attestation,
        "postflight_attestation": args.postflight_attestation,
        "promotion_attestation": args.promotion_attestation,
        "promotion_evidence_directory": args.promotion_evidence_directory,
        "promotion_run_id": args.promotion_run_id,
        "release_metadata": args.release_metadata,
        "candidate_publication_scan": args.candidate_publication_scan,
        "candidate_publication_scan_signature": (
            args.candidate_publication_scan_signature
        ),
        "postflight_receipt": args.postflight_receipt,
        "postflight_signature": args.postflight_signature,
        "promotion_receipt_sha256": args.promotion_receipt_sha256,
        "release_tag": args.release_tag,
    }


def _serve_command(args: argparse.Namespace) -> int:
    from .runtime.app import RuntimeApp
    from .runtime.orchestrator import OrchestratorError
    from .runtime.provider import ProviderError
    from .runtime.registry import RegistryError
    from .runtime.server import RuntimeServerError
    from .runtime.storage import StorageError

    try:
        if args.model is None and not args.controller_route:
            raise RappStackCubbyError(
                "--model is required unless --controller-route is enabled"
            )
        model = (
            args.model
            if args.model is not None
            else "deterministic-controller-route/1.0"
        )
        config = RuntimeConfig(
            soul_path=args.soul,
            agent_directories=tuple(args.agents_dir),
            data_root=args.data_dir,
            instance_id=args.instance_id,
            root=args.root,
            principal=args.principal,
            attestation_mode=args.attestation_mode,
            host=args.host,
            port=args.port,
            model=model,
            request_timeout=args.request_timeout,
            provider_timeout=args.provider_timeout,
            generated_agents_dir=args.generated_agents_dir,
            allow_agent_writes=args.allow_agent_writes,
            imessage_status_path=(
                args.imessage_status
                or (
                    Path(os.environ["RAPP_STACK_IMESSAGE_STATUS"])
                    if os.environ.get("RAPP_STACK_IMESSAGE_STATUS")
                    else None
                )
            ),
            twin_rappid=args.twin_rappid,
            child_private_key_path=args.child_private_key,
            paired_controller_public_jwk_path=(
                args.paired_controller_public_jwk
            ),
            paired_controller_rappid=args.paired_controller_rappid,
            replay_db_path=args.replay_db,
            signed_ingress_freshness_seconds=(
                args.signed_ingress_freshness_seconds
            ),
            signed_ingress_key_epoch=args.signed_ingress_key_epoch,
            signed_only=args.signed_only,
            controller_route_enabled=args.controller_route,
            controller_loadout_root=args.controller_loadout_root,
            auth_token_file=args.auth_token_file,
            github_token_file=args.github_token_file,
        )
        app = RuntimeApp(config)
        print(app.url, flush=True)
        try:
            app.serve_forever()
        except KeyboardInterrupt:
            return 0
        finally:
            app.shutdown()
    except (
        OrchestratorError,
        ProviderError,
        RegistryError,
        RuntimeServerError,
        StorageError,
    ) as error:
        raise RappStackCubbyError(str(error)) from error
    return 0


def _models_command(
    selected_model: str | None,
    timeout: float,
    as_json: bool,
    github_token_file: Path | None = None,
) -> int:
    from .runtime.provider import (
        CopilotProvider,
        ProviderError,
        provider_preflight_status,
    )

    try:
        provider_arguments: dict[str, object] = {
            "model": selected_model,
            "timeout": timeout,
        }
        if github_token_file is not None:
            provider_arguments["github_token_file"] = github_token_file
        provider = CopilotProvider(**provider_arguments)
        models = provider.list_models()
        selected = (
            None
            if selected_model is None
            else provider.validate_model(selected_model, models=models)
        )
    except ProviderError as error:
        status = provider_preflight_status(error)
        payload = {
            "authenticated": False,
            "chat_completion_model_count": 0,
            "chat_completion_models": [],
            "provider": "github-copilot",
            "selected_model": selected_model,
            "selected_model_valid": False,
            "status": status,
        }
        if as_json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"status: {status}", file=sys.stderr)
            print(f"error: {error}", file=sys.stderr)
        return 2
    payload = {
        "provider": "github-copilot",
        "authenticated": True,
        "chat_completion_model_count": len(models),
        "chat_completion_models": [item.as_dict() for item in models],
        "selected_model": None if selected is None else selected.id,
        "selected_model_valid": selected is not None,
        "status": "ok",
    }
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for item in models:
            print(item.id)
        if selected is not None:
            print(f"validated: {selected.id}")
    return 0


def _provider_login_command(args: argparse.Namespace) -> int:
    from .runtime.github_auth import GitHubAuthError, device_login

    try:
        result = device_login(args.token_file, timeout=args.timeout)
    except GitHubAuthError as error:
        raise RappStackCubbyError(str(error)) from error
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("authenticated: true")
        print(
            "refresh_token_available: "
            + str(result["refresh_token_available"]).lower()
        )
    return 0


def _provider_refresh_command(args: argparse.Namespace) -> int:
    from .runtime.github_auth import GitHubAuthError, refresh_token_file

    try:
        result = refresh_token_file(
            args.token_file,
            timeout=args.timeout,
        )
    except GitHubAuthError as error:
        raise RappStackCubbyError(str(error)) from error
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("authenticated: true")
        print(
            "refresh_token_available: "
            + str(result["refresh_token_available"]).lower()
        )
    return 0


def _provider_smoke_command(args: argparse.Namespace) -> int:
    import time

    from .runtime.provider import (
        CopilotProvider,
        ProviderError,
        ProviderProtocolError,
        provider_preflight_status,
    )

    started = time.perf_counter()
    try:
        provider = CopilotProvider(
            model=args.model,
            timeout=args.timeout,
            github_token_file=args.github_token_file,
        )
        models = provider.list_models()
        provider.validate_model(args.model, models=models)
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "rapp_provider_probe",
                    "description": "Return one fixed synthetic probe value.",
                    "parameters": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "value": {
                                "type": "string",
                                "enum": ["synthetic"],
                            }
                        },
                        "required": ["value"],
                    },
                },
            }
        ]
        messages: list[dict[str, object]] = [
            {
                "role": "system",
                "content": (
                    "This is a synthetic protocol probe. Call "
                    "rapp_provider_probe exactly once with value synthetic; "
                    "do not include prose."
                ),
            },
            {
                "role": "user",
                "content": "Run the required synthetic protocol probe.",
            },
        ]
        first = provider.complete(
            messages,
            tools=tools,
            timeout=args.timeout,
        )
        if len(first.tool_calls) != 1:
            raise ProviderProtocolError(
                "provider smoke did not produce exactly one tool call"
            )
        call = first.tool_calls[0]
        try:
            arguments = json.loads(call.arguments)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ProviderProtocolError(
                "provider smoke tool arguments are invalid"
            ) from error
        if (
            call.name != "rapp_provider_probe"
            or arguments != {"value": "synthetic"}
        ):
            raise ProviderProtocolError(
                "provider smoke tool call did not match the fixed probe"
            )
        messages.extend(
            [
                {
                    "role": "assistant",
                    "content": first.content,
                    "tool_calls": [call.as_openai()],
                },
                {
                    "role": "tool",
                    "tool_call_id": call.id,
                    "name": call.name,
                    "content": '{"status":"ok"}',
                },
            ]
        )
        second = provider.complete(
            messages,
            tools=tools,
            timeout=args.timeout,
        )
        if second.tool_calls:
            raise ProviderProtocolError(
                "provider smoke did not terminate after the fixed tool result"
            )
    except ProviderError as error:
        payload = {
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "model": args.model,
            "response_shape": None,
            "status": provider_preflight_status(error),
            "success": False,
        }
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"status: {payload['status']}", file=sys.stderr)
        return 2
    payload = {
        "latency_ms": int((time.perf_counter() - started) * 1000),
        "model": args.model,
        "response_shape": {
            "completion_content_present": bool(second.content),
            "completion_finish_reason_present": (
                second.finish_reason is not None
            ),
            "completion_tool_calls": len(second.tool_calls),
            "initial_content_present": bool(first.content),
            "initial_tool_calls": len(first.tool_calls),
        },
        "status": "ok",
        "success": True,
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("success: true")
        print(f"model: {args.model}")
        print(f"latency_ms: {payload['latency_ms']}")
        print("response_shape: tool-call-then-completion")
    return 0


def _health_command(
    raw_url: str,
    timeout: float,
    auth_token_file: Path | None = None,
) -> int:
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not 0 < float(timeout) <= 60
    ):
        raise RappStackCubbyError(
            "health timeout must be between 0 and 60 seconds"
        )
    url = _local_health_url(raw_url)
    headers = {"Accept": "application/json"}
    auth_token: bytes | None = None
    auth_challenge: bytes | None = None
    if auth_token_file is not None:
        from .runtime.auth import (
            AUTH_CHALLENGE_HEADER,
            encode_auth_value,
            new_auth_challenge,
            read_auth_token,
        )

        auth_token = read_auth_token(auth_token_file)
        auth_challenge = new_auth_challenge()
        headers[AUTH_CHALLENGE_HEADER] = encode_auth_value(auth_challenge)
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        response = urllib.request.urlopen(request, timeout=float(timeout))
        try:
            raw = response.read(64 * 1024 + 1)
            status = getattr(response, "status", 200)
            auth_proof = response.headers.get("X-Rapp-Auth-Proof")
        finally:
            response.close()
    except urllib.error.HTTPError as error:
        raw = error.read(64 * 1024 + 1)
        status = error.code
        auth_proof = error.headers.get("X-Rapp-Auth-Proof")
    except urllib.error.URLError as error:
        raise RappStackCubbyError("local health endpoint is unavailable") from error
    if len(raw) > 64 * 1024:
        raise RappStackCubbyError("local health response exceeds the size limit"        )
    if auth_token is not None and auth_challenge is not None:
        from .runtime.auth import verify_auth_challenge_proof

        if not verify_auth_challenge_proof(
            auth_token,
            auth_challenge,
            auth_proof,
        ):
            raise RappStackCubbyError(
                "local health endpoint authentication failed"
            )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RappStackCubbyError(
            "local health endpoint returned invalid JSON"
        ) from error
    if not isinstance(payload, dict):
        raise RappStackCubbyError(
            "local health endpoint must return a JSON object"
        )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if 200 <= int(status) < 300 else 1


def _controller_loadout_command(root: Path, output_dir: Path) -> int:
    from .controller import build_controller_loadout

    manifest = build_controller_loadout(root, output_dir)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


def _controller_auth_command(
    private_dir: Path,
    *,
    verify_only: bool,
) -> int:
    from .runtime.auth import prepare_controller_auth

    path, created = prepare_controller_auth(
        private_dir,
        verify_only=verify_only,
    )
    print(
        json.dumps(
            {
                "created": created,
                "token_bytes": 32,
                "token_file": str(path),
                "verified": True,
            },
            sort_keys=True,
        )
    )
    return 0


def _controller_command(args: argparse.Namespace) -> int:
    from .protocols.canonical import canonical_json_bytes, parse_json
    from .runtime.orchestrator import (
        RequestValidationError,
        build_controller_chat_request,
    )

    if (
        not isinstance(args.timeout, (int, float))
        or isinstance(args.timeout, bool)
        or not 0 < float(args.timeout) <= 300
    ):
        raise RappStackCubbyError(
            "controller timeout must be between 0 and 300 seconds"
        )
    action_map = {
        "adopt": "adopt_install",
        "hatch": "hatch_repo",
        "self-test": "self_test",
        "rotate": "rotate_keys",
    }
    action = action_map.get(
        args.controller_action, args.controller_action
    )
    arguments: dict[str, object] = {}
    for source, target in (
        ("repository_url", "repository_url"),
        ("commit", "commit"),
        ("expected_tree_digest", "expected_tree_digest"),
        ("product_rappid", "development_rappid"),
        ("install_root", "install_root"),
        ("rappid", "rappid"),
        ("model", "model"),
        ("github_token_file", "github_token_file"),
        ("attestation_mode", "attestation_mode"),
        ("port", "port"),
        ("confirmation", "confirmation"),
    ):
        value = getattr(args, source, None)
        if value is not None:
            arguments[target] = (
                str(value) if isinstance(value, Path) else value
            )
    if getattr(args, "trusted_development", False):
        arguments["trusted_development"] = True
    try:
        payload = build_controller_chat_request(
            action, arguments, args.idempotency_key
        )
    except RequestValidationError as error:
        raise RappStackCubbyError(str(error)) from error
    url = _local_chat_url(args.url)
    body = canonical_json_bytes(payload)
    from .runtime.auth import bearer_authorization, read_auth_token

    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Accept": "application/json",
            "Authorization": bearer_authorization(
                read_auth_token(args.auth_token_file)
            ),
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        response = urllib.request.urlopen(
            request, timeout=float(args.timeout)
        )
        try:
            raw = response.read(2 * 1024 * 1024 + 1)
            status = getattr(response, "status", 200)
        finally:
            response.close()
    except urllib.error.HTTPError as error:
        raw = error.read(2 * 1024 * 1024 + 1)
        status = error.code
    except urllib.error.URLError as error:
        raise RappStackCubbyError(
            "local controller /chat endpoint is unavailable"
        ) from error
    if status != 200 or len(raw) > 2 * 1024 * 1024:
        raise RappStackCubbyError(
            "local controller /chat request failed"
        )
    try:
        outer = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RappStackCubbyError(
            "local controller /chat response is invalid"
        ) from error
    proof = outer.get("result_proof") if isinstance(outer, dict) else None
    result_text = outer.get("response") if isinstance(outer, dict) else None
    controller_result = (
        outer.get("controller_result") if isinstance(outer, dict) else None
    )
    try:
        canonical_result = (
            canonical_json_bytes(controller_result)
            if isinstance(controller_result, dict)
            else b""
        )
    except Exception:
        canonical_result = b""
    if (
        not isinstance(proof, dict)
        or not isinstance(result_text, str)
        or not isinstance(controller_result, dict)
        or proof.get("schema")
        != "rapp-controller-result-proof/1.0"
        or proof.get("action") != action
        or proof.get("request_sha256")
        != hashlib.sha256(
            payload["user_input"].encode("utf-8")
        ).hexdigest()
        or proof.get("result_sha256") != hashlib.sha256(canonical_result).hexdigest()
        or proof.get("controller_result_sha256")
        != proof.get("result_sha256")
        or proof.get("child_response_sha256")
        != hashlib.sha256(result_text.encode("utf-8")).hexdigest()
        or proof.get("status")
        != ("ok" if controller_result.get("ok") is True else "rejected")
    ):
        raise RappStackCubbyError(
            "local controller result proof is invalid"
        )
    result = controller_result
    if action != "chat":
        try:
            parsed_result = parse_json(result_text)
        except Exception as error:
            raise RappStackCubbyError(
                "local controller result is invalid"
            ) from error
        if parsed_result != controller_result:
            raise RappStackCubbyError(
                "local controller response does not match its result"
            )
    print(json.dumps(outer, indent=2, sort_keys=True))
    return 0 if isinstance(result, dict) and result.get("ok") is True else 1


def _source_manifest_command(root: Path, *, check: bool) -> int:
    from .packaging.source import (
        validate_source_manifest,
        write_source_manifest,
    )

    value = (
        validate_source_manifest(root)
        if check
        else write_source_manifest(root)
    )
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def _fetch_dependencies_command(root: Path, cache: Path) -> int:
    from .packaging.dependencies import fetch_dependencies

    value = fetch_dependencies(root, cache)
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def _build_release_command(
    root: Path,
    dependency_cache: Path,
    output: Path,
    source_date_epoch: int,
    source_revision: str,
    signing_key: Path | None,
    signing_trust: Path | None,
) -> int:
    from .packaging.builder import build_release

    value = build_release(
        root,
        dependency_cache,
        output,
        source_date_epoch=source_date_epoch,
        source_revision=source_revision,
        signing_key=signing_key,
        signing_trust=signing_trust,
    )
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def _verify_artifact_command(path: Path, expected_sha256: str | None) -> int:
    from .packaging.builder import verify_artifact

    value = verify_artifact(path, expected_sha256=expected_sha256)
    summary = {
        "artifact_type": value["artifact_type"],
        "file_count": value["file_count"],
        "sha256": value["sha256"],
        "size": value["size"],
        "verified": True,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def _verify_release_command(
    manifest: Path,
    expected_sha256: str,
    trust: Path,
    signature: Path | None,
    checksums: Path | None,
    source_root: Path | None,
    github_attestation: Path | None,
) -> int:
    from .packaging.release import verify_release

    value = verify_release(
        manifest,
        expected_manifest_sha256=expected_sha256,
        trust_path=trust,
        signature_path=signature,
        checksums_path=checksums,
        source_root=source_root,
        github_attestation=github_attestation,
    )
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def _publication_scan_command(args: argparse.Namespace) -> int:
    from .packaging.publication import (
        scan_publication,
        sign_publication_receipt,
        write_publication_receipt,
    )

    root = _selected_root(args.root)
    policy = args.policy or root / "PUBLICATION_SCAN_POLICY.json"
    actions_logs: list[tuple[str, Path]] = []
    for value in args.actions_log:
        run_id, separator, path = value.partition("=")
        if not separator or not run_id or not path:
            raise RappStackCubbyError(
                "--actions-log must be RUN_ID=ABSOLUTE_ZIP"
            )
        actions_logs.append((run_id, Path(path)))
    signing_values = (
        args.signing_key,
        args.signing_trust,
        args.signature_output,
    )
    if any(value is not None for value in signing_values) and not all(
        value is not None for value in signing_values
    ):
        raise RappStackCubbyError(
            "signing key, trust, and signature output are required together"
        )
    value = scan_publication(
        root,
        policy_path=policy,
        pages_root=args.pages,
        release_assets_root=args.release_assets,
        public_redownload_root=args.public_redownload,
        actions_logs=actions_logs,
        phase=args.phase,
        timestamp=args.timestamp,
    )
    write_publication_receipt(args.output, value)
    signed = False
    if args.signing_key is not None:
        sign_publication_receipt(
            args.output,
            args.signature_output,
            key_path=args.signing_key,
            repository_root=root,
            trust_path=args.signing_trust,
        )
        signed = True
    print(
        json.dumps(
            {
                "counts": value["counts"],
                "output": str(args.output),
                "result": value["result"],
                "schema": value["schema"],
                "signed": signed,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if value["result"] == "pass" else 1


def _verify_publication_scan_command(args: argparse.Namespace) -> int:
    from .packaging.publication import verify_publication_receipt

    value = verify_publication_receipt(
        args.receipt,
        policy_path=args.policy,
        required_phase=args.phase,
        signature_path=args.signature,
        trust_path=args.trust,
        expected_source_commit=args.source_commit,
    )
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def _sign_evidence_command(args: argparse.Namespace) -> int:
    from .promotion import sign_evidence

    root = _selected_root(args.root)
    value = sign_evidence(
        args.artifact,
        args.signature,
        key_path=args.signing_key,
        repository_root=root,
        trust_path=args.trust,
    )
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def _verify_promotion_command(args: argparse.Namespace) -> int:
    from .promotion import verify_promotion_bundle

    root = _selected_root(args.root)
    value = verify_promotion_bundle(
        args.evidence_directory,
        policy_path=args.policy or root / "PUBLICATION_SCAN_POLICY.json",
        trust_path=args.trust or root / "RELEASE_TRUST.json",
        expected_tag=args.tag,
        expected_commit=args.commit,
        expected_live_proof_sha256=args.live_proof_sha256,
    )
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def _hatch_egg_command(
    egg: Path,
    install_root: Path,
    python: Path,
    expected_sha256: str,
    release_manifest: Path,
    release_manifest_sha256: str,
    release_trust: Path,
    release_signature: Path | None,
    release_checksums: Path | None,
    github_attestation: Path | None,
    controller_loadout_root: Path | None,
    trusted_development: bool,
) -> int:
    from .packaging.hatch import hatch_egg
    from .packaging.release import verify_release

    release = verify_release(
        release_manifest,
        expected_manifest_sha256=release_manifest_sha256,
        trust_path=release_trust,
        signature_path=release_signature,
        checksums_path=release_checksums,
        github_attestation=github_attestation,
    )

    value = hatch_egg(
        egg,
        install_root,
        python,
        expected_egg_sha256=expected_sha256,
        release_verification=release,
        controller_loadout_root=controller_loadout_root,
        allow_trusted_development=trusted_development,
    )
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def _verify_install_command(install_root: Path) -> int:
    from .packaging.hatch import verify_install

    value = verify_install(install_root)
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def _uninstall_preview_command(install_root: Path) -> int:
    from .packaging.hatch import uninstall_preview

    value = uninstall_preview(install_root)
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def _uninstall_twin_command(
    install_root: Path,
    controller_root: Path,
    product_rappid: str,
    instance_rappid: str,
    confirmation: str,
    dry_run: bool,
) -> int:
    from .packaging.hatch import uninstall_twin

    value = uninstall_twin(
        install_root,
        expected_product_rappid=product_rappid,
        expected_instance_rappid=instance_rappid,
        confirmation=confirmation,
        controller_root=controller_root,
        dry_run=dry_run,
    )
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def _super_rar_command(root: Path) -> int:
    from .packaging.common import read_json_object
    from .packaging.indexes import build_super_rar_index

    value = read_json_object(root / "rapp-super-rar.json")
    rebuilt = build_super_rar_index(
        value.get("entries", []),
        source_tree_digest=value.get("source_tree_digest_binding", ""),
        release_specific=False,
    )
    comparable = dict(rebuilt)
    comparable.pop("source_tree_digest")
    expected = dict(value)
    expected.pop("source_tree_digest_binding", None)
    if comparable != expected:
        raise RappStackCubbyError("committed super-RAR index is invalid")
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def _imessage_command(args: argparse.Namespace) -> int:
    from .imessage.bridge import IMessageBridgeError
    from .imessage.cli import run_imessage_command
    from .imessage.config import ConfigError
    from .imessage.state import StateError

    try:
        return run_imessage_command(args)
    except KeyboardInterrupt:
        return 130
    except (
        ConfigError,
        IMessageBridgeError,
        StateError,
        subprocess.SubprocessError,
    ) as error:
        raise RappStackCubbyError("iMessage command failed safely") from error


def _select_health_url(positional: str | None, option: str | None) -> str:
    if positional is not None and option is not None:
        raise RappStackCubbyError(
            "provide the health URL once, either positionally or with --url"
        )
    return option or positional or f"http://{DEFAULT_HOST}:{DEFAULT_PORT}/health"


def _local_health_url(raw_url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(raw_url)
        port = parsed.port
    except ValueError as error:
        raise RappStackCubbyError("health URL is invalid") from error
    if (
        parsed.scheme != "http"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise RappStackCubbyError(
            "health URL must be an uncredentialed local HTTP URL"
        )
    hostname = parsed.hostname.lower()
    if hostname != "localhost":
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError as error:
            raise RappStackCubbyError(
                "health URL host must be loopback"
            ) from error
        if not address.is_loopback:
            raise RappStackCubbyError(
                "health URL host must be loopback"
            )
    path = parsed.path.rstrip("/")
    if path in {"", "/health"}:
        path = "/health"
    else:
        raise RappStackCubbyError("health URL path must be /health")
    if port is not None and not 1 <= port <= 65535:
        raise RappStackCubbyError("health URL port is invalid")
    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host if port is None else f"{host}:{port}"
    return urllib.parse.urlunsplit(("http", netloc, path, "", ""))


def _local_chat_url(raw_url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(raw_url)
        port = parsed.port
    except ValueError as error:
        raise RappStackCubbyError("controller URL is invalid") from error
    if (
        parsed.scheme != "http"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path.rstrip("/") != "/chat"
    ):
        raise RappStackCubbyError(
            "controller URL must be an uncredentialed local HTTP /chat URL"
        )
    hostname = parsed.hostname.lower()
    if hostname != "localhost":
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError as error:
            raise RappStackCubbyError(
                "controller URL host must be loopback"
            ) from error
        if not address.is_loopback:
            raise RappStackCubbyError(
                "controller URL host must be loopback"
            )
    if port is not None and not 1 <= port <= 65535:
        raise RappStackCubbyError("controller URL port is invalid")
    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host if port is None else f"{host}:{port}"
    return urllib.parse.urlunsplit(("http", netloc, "/chat", "", ""))
