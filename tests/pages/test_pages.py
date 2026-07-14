from __future__ import annotations

import json
import re
import subprocess
import tarfile
import textwrap
import unittest
import urllib.parse
from pathlib import Path

from rapp_stack_cubby.context import validate_schema_instance
from rapp_stack_cubby.pages import (
    API_RELATIVE,
    API_SCHEMAS,
    DOWNLOAD_ASSETS,
    PAGES_URL,
    PAGES_MANIFEST_RELATIVE,
    REPOSITORY_URL,
    SITEMAP_BYTES,
    _html_errors,
    _json_bytes,
    _privacy_errors,
    _routing_file_errors,
    _svg_errors,
    _xml_errors,
    build_pages,
    build_static_api,
    check_pages,
    check_pages_artifact,
    check_workflows,
    render_generated_files,
)
from tests.packaging._support import (
    PackagingWorkspace,
    create_exact_signed_release,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class PagesApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.api = build_static_api(REPOSITORY_ROOT)

    def test_generated_api_matches_source_truth_byte_for_byte(self) -> None:
        self.assertEqual(set(self.api), set(API_SCHEMAS))
        for name, value in self.api.items():
            with self.subTest(name=name):
                path = REPOSITORY_ROOT / API_RELATIVE / name
                self.assertEqual(path.read_bytes(), _json_bytes(value))

    def test_status_metrics_are_direct_source_counts(self) -> None:
        status = self.api["status.json"]
        census = json.loads(
            (REPOSITORY_ROOT / "SOURCE_CENSUS.json").read_text()
        )
        capabilities = json.loads(
            (REPOSITORY_ROOT / "CAPABILITY_MATRIX.json").read_text()
        )
        agents = json.loads(
            (
                REPOSITORY_ROOT
                / "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/"
                "agent-catalog.json"
            ).read_text()
        )
        metrics = status["metrics"]

        self.assertEqual(
            status["journey"],
            {
                "offline_end_to_end_local_attestation": "implemented",
                "live_copilot": "implemented_this_host",
                "live_imessage": "external_final_gate",
                "public_pages": "external_final_gate",
            },
        )
        self.assertEqual(
            status["live_provider_host_proof"],
            json.loads(
                (
                    REPOSITORY_ROOT / "LIVE_PROVIDER_STATUS.json"
                ).read_text(encoding="utf-8")
            ),
        )
        self.assertEqual(metrics["repositories_audited"], census["repository_count"])
        self.assertEqual(metrics["repositories_audited"], 307)
        self.assertEqual(metrics["antecedent_repositories"], 299)
        self.assertEqual(metrics["local_product_nodes"], 1)
        self.assertEqual(
            status["evidence"]["cutoff"],
            "2026-07-13T08:57:20.399000Z",
        )
        self.assertTrue(status["evidence"]["audit_complete"])
        self.assertEqual(
            status["evidence"]["drift_review"],
            {
                "post_window_drift_count": 5,
                "required_count": 12,
                "status": "complete",
            },
        )
        self.assertEqual(
            status["evidence"]["observation_window"]["capture_started_at"],
            "2026-07-13T09:07:31.710577Z",
        )
        self.assertEqual(
            metrics["capabilities"],
            capabilities["aggregates"]["capability_count"],
        )
        self.assertEqual(metrics["actual_agents"], agents["agent_count"])
        self.assertEqual(metrics["streamable_controllers"], 1)
        self.assertGreater(metrics["tests"], 200)

    def test_capability_api_has_complete_implementation_parity(self) -> None:
        source = json.loads(
            (REPOSITORY_ROOT / "CAPABILITY_MATRIX.json").read_text()
        )
        matrix = json.loads(
            (
                REPOSITORY_ROOT
                / "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/"
                "implementation-matrix.json"
            ).read_text()
        )
        value = self.api["capabilities.json"]

        self.assertEqual(value["total"], len(source["capabilities"]))
        self.assertEqual(value["selected_count"], 61)
        self.assertEqual(
            {item["id"] for item in value["capabilities"]},
            {item["capability_id"] for item in matrix["capabilities"]},
        )
        pages = next(
            item
            for item in value["capabilities"]
            if item["id"] == "security.pages-private-state"
        )
        self.assertEqual(pages["implementation_state"], "implemented_now")
        self.assertEqual(pages["owner"]["kind"], "pages")
        scanner = next(
            item
            for item in value["capabilities"]
            if item["id"] == "release.scanner-matrix"
        )
        self.assertEqual(scanner["implementation_state"], "implemented_now")
        self.assertEqual(scanner["owner"]["kind"], "packaging")
        self.assertEqual(scanner["owner"]["name"], "publication-scan")

    def test_architecture_api_preserves_complete_graph_topology(self) -> None:
        source = json.loads((REPOSITORY_ROOT / "SYSTEM_GRAPH.json").read_text())
        value = self.api["architecture.json"]

        self.assertEqual(
            len(value["nodes"]),
            len(source["repo_nodes"]) + len(source["non_repo_nodes"]),
        )
        self.assertEqual(len(value["edges"]), len(source["edges"]))
        self.assertEqual(
            len(value["canonical_paths"]),
            len(source["canonical_end_to_end_paths"]),
        )
        self.assertEqual(value["aggregates"], source["aggregates"])
        node_ids = {item["id"] for item in value["nodes"]}
        self.assertIn("product:local/rapp-stack-cubby", node_ids)
        self.assertIn("runtime:clean-room-brainstem", node_ids)
        self.assertNotIn("runtime:microsoft-hardened-adaptation", node_ids)
        self.assertTrue(
            any(
                item["source_id"] == "actor:local-owner"
                and item["target_id"] == "runtime:global-controller"
                and item["evidence_strength"] == "tested_local_implementation"
                for item in value["edges"]
            )
        )

    def test_context_api_matches_context_index_routes_and_entries(self) -> None:
        source = json.loads((REPOSITORY_ROOT / "CONTEXT_INDEX.json").read_text())
        value = self.api["context.json"]

        self.assertEqual(value["authority_order"], source["authority_order"])
        self.assertEqual(value["entries"], source["entries"])
        self.assertEqual(
            value["capability_routes"], source["capability_routes"]
        )
        self.assertTrue(
            all(route["local_claim"] and route["major_gaps"] for route in value["capability_routes"])
        )

    def test_all_api_documents_satisfy_the_shared_schema(self) -> None:
        schema_path = REPOSITORY_ROOT / "schemas/pages-api.schema.json"
        schema = json.loads(schema_path.read_text())
        for name, value in self.api.items():
            with self.subTest(name=name):
                self.assertFalse(
                    validate_schema_instance(
                        value, schema, schema_path=schema_path
                    )
                )

    def test_prompt_catalog_is_exact_and_tutorial_is_prominent(self) -> None:
        prompts = self.api["prompts.json"]["prompts"]
        html = (REPOSITORY_ROOT / "docs/index.html").read_text()

        self.assertEqual(len(prompts), 10)
        self.assertEqual(prompts[0]["title"], "One idea to public product.")
        self.assertEqual(
            [item["id"] for item in prompts],
            [f"prompt-{index:02d}" for index in range(1, 11)],
        )
        for prompt in prompts:
            self.assertIn(prompt["title"], html)
            self.assertIn(prompt["prompt"], html)
        self.assertGreaterEqual(html.count("IMESSAGE_ONBOARDING.md"), 2)

    def test_pending_release_has_stable_urls_without_hash_self_reference(self) -> None:
        downloads = self.api["downloads.json"]

        self.assertEqual(downloads["status"], "pending")
        self.assertEqual(downloads["release"]["state"], "pending")
        self.assertIsNone(downloads["release"]["source_commit"])
        self.assertEqual(len(downloads["assets"]), len(DOWNLOAD_ASSETS))
        for item in downloads["assets"]:
            self.assertEqual(item["availability"], "pending")
            if item["distribution"] == "release-asset":
                self.assertTrue(
                    item["url"].startswith(
                        f"{REPOSITORY_URL}/releases/download/"
                    )
                )
            else:
                self.assertEqual(item["distribution"], "actions-artifact")
                self.assertTrue(item["url"].startswith(f"{PAGES_URL}evidence/"))
            self.assertNotIn("sha256", item)
        self.assertTrue(downloads["exact_hashes"].endswith("/SHA256SUMS"))

    def test_release_core_alone_cannot_authorize_pages(self) -> None:
        with PackagingWorkspace() as workspace:
            source, _cache, output, result, _verified, attestation = (
                create_exact_signed_release(workspace)
            )
            with self.assertRaises(ValueError):
                build_pages(
                    source,
                    final=True,
                    release_directory=output,
                    release_manifest=output / "release-manifest.json",
                    release_manifest_sha256=result["release_manifest_sha256"],
                    release_signature=output / "release-manifest.json.sig",
                    release_trust=source / "RELEASE_TRUST.json",
                    checksums=output / "SHA256SUMS",
                    source_root=source,
                    github_attestation=attestation,
                    release_tag="v0.1.0-rc.11",
                )

    def test_rendering_is_deterministic(self) -> None:
        first = render_generated_files(REPOSITORY_ROOT)
        second = render_generated_files(REPOSITORY_ROOT)

        self.assertEqual(first, second)
        self.assertEqual(
            {path.as_posix() for path in first},
            {
                "docs/index.html",
                PAGES_MANIFEST_RELATIVE.as_posix(),
                *{
                    f"docs/api/v1/{name}"
                    for name in API_SCHEMAS
                },
            },
        )


class PagesSurfaceTests(unittest.TestCase):
    def test_complete_pages_checker_passes(self) -> None:
        result = check_pages(REPOSITORY_ROOT)

        self.assertTrue(result.ok, "\n".join(result.errors))
        self.assertEqual(result.api_count, 6)
        self.assertEqual(result.workflow_count, 4)
        self.assertGreater(result.file_count, 40)

    def test_core_content_works_without_javascript(self) -> None:
        html = (REPOSITORY_ROOT / "docs/index.html").read_text()

        self.assertNotRegex(html, r"<script\b")
        self.assertIn("<main id=\"main-content\">", html)
        self.assertIn("Complete system map", html)
        self.assertIn("Fresh install and hatch", html)
        self.assertIn("Complete context handoff", html)
        self.assertIn("Release and download", html)

    def test_accessibility_and_reduced_motion_structure_is_present(self) -> None:
        html = (REPOSITORY_ROOT / "docs/index.html").read_text()
        css = (REPOSITORY_ROOT / "docs/assets/styles.css").read_text()

        self.assertIn('class="skip-link"', html)
        self.assertIn("<nav aria-label=", html)
        self.assertIn("<caption>", html)
        self.assertIn("<details>", html)
        self.assertIn(":focus-visible", css)
        self.assertIn("@media (prefers-reduced-motion: reduce)", css)
        self.assertIn("@media print", css)

    def test_no_network_storage_cookie_or_service_worker_apis(self) -> None:
        for path in (
            REPOSITORY_ROOT / "docs/index.html",
            REPOSITORY_ROOT / "docs/404.html",
        ):
            with self.subTest(path=path.name):
                text = path.read_text()
                self.assertFalse(_privacy_errors(path.name, text))
                self.assertNotRegex(
                    text,
                    re.compile(
                        r"(?:\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\b|"
                        r"\bEventSource\b|"
                        r"localStorage|sessionStorage|indexedDB|serviceWorker)\b",
                        re.IGNORECASE,
                    ),
                )

    def test_project_url_and_routing_files_are_exact(self) -> None:
        robots = (REPOSITORY_ROOT / "docs/robots.txt").read_text()
        sitemap = (REPOSITORY_ROOT / "docs/sitemap.xml").read_text()
        not_found = (REPOSITORY_ROOT / "docs/404.html").read_text()

        self.assertIn(f"Sitemap: {PAGES_URL}sitemap.xml", robots)
        self.assertEqual(sitemap.count(f"<loc>{PAGES_URL}</loc>"), 1)
        self.assertEqual(
            (REPOSITORY_ROOT / "docs/sitemap.xml").read_bytes(),
            SITEMAP_BYTES,
        )
        self.assertEqual((REPOSITORY_ROOT / "docs/.nojekyll").read_bytes(), b"")
        targets = re.findall(r'(?:href|src)="([^"]+)"', not_found)
        for target in targets:
            with self.subTest(target=target):
                self.assertTrue(target.startswith("/rapp-stack-cubby/"))
                self.assertTrue(
                    urllib.parse.urljoin(
                        f"{PAGES_URL}missing/deep/route", target
                    ).startswith(PAGES_URL)
                )

    def test_exact_inventory_rejects_extra_active_web_files(self) -> None:
        with PackagingWorkspace() as workspace:
            source, _cache = workspace.copy_repository_with_fake_dependencies()
            attacks = {
                "attack.html": "<script src='https://evil.invalid/x.js'></script>",
                "attack.svg": "<svg><script>alert(1)</script></svg>",
                "attack.css": "@import 'https://evil.invalid/x.css';",
            }
            for name, content in attacks.items():
                path = source / "docs" / name
                path.write_text(content, encoding="utf-8")
                result = check_pages(source)
                self.assertFalse(result.ok)
                self.assertTrue(
                    any(
                        "unexpected" in error
                        or "stale" in error
                        or "forbidden" in error
                        for error in result.errors
                    ),
                    result.errors,
                )
                path.unlink()

    def test_markup_attack_regressions_are_rejected(self) -> None:
        with PackagingWorkspace() as workspace:
            source, _cache = workspace.copy_repository_with_fake_dependencies()
            index = source / "docs/index.html"
            original = index.read_text(encoding="utf-8")
            index.write_text(
                original.replace(
                    '<html lang="en">',
                    '<html lang="en" lang="fr">',
                    1,
                ),
                encoding="utf-8",
            )
            self.assertTrue(
                any("duplicate attribute" in item for item in _html_errors(source / "docs", index))
            )
            index.write_text(
                original.replace("</main>", "</section>", 1),
                encoding="utf-8",
            )
            self.assertTrue(
                any("malformed HTML" in item for item in _html_errors(source / "docs", index))
            )

            sitemap = source / "docs/sitemap.xml"
            sitemap.write_text(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<?xml-stylesheet href="https://evil.invalid/x.xsl"?>\n'
                "<urlset />\n",
                encoding="utf-8",
            )
            self.assertTrue(
                any("processing instructions" in item for item in _xml_errors(sitemap))
            )
            self.assertTrue(_routing_file_errors(source / "docs"))

            svg = source / "docs/assets/favicon.svg"
            svg.write_text(
                '<?xml-stylesheet href="x"?>\n<svg xmlns="http://www.w3.org/2000/svg"/>',
                encoding="utf-8",
            )
            self.assertTrue(
                any("processing instructions" in item for item in _svg_errors(svg))
            )

    def test_pages_tar_is_the_exact_inventory_including_nojekyll(self) -> None:
        with PackagingWorkspace() as workspace:
            archive = workspace.root / "pages.tar"
            with tarfile.open(archive, "w") as output:
                output.add(REPOSITORY_ROOT / "docs", arcname=".")
            self.assertFalse(check_pages_artifact(REPOSITORY_ROOT, archive))


class WorkflowTests(unittest.TestCase):
    @staticmethod
    def _release_ruleset_filter() -> str:
        workflow = (
            REPOSITORY_ROOT / ".github/workflows/release.yml"
        ).read_text(encoding="utf-8")
        block_start = workflow.index('RULESET_VALID="$(gh api')
        filter_start = workflow.index("--jq '", block_start) + len("--jq '")
        filter_end = workflow.index('\')"', filter_start)
        return workflow[filter_start:filter_end]

    @staticmethod
    def _exact_release_ruleset() -> dict[str, object]:
        return {
            "conditions": {
                "ref_name": {
                    "exclude": [],
                    "include": ["refs/tags/*"],
                },
            },
            "enforcement": "active",
            "name": "immutable-release-tags",
            "rules": [{"type": "deletion"}, {"type": "update"}],
            "target": "tag",
        }

    def _release_ruleset_is_valid(self, value: object) -> bool:
        result = subprocess.run(
            ["jq", "-e", self._release_ruleset_filter()],
            input=json.dumps(value),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertIn(result.returncode, (0, 1), result.stderr)
        return result.returncode == 0

    def test_full_local_gate_invokes_pages_checker(self) -> None:
        check = (REPOSITORY_ROOT / "scripts/check.sh").read_text()

        self.assertIn("-m rapp_stack_cubby.pages check", check)

    def test_workflow_policy_check_passes(self) -> None:
        self.assertFalse(check_workflows(REPOSITORY_ROOT))

    def test_every_workflow_run_block_has_valid_shell_syntax(self) -> None:
        blocks: list[tuple[Path, int, str]] = []
        scalar_markers = {"|", "|-", "|+", ">", ">-", ">+"}

        for path in sorted((REPOSITORY_ROOT / ".github/workflows").glob("*.yml")):
            lines = path.read_text(encoding="utf-8").splitlines()
            index = 0
            while index < len(lines):
                match = re.match(r"^(\s*)run:\s*(.*?)\s*$", lines[index])
                if match is None:
                    index += 1
                    continue
                line_number = index + 1
                indentation = len(match.group(1))
                value = match.group(2)
                index += 1
                if value in scalar_markers:
                    body: list[str] = []
                    while index < len(lines):
                        line = lines[index]
                        if (
                            line.strip()
                            and len(line) - len(line.lstrip()) <= indentation
                        ):
                            break
                        body.append(line)
                        index += 1
                    script = textwrap.dedent("\n".join(body)) + "\n"
                else:
                    self.assertTrue(value, f"{path.name}:{line_number}")
                    script = value + "\n"
                blocks.append((path, line_number, script))

        self.assertTrue(blocks)
        for path, line_number, script in blocks:
            with self.subTest(workflow=path.name, line=line_number):
                result = subprocess.run(
                    ["/bin/sh", "-n"],
                    input=script,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(
                    result.returncode,
                    0,
                    f"{path.name}:{line_number}: {result.stderr.strip()}",
                )

    def test_every_action_is_an_exact_locked_sha_with_tag_comment(self) -> None:
        lock = json.loads(
            (REPOSITORY_ROOT / "GITHUB_ACTIONS_LOCK.json").read_text()
        )
        pins = {
            item["uses"]: (item["commit"], item["tag"])
            for item in lock["actions"]
        }
        self.assertEqual(lock["runner"]["label"], "macos-15")
        self.assertEqual(lock["runner"]["architecture"], "arm64")
        self.assertTrue(
            lock["policy"]["protected_promotion_environment_required"]
        )
        self.assertEqual(
            lock["runner"]["label_source"],
            "https://docs.github.com/en/actions/reference/runners/github-hosted-runners#standard-github-hosted-runners-for-public-repositories",
        )
        seen: set[str] = set()
        for path in sorted((REPOSITORY_ROOT / ".github/workflows").glob("*.yml")):
            for uses, commit, tag in re.findall(
                r"uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
                r"@([0-9a-f]{40})\s+#\s+(v[0-9]+\.[0-9]+\.[0-9]+)",
                path.read_text(),
            ):
                self.assertEqual(pins[uses], (commit, tag))
                seen.add(uses)
        self.assertEqual(seen, set(pins))

    def test_events_permissions_and_release_commit_behavior_are_narrow(self) -> None:
        workflows = {
            path.name: path.read_text()
            for path in (REPOSITORY_ROOT / ".github/workflows").glob("*.yml")
        }

        self.assertNotIn("pull_request_target", "\n".join(workflows.values()))
        self.assertNotIn("secrets.", workflows["ci.yml"])
        self.assertNotIn("macos-15-arm64", "\n".join(workflows.values()))
        self.assertNotIn("cache: false", "\n".join(workflows.values()))
        self.assertTrue(
            all("runs-on: macos-15" in value for value in workflows.values())
        )
        self.assertIn("permissions:\n  contents: read", workflows["ci.yml"])
        self.assertIn("path: ./docs", workflows["pages.yml"])
        self.assertIn("include-hidden-files: true", workflows["pages.yml"])
        self.assertIn("mode=preserve", workflows["pages.yml"])
        self.assertIn("--release-manifest-sha256", workflows["pages.yml"])
        self.assertNotRegex(workflows["pages.yml"], r"(?m)^\s*path:\s*\.\s*$")
        self.assertNotIn("${{ inputs.", "\n".join(
            line
            for text in workflows.values()
            for line in text.splitlines()
            if line.lstrip().startswith(("run:", "gh ", "scripts/"))
        ))
        self.assertIn("scripts/prepare-release.sh", workflows["release.yml"])
        self.assertIn("name: release", workflows["release.yml"])
        self.assertIn("check-runs", workflows["release.yml"])
        self.assertIn("--include", workflows["release.yml"])
        self.assertIn("IMMUTABLE_HTTP_STATUS", workflows["release.yml"])
        self.assertIn(
            "immutable_releases/enforcement", workflows["release.yml"]
        )
        self.assertIn("immutable-release-tags", workflows["release.yml"])
        self.assertIn(
            "repos/${GITHUB_REPOSITORY}/rulesets", workflows["release.yml"]
        )
        self.assertIn(
            '"include": ["refs/tags/*"]',
            workflows["release.yml"],
        )
        self.assertIn(
            "(.bypass_actors == null) or (.bypass_actors == [])",
            workflows["release.yml"],
        )
        self.assertIn('.target == "tag"', workflows["release.yml"])
        self.assertIn('.enforcement == "active"', workflows["release.yml"])
        self.assertIn(
            "(.rules | sort_by(.type))",
            workflows["release.yml"],
        )
        self.assertLess(
            workflows["release.yml"].index("immutable_releases/enforcement"),
            workflows["release.yml"].index("immutable-release-tags"),
        )
        self.assertIn("scripts/postflight-release.sh", workflows["release.yml"])
        self.assertIn(
            'test "${DISPATCH_REF}" = "refs/tags/${INPUT_TAG}"',
            workflows["release.yml"],
        )
        self.assertIn(
            'test "${DISPATCH_SHA}" = "${INPUT_COMMIT}"',
            workflows["release.yml"],
        )
        self.assertIn("candidate-publication-scan.json", workflows["release.yml"])
        self.assertIn("postflight-success.json", workflows["release.yml"])
        self.assertIn("actions/upload-artifact@", workflows["release.yml"])
        self.assertNotIn("gh release upload", workflows["release.yml"])
        self.assertIn("name: promotion", workflows["promote.yml"])
        self.assertIn("scripts/promote-release.sh", workflows["promote.yml"])
        promote = workflows["promote.yml"]
        toolchain = promote.index("scripts/check-toolchain.sh")
        install = promote.index("python -m pip install")
        context = promote.index("scripts/context-check.sh")
        full_check = promote.index("scripts/check.sh")
        self.assertLess(toolchain, install)
        self.assertLess(install, context)
        self.assertLess(context, full_check)
        self.assertIn("--require-hashes -r requirements-ci.lock", promote)
        self.assertIn("--only-binary=:all:", promote)
        self.assertIn("--no-deps", promote)
        self.assertIn('--ref "${RELEASE_TAG}"', workflows["promote.yml"])
        self.assertIn("final-promotion-evidence", workflows["promote.yml"])
        self.assertNotIn("gh release upload", workflows["promote.yml"])
        self.assertIn("actions/download-artifact@", workflows["pages.yml"])
        self.assertNotRegex(
            workflows["release.yml"], r"(?m)^\s+tags:\s*$"
        )
        self.assertNotRegex(
            workflows["release.yml"], r"\bgit\s+(?:commit|push)\b"
        )

    def test_release_fallback_accepts_absent_or_null_bypass_actors(self) -> None:
        absent = self._exact_release_ruleset()
        explicit_null = self._exact_release_ruleset()
        explicit_null["bypass_actors"] = None

        self.assertTrue(self._release_ruleset_is_valid(absent))
        self.assertTrue(self._release_ruleset_is_valid(explicit_null))

    def test_release_fallback_accepts_empty_bypass_actors(self) -> None:
        value = self._exact_release_ruleset()
        value["bypass_actors"] = []

        self.assertTrue(self._release_ruleset_is_valid(value))

    def test_release_fallback_rejects_nonempty_bypass_actors(self) -> None:
        value = self._exact_release_ruleset()
        value["bypass_actors"] = [
            {"actor_id": 1, "actor_type": "RepositoryRole"},
        ]

        self.assertFalse(self._release_ruleset_is_valid(value))

    def test_release_fallback_rejects_every_other_ruleset_mismatch(self) -> None:
        top_level = {
            "name": "other",
            "target": "branch",
            "enforcement": "disabled",
        }
        for field, replacement in top_level.items():
            with self.subTest(field=field):
                value = self._exact_release_ruleset()
                value[field] = replacement
                self.assertFalse(self._release_ruleset_is_valid(value))

        condition_mismatches = {
            "missing-ref-name": {},
            "missing-include": {"ref_name": {"exclude": []}},
            "wrong-include": {
                "ref_name": {
                    "exclude": [],
                    "include": ["refs/tags/v*"],
                },
            },
            "nonempty-exclude": {
                "ref_name": {
                    "exclude": ["refs/tags/internal-*"],
                    "include": ["refs/tags/*"],
                },
            },
            "extra-condition": {
                "ref_name": {
                    "exclude": [],
                    "include": ["refs/tags/*"],
                    "unexpected": True,
                },
            },
        }
        for label, conditions in condition_mismatches.items():
            with self.subTest(condition=label):
                value = self._exact_release_ruleset()
                value["conditions"] = conditions
                self.assertFalse(self._release_ruleset_is_valid(value))

        rule_mismatches: dict[str, object] = {
            "missing-deletion": [{"type": "update"}],
            "missing-update": [{"type": "deletion"}],
            "duplicate": [{"type": "deletion"}, {"type": "deletion"}],
            "extra": [
                {"type": "deletion"},
                {"type": "update"},
                {"type": "creation"},
            ],
            "wrong-type": [{"type": "creation"}, {"type": "update"}],
            "wrong-shape": {
                "first": {"type": "deletion"},
                "second": {"type": "update"},
            },
            "extra-field": [
                {"type": "deletion"},
                {"parameters": {}, "type": "update"},
            ],
        }
        for label, rules in rule_mismatches.items():
            with self.subTest(rules=label):
                value = self._exact_release_ruleset()
                value["rules"] = rules
                self.assertFalse(self._release_ruleset_is_valid(value))

        reversed_rules = self._exact_release_ruleset()
        reversed_rules["rules"] = list(reversed(reversed_rules["rules"]))
        self.assertTrue(self._release_ruleset_is_valid(reversed_rules))


class VersionTests(unittest.TestCase):
    def test_candidate_version_agrees_across_source_manifests(self) -> None:
        version = (REPOSITORY_ROOT / "VERSION").read_text().strip()
        values = [
            json.loads(
                (
                    REPOSITORY_ROOT
                    / "cubbies/kody-w/rapplications/rapp-stack/manifest.json"
                ).read_text()
            )["version"],
            json.loads(
                (
                    REPOSITORY_ROOT
                    / "cubbies/kody-w/rapplications/rapp-stack/index_entry.json"
                ).read_text()
            )["version"],
            json.loads((REPOSITORY_ROOT / "STORE_INDEX.json").read_text())[
                "version"
            ],
            json.loads((REPOSITORY_ROOT / "rapp-super-rar.json").read_text())[
                "version"
            ],
            json.loads((REPOSITORY_ROOT / "RELEASE_STATUS.json").read_text())[
                "version"
            ],
            json.loads(
                (
                    REPOSITORY_ROOT / "cubbies/kody-w/cubby.json"
                ).read_text()
            )["product_version"],
        ]

        self.assertEqual(version, "0.1.0rc11")
        self.assertEqual(values, [version] * len(values))
        status = json.loads(
            (REPOSITORY_ROOT / "RELEASE_STATUS.json").read_text()
        )
        self.assertEqual(status["tag"], "v0.1.0-rc.11")


if __name__ == "__main__":
    unittest.main()
