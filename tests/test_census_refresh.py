from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapp_stack_cubby.census_refresh import (
    ApiResponse,
    CensusRefreshError,
    _parse_included_response,
    _safe_error_detail,
    build_refresh_candidate,
    write_refresh_candidate,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class _FakeClient:
    tool_version = "gh version test"

    def __init__(self, pages, heads):
        self.pages = pages
        self.heads = heads
        self.calls = []

    def get(self, path, *, parameters=None):
        self.calls.append((path, parameters))
        if path.endswith("/repos"):
            page = int(parameters["page"])
            return self.pages[page - 1]
        name = path.split("/")[2]
        return self.heads[name]


def _repository(index: int, *, created_at="2026-07-13T00:00:00Z"):
    name = f"repo-{index:03}"
    return {
        "archived": False,
        "created_at": created_at,
        "default_branch": "main",
        "description": None,
        "disabled": False,
        "fork": False,
        "full_name": f"kody-w/{name}",
        "has_pages": False,
        "homepage": None,
        "html_url": f"https://github.com/kody-w/{name}",
        "id": index,
        "language": "Python",
        "license": {"spdx_id": "MIT"},
        "name": name,
        "private": False,
        "pushed_at": "2026-07-13T00:00:00Z",
        "size": 1,
        "topics": ["rapp", "test"],
        "updated_at": "2026-07-13T00:00:00Z",
        "visibility": "public",
    }


class CensusRefreshTests(unittest.TestCase):
    def test_paginates_resolves_heads_and_builds_deterministic_diff(self):
        first = [_repository(index) for index in range(100)]
        second = [_repository(100)]
        pages = [
            ApiResponse(200, {"etag": '"first"'}, first),
            ApiResponse(200, {"etag": '"second"'}, second),
        ]
        heads = {
            item["name"]: ApiResponse(
                200, {}, {"sha": f"{item['id']:040x}"}
            )
            for item in first + second
        }
        client = _FakeClient(pages, heads)
        baseline = {
            "repositories": [
                {"name": "repo-000", "head_sha": "0" * 40, "classification": "C"},
                {"name": "removed", "head_sha": "f" * 40, "classification": "A"},
            ]
        }

        candidate = build_refresh_candidate(
            client,
            owner="kody-w",
            cutoff="2026-07-13T03:59:43.787Z",
            baseline=baseline,
        )

        self.assertEqual(candidate["raw_inventory"]["repository_count"], 101)
        self.assertEqual([page["item_count"] for page in candidate["response_pages"]], [100, 1])
        self.assertEqual(candidate["diff"]["removed"], ["removed"])
        self.assertEqual(candidate["diff"]["added"][0], "repo-001")
        self.assertEqual(
            [item["candidate_audit_shard"] for item in candidate["repositories"][:9]],
            [0, 1, 2, 3, 4, 5, 6, 7, 0],
        )
        self.assertEqual(len(candidate["raw_inventory"]["sha256"]), 64)
        self.assertEqual(
            len(candidate["raw_inventory"]["inventory_records_sha256"]), 64
        )
        self.assertEqual(
            len(candidate["raw_inventory"]["head_observations_sha256"]), 64
        )
        self.assertEqual(len(candidate["head_observations"]), 101)
        self.assertEqual(
            candidate["repositories"][0]["current_observed_at"],
            candidate["head_observations"][0]["observed_at"],
        )
        self.assertEqual(
            candidate["repositories"][0]["head_observed_at"],
            candidate["head_observations"][0]["head_observed_at"],
        )
        self.assertEqual(candidate["repositories"][0]["topics"], ["rapp", "test"])
        self.assertFalse(candidate["repositories"][0]["private"])
        self.assertLessEqual(
            candidate["capture_started_at"],
            candidate["inventory_completed_at"],
        )
        self.assertLessEqual(
            candidate["inventory_completed_at"],
            candidate["heads_started_at"],
        )
        self.assertLessEqual(
            candidate["heads_started_at"],
            candidate["capture_completed_at"],
        )
        for page in candidate["response_pages"]:
            self.assertEqual(len(page["body_sha256"]), 64)
            self.assertIn("response_time_ms", page)

    def test_empty_repository_head_is_recorded(self):
        repository = _repository(1)
        repository["size"] = 0
        client = _FakeClient(
            [ApiResponse(200, {}, [repository])],
            {repository["name"]: ApiResponse(409, {}, {"message": "empty"})},
        )
        candidate = build_refresh_candidate(
            client,
            owner="kody-w",
            cutoff="2026-07-13T03:59:43Z",
            baseline={"repositories": []},
        )
        record = candidate["repositories"][0]
        self.assertIsNone(record["current_head_sha"])
        self.assertEqual(record["head_status"], "empty_repository")
        self.assertEqual(
            candidate["head_observations"][0]["head_status"],
            "empty_repository",
        )

    def test_empty_repository_without_default_branch_is_actually_queried(self):
        repository = _repository(1)
        repository["default_branch"] = None
        repository["size"] = 0
        client = _FakeClient(
            [ApiResponse(200, {}, [repository])],
            {repository["name"]: ApiResponse(409, {}, {"message": "empty"})},
        )

        candidate = build_refresh_candidate(
            client,
            owner="kody-w",
            cutoff="2026-07-13T03:59:43Z",
            baseline={"repositories": []},
        )

        head_path, parameters = client.calls[-1]
        self.assertEqual(head_path, "repos/kody-w/repo-001/commits")
        self.assertEqual(parameters, {"per_page": "1"})
        self.assertEqual(
            candidate["repositories"][0]["current_observed_at"],
            candidate["head_observations"][0]["response_received_at"],
        )

    def test_rate_limit_and_api_errors_fail_closed(self):
        for status in (403, 429, 500):
            with self.subTest(status=status):
                client = _FakeClient(
                    [
                        ApiResponse(
                            status,
                            {
                                "x-ratelimit-remaining": "0",
                                "x-ratelimit-reset": "123",
                            },
                            {"message": "do not persist this body"},
                        )
                    ],
                    {},
                )
                with self.assertRaises(CensusRefreshError) as raised:
                    build_refresh_candidate(
                        client,
                        owner="kody-w",
                        cutoff="2026-07-13T03:59:43Z",
                        baseline={"repositories": []},
                    )
                self.assertNotIn("do not persist", str(raised.exception))

    def test_parser_keeps_only_safe_headers_and_error_redacts_tokens(self):
        response = _parse_included_response(
            b"HTTP/2.0 200 OK\r\n"
            b"Etag: W/\"abc\"\r\n"
            b"X-Oauth-Scopes: repo\r\n"
            b"\r\n"
            b"[]"
        )
        self.assertEqual(response.headers, {"etag": 'W/"abc"'})
        token = b"ghp_" + b"abcdefghijklmnopqrstuvwxyz1234"
        detail = _safe_error_detail(b"failed " + token)
        self.assertNotIn("ghp_", detail)

    def test_free_text_public_identifiers_are_sanitized(self):
        repository = _repository(1)
        repository["description"] = "public identity person@example.com"
        client = _FakeClient(
            [ApiResponse(200, {}, [repository])],
            {repository["name"]: ApiResponse(200, {}, {"sha": "1" * 40})},
        )
        candidate = build_refresh_candidate(
            client,
            owner="kody-w",
            cutoff="2026-07-13T03:59:43Z",
            baseline={"repositories": []},
        )
        self.assertEqual(
            candidate["repositories"][0]["description"],
            "public identity [PUBLIC-IDENTIFIER-REDACTED]",
        )

    def test_requires_exact_cutoff_and_protects_audited_output(self):
        client = _FakeClient([ApiResponse(200, {}, [])], {})
        with self.assertRaises(CensusRefreshError):
            build_refresh_candidate(
                client,
                owner="kody-w",
                cutoff="2026-07-13",
                baseline={"repositories": []},
            )
        with self.assertRaises(CensusRefreshError):
            write_refresh_candidate(
                REPOSITORY_ROOT,
                "SOURCE_CENSUS.json",
                owner="kody-w",
                cutoff="2026-07-13T03:59:43Z",
                client=client,
            )

    def test_explicit_candidate_output_is_written_inside_repository(self):
        with tempfile.TemporaryDirectory(
            prefix=".test-census-refresh-", dir=REPOSITORY_ROOT
        ) as temporary:
            root = Path(temporary)
            (root / "SOURCE_CENSUS.json").write_text(
                json.dumps({"repositories": []}) + "\n", encoding="utf-8"
            )
            client = _FakeClient([ApiResponse(200, {"etag": '"empty"'}, [])], {})
            candidate = write_refresh_candidate(
                root,
                "candidate/result.json",
                owner="kody-w",
                cutoff="2026-07-13T03:59:43Z",
                client=client,
            )
            written = json.loads(
                (root / "candidate/result.json").read_text(encoding="utf-8")
            )
            self.assertEqual(written, candidate)


if __name__ == "__main__":
    unittest.main()
