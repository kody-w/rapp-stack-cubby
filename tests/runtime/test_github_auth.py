from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
import urllib.parse
from pathlib import Path

from rapp_stack_cubby.context import validate_schema_instance
from rapp_stack_cubby.runtime.github_auth import (
    GITHUB_TOKEN_SCHEMA,
    GitHubAuthError,
    device_login,
    read_github_token_file,
    refresh_token_file,
)
from rapp_stack_cubby.runtime.provider import CopilotProvider

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self.status = 200
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self, amount: int = -1) -> bytes:
        return self._raw if amount < 0 else self._raw[:amount]

    def close(self) -> None:
        return None


class RecordingOpener:
    def __init__(self, *payloads: object) -> None:
        self.responses = [FakeResponse(payload) for payload in payloads]
        self.requests = []

    def __call__(self, request, *, timeout):
        self.requests.append((request, timeout))
        if not self.responses:
            raise AssertionError("unexpected OAuth request")
        return self.responses.pop(0)


class GitHubTokenFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".github-auth-",
            dir=REPOSITORY_ROOT,
        )
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self, payload: object, *, mode: int = 0o600) -> Path:
        path = self.root / "provider-token.json"
        path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        os.chmod(path, mode)
        return path

    def test_reads_versioned_and_legacy_bounded_json(self) -> None:
        versioned = self._write(
            {
                "schema": GITHUB_TOKEN_SCHEMA,
                "access_token": "synthetic-access",
                "refresh_token": "synthetic-refresh",
            }
        )
        credential = read_github_token_file(versioned)
        self.assertEqual(credential.access_token, "synthetic-access")
        self.assertEqual(credential.refresh_token, "synthetic-refresh")

        versioned.write_text(
            json.dumps({"access_token": "legacy-access"}) + "\n",
            encoding="utf-8",
        )
        os.chmod(versioned, 0o600)
        legacy = read_github_token_file(versioned)
        self.assertEqual(legacy.access_token, "legacy-access")
        self.assertIsNone(legacy.refresh_token)

    def test_versioned_token_schema_accepts_only_private_contract_fields(self):
        schema_path = (
            REPOSITORY_ROOT / "schemas/copilot-token.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        payload = {
            "schema": GITHUB_TOKEN_SCHEMA,
            "access_token": "synthetic-access",
            "refresh_token": "synthetic-refresh",
        }
        self.assertEqual(
            validate_schema_instance(
                payload,
                schema,
                schema_path=schema_path,
            ),
            [],
        )
        payload["token_path"] = "forbidden"
        self.assertTrue(
            validate_schema_instance(
                payload,
                schema,
                schema_path=schema_path,
            )
        )

    def test_rejects_relative_symlink_wrong_mode_extra_fields_and_size(self) -> None:
        path = self._write({"access_token": "synthetic-access"})
        with self.assertRaisesRegex(GitHubAuthError, "absolute"):
            read_github_token_file(Path(path.name))

        os.chmod(path, 0o644)
        with self.assertRaisesRegex(GitHubAuthError, "0600"):
            read_github_token_file(path)
        os.chmod(path, 0o600)

        linked = self.root / "linked"
        linked.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(GitHubAuthError, "symbolic"):
            read_github_token_file(linked / path.name)

        path.write_text(
            json.dumps(
                {
                    "access_token": "synthetic-access",
                    "unexpected": True,
                }
            ),
            encoding="utf-8",
        )
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(GitHubAuthError, "legacy"):
            read_github_token_file(path)

        path.write_bytes(b"{" + b"x" * (64 * 1024) + b"}")
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(GitHubAuthError, "size"):
            read_github_token_file(path)

    def test_provider_explicit_file_precedes_environment_and_gh(self) -> None:
        path = self._write({"access_token": "file-access"})

        def forbidden(*args, **kwargs):
            raise AssertionError("gh must not be called")

        provider = CopilotProvider(
            model="synthetic-model",
            github_token_file=path,
            environment={"GITHUB_TOKEN": "environment-access"},
            run_command=forbidden,
        )
        self.assertEqual(provider.resolve_github_token(), "file-access")


class GitHubDeviceFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".github-device-",
            dir=REPOSITORY_ROOT,
        )
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.path = self.root / "provider-token.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_pending_slow_down_success_is_bounded_and_mode_0600(self) -> None:
        opener = RecordingOpener(
            {
                "device_code": "synthetic-device-secret",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://github.com/login/device",
                "expires_in": 120,
                "interval": 1,
            },
            {"error": "authorization_pending"},
            {"error": "slow_down"},
            {
                "access_token": "synthetic-access",
                "refresh_token": "synthetic-refresh",
                "token_type": "bearer",
            },
        )
        now = [0.0]
        displayed: list[str] = []

        result = device_login(
            self.path,
            timeout=60,
            urlopen=opener,
            sleep=lambda seconds: now.__setitem__(0, now[0] + seconds),
            clock=lambda: now[0],
            display=displayed.append,
        )

        self.assertTrue(result["authenticated"])
        self.assertEqual(
            stat.S_IMODE(self.path.stat().st_mode),
            0o600,
        )
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], GITHUB_TOKEN_SCHEMA)
        rendered = "\n".join(displayed)
        self.assertIn("https://github.com/login/device", rendered)
        self.assertIn("ABCD-EFGH", rendered)
        self.assertNotIn("synthetic-device-secret", rendered)
        self.assertNotIn("synthetic-access", rendered)
        poll_fields = urllib.parse.parse_qs(
            opener.requests[-1][0].data.decode("ascii")
        )
        self.assertEqual(
            poll_fields["grant_type"],
            ["urn:ietf:params:oauth:grant-type:device_code"],
        )
        self.assertEqual(now[0], 8.0)

    def test_cancel_and_expiry_never_create_token_file(self) -> None:
        device = {
            "device_code": "synthetic-device-secret",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://github.com/login/device",
            "expires_in": 30,
            "interval": 1,
        }
        with self.assertRaisesRegex(GitHubAuthError, "cancelled"):
            device_login(
                self.path,
                timeout=30,
                urlopen=RecordingOpener(device),
                sleep=lambda seconds: (_ for _ in ()).throw(
                    KeyboardInterrupt()
                ),
                clock=lambda: 0.0,
                display=lambda line: None,
            )
        self.assertFalse(self.path.exists())

        now = [0.0]
        with self.assertRaisesRegex(GitHubAuthError, "expired"):
            device_login(
                self.path,
                timeout=30,
                urlopen=RecordingOpener(device),
                sleep=lambda seconds: now.__setitem__(
                    0, now[0] + seconds + 30
                ),
                clock=lambda: now[0],
                display=lambda line: None,
            )
        self.assertFalse(self.path.exists())

    def test_refresh_replaces_token_without_returning_credentials(self) -> None:
        self.path.write_text(
            json.dumps(
                {
                    "schema": GITHUB_TOKEN_SCHEMA,
                    "access_token": "old-access",
                    "refresh_token": "old-refresh",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        os.chmod(self.path, 0o600)
        opener = RecordingOpener(
            {
                "access_token": "new-access",
                "refresh_token": "new-refresh",
            }
        )

        result = refresh_token_file(
            self.path,
            urlopen=opener,
        )

        credential = read_github_token_file(self.path)
        self.assertEqual(credential.access_token, "new-access")
        self.assertEqual(credential.refresh_token, "new-refresh")
        rendered = json.dumps(result)
        self.assertNotIn("old-access", rendered)
        self.assertNotIn("old-refresh", rendered)
        self.assertNotIn("new-access", rendered)
        self.assertNotIn("new-refresh", rendered)


if __name__ == "__main__":
    unittest.main()
