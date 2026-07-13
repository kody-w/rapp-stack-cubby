from __future__ import annotations

import io
import json
import os
import plistlib
import stat
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from rapp_stack_cubby.cli import main
from rapp_stack_cubby.imessage.cli import (
    LAUNCH_AGENT_LABEL,
    OwnerChatBinding,
    discover_owner_binding,
)
from rapp_stack_cubby.imessage.config import ConfigError
from rapp_stack_cubby.imessage.source_scan import scan_imessage_sources

from tests.agents._support import AgentEnvironment, decoded

from ._support import REPOSITORY_ROOT, WorkDirectory, make_config


class IMessageCliAgentInstallerTests(unittest.TestCase):
    def test_owner_discovery_binds_realistic_account_from_same_catalog(self) -> None:
        catalog = json.loads(
            (
                REPOSITORY_ROOT
                / "tests/fixtures/imsg-v0.12.3-chat-catalog.json"
            ).read_text(encoding="utf-8")
        )
        responses = [
            subprocess.CompletedProcess([], 0, "0.12.3\n", ""),
            subprocess.CompletedProcess([], 0, json.dumps(catalog), ""),
        ]
        with mock.patch(
            "rapp_stack_cubby.imessage.cli.verify_installed_imsg",
            return_value={"ok": True},
        ), mock.patch(
            "rapp_stack_cubby.imessage.cli._run_bounded",
            side_effect=responses,
        ):
            binding = discover_owner_binding(
                Path("/synthetic/imsg"),
                ["synthetic-owner-handle"],
            )
        self.assertEqual(
            binding.account_id,
            "E:synthetic-owner@invalid.example",
        )
        self.assertEqual(
            binding.chat_ids,
            ("42", "iMessage;-;synthetic-owner-handle"),
        )

    def test_owner_discovery_rejects_inconsistent_accounts(self) -> None:
        chats = [
            {
                "account_id": account,
                "guid": f"iMessage;-;synthetic-owner-handle-{index}",
                "id": index,
                "identifier": "synthetic-owner-handle",
                "is_group": False,
                "participants": ["synthetic-owner-handle"],
                "service": "iMessage",
            }
            for index, account in enumerate(("E:first", "E:second"), 1)
        ]
        responses = [
            subprocess.CompletedProcess([], 0, "0.12.3\n", ""),
            subprocess.CompletedProcess(
                [], 0, json.dumps({"chats": chats}), ""
            ),
        ]
        with mock.patch(
            "rapp_stack_cubby.imessage.cli.verify_installed_imsg",
            return_value={"ok": True},
        ), mock.patch(
            "rapp_stack_cubby.imessage.cli._run_bounded",
            side_effect=responses,
        ), self.assertRaises(ConfigError):
            discover_owner_binding(
                Path("/synthetic/imsg"),
                ["synthetic-owner-handle"],
            )

    def test_same_account_duplicate_chats_require_private_disambiguation(self) -> None:
        chats = [
            {
                "account_id": "E:synthetic-owner@invalid.example",
                "guid": f"iMessage;-;synthetic-owner-handle-{index}",
                "id": index,
                "identifier": "synthetic-owner-handle",
                "is_group": False,
                "participants": ["synthetic-owner-handle"],
                "service": "iMessage",
            }
            for index in (41, 42)
        ]

        def discover(selected=()):
            responses = [
                subprocess.CompletedProcess([], 0, "0.12.3\n", ""),
                subprocess.CompletedProcess(
                    [],
                    0,
                    json.dumps({"chats": chats}),
                    "",
                ),
            ]
            with mock.patch(
                "rapp_stack_cubby.imessage.cli.verify_installed_imsg",
                return_value={"ok": True},
            ), mock.patch(
                "rapp_stack_cubby.imessage.cli._run_bounded",
                side_effect=responses,
            ):
                return discover_owner_binding(
                    Path("/synthetic/imsg"),
                    ["synthetic-owner-handle"],
                    selected_chat_ids=selected,
                )

        with self.assertRaises(ConfigError):
            discover()
        binding = discover(("42",))
        self.assertEqual(
            binding,
            OwnerChatBinding(
                ("42", "iMessage;-;synthetic-owner-handle-42"),
                "E:synthetic-owner@invalid.example",
            ),
        )

    def test_imessage_source_privacy_scan_passes(self) -> None:
        result = scan_imessage_sources(REPOSITORY_ROOT)
        self.assertTrue(result.ok, result.findings)

    def test_tutorial_covers_complete_fresh_fork_flow(self) -> None:
        tutorial = (
            REPOSITORY_ROOT / "docs/operations/IMESSAGE_ONBOARDING.md"
        ).read_text(encoding="utf-8").casefold()
        for required in (
            "macos arm64",
            "python 3.11",
            "gh auth login",
            "full disk access",
            "automation",
            "controller-loadout",
            "exact public twin",
            "silent",
            "foreground smoke test",
            "signed twin-chat",
            "launchagent",
            "sleep/wake",
            "ambiguous send",
            "privacy-preserving backup",
            "safe uninstall",
        ):
            with self.subTest(required=required):
                self.assertIn(required, tutorial)

    def test_lock_records_exact_imsg_evidence(self) -> None:
        dependency = json.loads(
            (REPOSITORY_ROOT / "DEPENDENCY_LOCK.json").read_text(encoding="utf-8")
        )
        imsg = dependency["tools"][0]
        self.assertEqual(imsg["version"], "0.12.3")
        self.assertEqual(
            imsg["source"]["annotated_ref"],
            "76585a9e13a33534bec26d5478482efcc238f803",
        )
        self.assertEqual(
            imsg["source"]["commit"],
            "dea78a9e9c493740575b03e443041ef5fbd2d463",
        )
        self.assertEqual(
            imsg["release"]["archive_sha256"],
            "35977a22e9721440acf9f5b945d67034939948ba4fa4ea46b0f55d527f24d4f2",
        )
        self.assertEqual(imsg["signing"]["team_id"], "Y5PE65HELJ")
        stack = json.loads(
            (REPOSITORY_ROOT / "STACK_LOCK.json").read_text(encoding="utf-8")
        )
        self.assertNotIn(
            "imsg-release-hash",
            {item["id"] for item in stack["unresolved"]},
        )
        installed = stack["dependency_policy"]["imsg"]["installed_verification"]
        self.assertTrue(installed["codesign_strict_verified"])
        self.assertTrue(installed["archive_hash_verified"])
        self.assertFalse(installed["owner_config_initialized"])
        self.assertFalse(installed["message_sent"])

    def test_init_never_prints_discovered_identifiers(self) -> None:
        with WorkDirectory() as root:
            config = root / "config.json"
            raw_chat = "private-chat-sentinel"
            auth_dir = root / "controller-auth"
            auth_dir.mkdir(mode=0o700)
            auth_token = auth_dir / "controller-auth.token"
            auth_token.write_bytes(b"\x22" * 32)
            os.chmod(auth_token, 0o600)
            output = io.StringIO()
            with mock.patch(
                "rapp_stack_cubby.imessage.cli.discover_owner_binding",
                return_value=OwnerChatBinding(
                    (raw_chat,),
                    "primary-account",
                ),
            ), redirect_stdout(output):
                status = main(
                    [
                        "imessage",
                        "init",
                        "--config",
                        str(config),
                        "--state-dir",
                        str(root / "state"),
                        "--imsg",
                        str(root / "tools" / "bin" / "imsg"),
                        "--global-controller-url",
                        "http://127.0.0.1:8756/chat",
                        "--controller-auth-token-file",
                        str(auth_token),
                        "--target-rappid",
                        (
                            "rappid:@sample-owner/sample-twin:"
                            "0000000000000000000000000000000000000000000000000000000000000000"
                        ),
                        "--owner",
                        "private-owner-sentinel",
                    ]
                )
            self.assertEqual(status, 0)
            self.assertNotIn(raw_chat, output.getvalue())
            self.assertNotIn("private-owner-sentinel", output.getvalue())
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)

    def test_status_is_content_free(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            config.state_dir.mkdir(mode=0o700)
            status_path = config.state_dir / "status.json"
            status_path.write_text(
                json.dumps(
                    {
                        "dropped": 1,
                        "failed": 0,
                        "heartbeat_at": 0,
                        "imsg_version": "0.12.3",
                        "lifecycle": "stopped",
                        "pending": 0,
                        "processed": 2,
                        "read_ready": False,
                        "ready": False,
                        "restart_count": 1,
                        "send_ready": None,
                        "transport_ready": False,
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(status_path, 0o600)
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "imessage",
                        "status",
                        "--config",
                        str(config.config_path),
                    ]
                )
            self.assertEqual(result, 1)
            value = json.loads(output.getvalue())
            self.assertNotIn("path", value)
            self.assertNotIn("owner", value)
            self.assertNotIn("content", value)

    def test_service_plist_is_per_user_aqua_and_not_started(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            home = root / "home"
            launch_agents = home / "Library" / "LaunchAgents"
            plist = launch_agents / f"{LAUNCH_AGENT_LABEL}.plist"
            output = io.StringIO()
            with mock.patch("pathlib.Path.home", return_value=home), redirect_stdout(
                output
            ):
                result = main(
                    [
                        "imessage",
                        "service-install",
                        "--config",
                        str(config.config_path),
                        "--python",
                        str(Path(sys.executable).resolve()),
                        "--source-root",
                        str(REPOSITORY_ROOT),
                        "--plist",
                        str(plist),
                    ]
                )
            self.assertEqual(result, 0)
            value = plistlib.loads(plist.read_bytes())
            self.assertEqual(value["Label"], LAUNCH_AGENT_LABEL)
            self.assertEqual(value["LimitLoadToSessionType"], "Aqua")
            self.assertNotIn("LaunchDaemon", str(value))
            self.assertNotIn("Program", value)
            self.assertEqual(json.loads(output.getvalue())["loaded"], False)
            self.assertEqual(stat.S_IMODE(plist.stat().st_mode), 0o600)

    def test_service_uninstall_preserves_plist_when_bootout_fails(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            home = root / "home"
            plist = (
                home
                / "Library"
                / "LaunchAgents"
                / f"{LAUNCH_AGENT_LABEL}.plist"
            )
            with mock.patch("pathlib.Path.home", return_value=home):
                self.assertEqual(
                    main(
                        [
                            "imessage",
                            "service-install",
                            "--config",
                            str(config.config_path),
                            "--python",
                            str(Path(sys.executable).resolve()),
                            "--source-root",
                            str(REPOSITORY_ROOT),
                            "--plist",
                            str(plist),
                        ]
                    ),
                    0,
                )
                with mock.patch(
                    "rapp_stack_cubby.imessage.cli.subprocess.run",
                    side_effect=[
                        subprocess.CompletedProcess([], 0, "service = {}", ""),
                        subprocess.CompletedProcess(
                            [], 5, "", "synthetic bootout failure"
                        ),
                        subprocess.CompletedProcess(
                            [], 0, "service = {}", ""
                        ),
                    ],
                ), redirect_stderr(io.StringIO()):
                    result = main(
                        [
                            "imessage",
                            "service-uninstall",
                            "--config",
                            str(config.config_path),
                            "--plist",
                            str(plist),
                            "--stop",
                        ]
                    )
            self.assertEqual(result, 2)
            self.assertTrue(plist.is_file())

    def test_install_then_uninstall_removes_verified_unloaded_plist(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            home = root / "home"
            plist = (
                home
                / "Library"
                / "LaunchAgents"
                / f"{LAUNCH_AGENT_LABEL}.plist"
            )
            not_loaded = subprocess.CompletedProcess(
                [],
                113,
                "",
                "Could not find service",
            )
            output = io.StringIO()
            with mock.patch("pathlib.Path.home", return_value=home):
                self.assertEqual(
                    main(
                        [
                            "imessage",
                            "service-install",
                            "--config",
                            str(config.config_path),
                            "--python",
                            str(Path(sys.executable).resolve()),
                            "--source-root",
                            str(REPOSITORY_ROOT),
                            "--plist",
                            str(plist),
                        ]
                    ),
                    0,
                )
                with mock.patch(
                    "rapp_stack_cubby.imessage.cli.subprocess.run",
                    side_effect=[not_loaded, not_loaded],
                ), redirect_stdout(output):
                    result = main(
                        [
                            "imessage",
                            "service-uninstall",
                            "--config",
                            str(config.config_path),
                            "--plist",
                            str(plist),
                        ]
                    )
            self.assertEqual(result, 0)
            self.assertFalse(plist.exists())
            self.assertEqual(
                json.loads(output.getvalue().splitlines()[-1]),
                {"removed": True, "stopped": False},
            )

    def test_loaded_uninstall_requires_stop_and_confirms_bootout(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            home = root / "home"
            plist = (
                home
                / "Library"
                / "LaunchAgents"
                / f"{LAUNCH_AGENT_LABEL}.plist"
            )
            loaded = subprocess.CompletedProcess([], 0, "service = {}", "")
            not_loaded = subprocess.CompletedProcess(
                [],
                113,
                "",
                "Could not find service",
            )
            with mock.patch("pathlib.Path.home", return_value=home):
                self.assertEqual(
                    main(
                        [
                            "imessage",
                            "service-install",
                            "--config",
                            str(config.config_path),
                            "--python",
                            str(Path(sys.executable).resolve()),
                            "--source-root",
                            str(REPOSITORY_ROOT),
                            "--plist",
                            str(plist),
                        ]
                    ),
                    0,
                )
                with mock.patch(
                    "rapp_stack_cubby.imessage.cli.subprocess.run",
                    return_value=loaded,
                ), redirect_stderr(io.StringIO()):
                    self.assertEqual(
                        main(
                            [
                                "imessage",
                                "service-uninstall",
                                "--config",
                                str(config.config_path),
                                "--plist",
                                str(plist),
                            ]
                        ),
                        2,
                    )
                self.assertTrue(plist.exists())
                with mock.patch(
                    "rapp_stack_cubby.imessage.cli.subprocess.run",
                    side_effect=[
                        loaded,
                        subprocess.CompletedProcess([], 0, "", ""),
                        not_loaded,
                        not_loaded,
                    ],
                ), redirect_stdout(io.StringIO()):
                    self.assertEqual(
                        main(
                            [
                                "imessage",
                                "service-uninstall",
                                "--config",
                                str(config.config_path),
                                "--plist",
                                str(plist),
                                "--stop",
                            ]
                        ),
                        0,
                    )
            self.assertFalse(plist.exists())

    def test_failed_bootout_may_remove_only_after_verified_unloaded(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            home = root / "home"
            plist = (
                home
                / "Library"
                / "LaunchAgents"
                / f"{LAUNCH_AGENT_LABEL}.plist"
            )
            loaded = subprocess.CompletedProcess([], 0, "service = {}", "")
            failed = subprocess.CompletedProcess([], 5, "", "failure")
            not_loaded = subprocess.CompletedProcess(
                [],
                113,
                "",
                "Could not find service",
            )
            with mock.patch("pathlib.Path.home", return_value=home):
                self.assertEqual(
                    main(
                        [
                            "imessage",
                            "service-install",
                            "--config",
                            str(config.config_path),
                            "--python",
                            str(Path(sys.executable).resolve()),
                            "--source-root",
                            str(REPOSITORY_ROOT),
                            "--plist",
                            str(plist),
                        ]
                    ),
                    0,
                )
                with mock.patch(
                    "rapp_stack_cubby.imessage.cli.subprocess.run",
                    side_effect=[loaded, failed, not_loaded, not_loaded],
                ), redirect_stdout(io.StringIO()):
                    result = main(
                        [
                            "imessage",
                            "service-uninstall",
                            "--config",
                            str(config.config_path),
                            "--plist",
                            str(plist),
                            "--stop",
                        ]
                    )
            self.assertEqual(result, 0)
            self.assertFalse(plist.exists())

    def test_installer_is_immutable_and_avoids_unsafe_staging(self) -> None:
        installer = (REPOSITORY_ROOT / "scripts/install-imsg.sh").read_text(
            encoding="utf-8"
        )
        uninstaller = (REPOSITORY_ROOT / "scripts/uninstall-imsg.sh").read_text(
            encoding="utf-8"
        )
        for expected in (
            "0.12.3",
            "35977a22e9721440acf9f5b945d67034939948ba4fa4ea46b0f55d527f24d4f2",
            "Developer ID Application: Peter Steinberger",
            "Y5PE65HELJ",
            "x86_64",
            "arm64e",
            "unzip -Z1",
            "codesign --verify --strict",
        ):
            self.assertIn(expected, installer)
        self.assertNotIn("mktemp", installer)
        self.assertNotIn("/tmp", installer)
        self.assertNotIn("curl |", installer)
        self.assertIn("INSTALL_ROOT", uninstaller)
        self.assertIn("--dry-run", uninstaller)
        self.assertLess(
            uninstaller.index("verify_link"),
            uninstaller.index('/bin/rm "$path"'),
        )
        self.assertNotIn("HOME", installer)

    def test_actual_agent_returns_only_content_free_facts(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            config.state_dir.mkdir(mode=0o700)
            status_path = config.state_dir / "status.json"
            status_path.write_text(
                json.dumps(
                    {
                        "controller_ready": False,
                        "dropped": 0,
                        "failed": 0,
                        "heartbeat_at": 0,
                        "imsg_version": "0.12.3",
                        "lifecycle": "running",
                        "pending": 0,
                        "processed": 0,
                        "read_ready": True,
                        "ready": True,
                        "restart_count": 0,
                        "send_ready": None,
                        "transport_ready": True,
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(status_path, 0o600)
            with mock.patch.dict(
                os.environ,
                {
                    "RAPP_STACK_IMESSAGE_CONFIG": str(config.config_path),
                    "RAPP_STACK_IMESSAGE_STATUS": str(status_path),
                },
            ), AgentEnvironment() as environment:
                agent = environment.snapshot.get("IMessage")
                for action in ("status", "preflight", "tutorial", "transport"):
                    value = decoded(agent, action=action)
                    encoded = json.dumps(value)
                    self.assertNotIn("synthetic-owner-handle", encoded)
                    self.assertNotIn("synthetic-owner-chat", encoded)
                    self.assertNotIn(str(root), encoded)
                    self.assertEqual(value["imsg_version"], "0.12.3")
                    if action != "tutorial":
                        self.assertFalse(value["ready"])


if __name__ == "__main__":
    unittest.main()
