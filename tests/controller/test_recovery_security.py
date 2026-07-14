from __future__ import annotations

import unittest
import shutil
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from ._support import (
    ControllerEnvironment,
    IDENTITY_HASH,
    RAPPID,
    decoded,
    REPOSITORY_ROOT,
)


class ControllerRecoverySecurityTests(unittest.TestCase):
    def _fault_then_recover(self, action, phases, *, setup, arguments):
        for phase in phases:
            with self.subTest(action=action, phase=phase):
                with ControllerEnvironment() as environment:
                    setup(environment)
                    fired = False

                    def boundary(observed_action, observed_phase):
                        nonlocal fired
                        if (
                            not fired
                            and observed_action == action
                            and observed_phase == phase
                        ):
                            fired = True
                            raise RuntimeError("transition_failed")

                    with patch.dict(
                        environment.globals,
                        {"_transition_boundary": boundary},
                    ):
                        first = decoded(
                            environment.agent,
                            action=action,
                            idempotency_key=f"{action}-{phase}",
                            **arguments,
                        )
                    self.assertTrue(fired)
                    self.assertFalse(first["ok"])
                    recovered = decoded(
                        environment.agent,
                        action=action,
                        idempotency_key=f"{action}-{phase}",
                        **arguments,
                    )
                    self.assertTrue(recovered["ok"], recovered)

    def test_archive_unarchive_stop_purge_and_rotation_recover_each_phase(self):
        self._fault_then_recover(
            "archive",
            ("stop_intent", "state_archived", "promoted", "completed"),
            setup=lambda environment: environment.create_twin(),
            arguments={"rappid": RAPPID},
        )

        def archived(environment):
            environment.create_twin()
            result = decoded(
                environment.agent,
                action="archive",
                rappid=RAPPID,
                idempotency_key="setup-archive",
            )
            self.assertTrue(result["ok"])

        self._fault_then_recover(
            "unarchive",
            ("activate_intent", "state_active", "promoted", "completed"),
            setup=archived,
            arguments={"rappid": RAPPID},
        )
        self._fault_then_recover(
            "stop",
            ("stop_intent", "stopped", "completed"),
            setup=lambda environment: environment.create_twin(),
            arguments={"rappid": RAPPID},
        )
        self._fault_then_recover(
            "purge",
            (
                "quarantine_intent",
                "quarantined",
                "deleted",
                "tombstone_committed",
                "completed",
            ),
            setup=archived,
            arguments={"rappid": RAPPID, "confirmation": RAPPID},
        )
        self._fault_then_recover(
            "rotate_keys",
            ("staged", "switch_intent", "switched", "cleaned", "completed"),
            setup=lambda environment: environment.create_twin(),
            arguments={"rappid": RAPPID},
        )

    def test_symlinked_twin_paths_never_change_external_bytes(self):
        cases = (
            ("status", "active", {}),
            (
                "start",
                "active",
                {
                    "idempotency_key": "symlink-start",
                    "model": "explicit-model",
                },
            ),
            (
                "rotate_keys",
                "active",
                {"idempotency_key": "symlink-rotate"},
            ),
            (
                "purge",
                "archive",
                {
                    "idempotency_key": "symlink-purge",
                    "confirmation": RAPPID,
                },
            ),
        )
        for action, location, extra in cases:
            with self.subTest(action=action):
                with ControllerEnvironment() as environment:
                    root = environment.initialize()
                    outside = environment.root / f"outside-{action}"
                    outside.mkdir()
                    marker = outside / "marker.bin"
                    marker.write_bytes(b"outside-must-not-change")
                    link = (
                        root
                        / "twins"
                        / location
                        / IDENTITY_HASH
                    )
                    link.symlink_to(outside, target_is_directory=True)
                    before = marker.read_bytes()
                    result = decoded(
                        environment.agent,
                        action=action,
                        rappid=RAPPID,
                        **extra,
                    )
                    self.assertFalse(result["ok"])
                    self.assertEqual(marker.read_bytes(), before)
                    self.assertTrue(outside.is_dir())

    def test_forbidden_runtime_tree_is_rejected_and_unlisted_file_not_promoted(self):
        with ControllerEnvironment() as environment:
            root = environment.initialize()
            source = root / "staging/source-fixture"
            source.mkdir()
            (source / "kept.txt").write_text("kept\n", encoding="utf-8")
            runtime = source / "runtime"
            runtime.mkdir()
            (runtime / "private.pem").write_text(
                "outside-secret\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(RuntimeError, "source_invalid"):
                environment.globals["scan_source_tree"](source)

            (runtime / "private.pem").unlink()
            runtime.rmdir()
            (source / "unlisted.txt").write_text(
                "not promoted\n", encoding="utf-8"
            )
            record = {
                "executable": False,
                "mode": "0644",
                "path": "kept.txt",
                "sha256": environment.globals["hashlib"]
                .sha256(b"kept\n")
                .hexdigest(),
                "size": 5,
            }
            profile = {
                "profile": "development_non_release",
                "release_manifest_sha256": None,
                "source_tree_digest": environment.globals["_tree_digest"](
                    [record]
                ),
                "files": [record],
            }
            promoted = root / "staging/promoted"
            environment.globals["_copy_source_records"](
                source, promoted, profile
            )
            self.assertTrue((promoted / "kept.txt").is_file())
            self.assertFalse((promoted / "unlisted.txt").exists())

    def test_private_instance_identity_never_reuses_product_identity(self):
        with ControllerEnvironment() as environment:
            product = environment.globals["parse_rappid"](RAPPID)
            first = environment.globals["_mint_instance_identity"](
                product, "a" * 40, "b" * 64
            )
            second = environment.globals["_mint_instance_identity"](
                product, "a" * 40, "b" * 64
            )
        self.assertNotEqual(first["rappid"], RAPPID)
        self.assertNotEqual(second["rappid"], RAPPID)
        self.assertNotEqual(first["rappid"], second["rappid"])

    def test_hatch_recovers_every_persisted_boundary(self):
        with tempfile.TemporaryDirectory(
            prefix=".test-hatch-recovery-",
            dir=REPOSITORY_ROOT,
        ) as directory:
            template = Path(directory)
            agents = (
                template
                / "cubbies/kody-w/rapplications/rapp-stack/twin/agents"
            )
            agents.mkdir(parents=True)
            (agents / "sample_agent.py").write_text(
                '"""sample"""\n', encoding="utf-8"
            )
            soul = (
                template
                / "cubbies/kody-w/rapplications/rapp-stack/twin/soul.md"
            )
            soul.write_text("sample soul\n", encoding="utf-8")
            digest = None
            for phase in (
                "checkout_intent",
                "source_verified",
                "prepared",
                "promoted",
                "completed",
            ):
                with self.subTest(phase=phase), ControllerEnvironment() as environment:
                    digest = environment.globals[
                        "deterministic_tree_digest"
                    ](template)

                    def checkout(destination, repository_url, commit):
                        del repository_url, commit
                        shutil.copytree(template, destination)

                    fired = False

                    def boundary(action, observed):
                        nonlocal fired
                        if action == "hatch_repo" and observed == phase and not fired:
                            fired = True
                            raise RuntimeError("transition_failed")

                    arguments = {
                        "action": "hatch_repo",
                        "repository_url": (
                            "https://github.com/kody-w/rapp-stack-cubby.git"
                        ),
                        "commit": "a" * 40,
                        "expected_tree_digest": digest,
                        "development_rappid": RAPPID,
                        "idempotency_key": f"hatch-{phase}",
                    }
                    with patch.dict(
                        environment.globals,
                        {
                            "_checkout_exact": checkout,
                            "_transition_boundary": boundary,
                        },
                    ):
                        first = decoded(environment.agent, **arguments)
                    self.assertFalse(first["ok"])
                    with patch.dict(
                        environment.globals,
                        {"_checkout_exact": checkout},
                    ):
                        recovered = decoded(environment.agent, **arguments)
                    self.assertTrue(recovered["ok"], recovered)

    def test_start_recovers_every_persisted_boundary(self):
        for phase in ("spawn_intent", "starting", "running", "completed"):
            with self.subTest(phase=phase), ControllerEnvironment() as environment:
                environment.create_twin()
                provider_token = environment.create_provider_token()
                child = Mock()
                child.pid = 61000
                child.poll.return_value = None
                fired = False

                def boundary(action, observed):
                    nonlocal fired
                    if action == "start" and observed == phase and not fired:
                        fired = True
                        raise RuntimeError("transition_failed")

                def observed(state):
                    running = state.get("runtime_status") == "running"
                    return {
                        "runtime_status": "running" if running else "stopped",
                        "healthy": running,
                        "identity_verified": running,
                    }

                patches = {
                    "_validate_python": (
                        lambda selected=None: "/opt/homebrew/bin/python3.11"
                    ),
                    "_preflight_model": (
                        lambda python, source, model, token: model
                    ),
                    "_process_start_identity": lambda pid: "c" * 64,
                    "_wait_health": (
                        lambda port, instance, timeout, child, start_identity, *,
                        diagnostics: True
                    ),
                    "_observed_runtime": observed,
                    "_group_alive": lambda pgid: False,
                }
                arguments = {
                    "action": "start",
                    "rappid": RAPPID,
                    "model": "explicit-model",
                    "github_token_file": str(provider_token),
                    "idempotency_key": f"start-{phase}",
                }
                with patch.object(
                    environment.globals["subprocess"],
                    "Popen",
                    return_value=child,
                ), patch.object(
                    environment.globals["os"],
                    "getpgid",
                    side_effect=lambda pid: pid,
                ), patch.dict(
                    environment.globals,
                    {**patches, "_transition_boundary": boundary},
                ):
                    first = decoded(environment.agent, **arguments)
                self.assertFalse(first["ok"])
                with patch.object(
                    environment.globals["subprocess"],
                    "Popen",
                    return_value=child,
                ), patch.object(
                    environment.globals["os"],
                    "getpgid",
                    side_effect=lambda pid: pid,
                ), patch.dict(environment.globals, patches):
                    recovered = decoded(environment.agent, **arguments)
                self.assertTrue(recovered["ok"], recovered)

    def test_purge_cleanup_failure_stays_quarantined_until_retry(self):
        with ControllerEnvironment() as environment:
            environment.create_twin()
            decoded(
                environment.agent,
                action="archive",
                rappid=RAPPID,
                idempotency_key="cleanup-archive",
            )
            original = environment.globals["_safe_remove_tree"]
            failed = False

            def fail_quarantine(root, path):
                nonlocal failed
                if not failed and Path(path).name.startswith("purge-"):
                    failed = True
                    raise RuntimeError("transition_failed")
                return original(root, path)

            arguments = {
                "action": "purge",
                "rappid": RAPPID,
                "confirmation": RAPPID,
                "idempotency_key": "cleanup-purge",
            }
            with patch.dict(
                environment.globals,
                {"_safe_remove_tree": fail_quarantine},
            ):
                first = decoded(environment.agent, **arguments)
            root = environment.controller_data
            self.assertFalse(first["ok"])
            self.assertFalse(
                (root / "twins/archive" / IDENTITY_HASH).exists()
            )
            self.assertFalse(
                (root / "twins/purged" / f"{IDENTITY_HASH}.json").exists()
            )
            self.assertEqual(len(list((root / "staging").iterdir())), 1)
            recovered = decoded(environment.agent, **arguments)
            self.assertTrue(recovered["ok"])

    def test_rotation_cleanup_retry_keeps_switched_generation(self):
        with ControllerEnvironment() as environment:
            twin = environment.create_twin()
            state = environment.globals["_load_state"](twin)
            _controller, pairing = environment.globals[
                "_ensure_twin_transport"
            ](environment.controller_data, twin, state)
            state = dict(state)
            state["transport"] = environment.globals["_transport_state"](
                pairing
            )
            environment.globals["_write_state"](twin, state)
            original = environment.globals["_safe_remove_tree"]
            failed = False

            def fail_retired(root, path):
                nonlocal failed
                if not failed and ".twin-chat-retired-" in Path(path).name:
                    failed = True
                    raise RuntimeError("transition_failed")
                return original(root, path)

            arguments = {
                "action": "rotate_keys",
                "rappid": RAPPID,
                "idempotency_key": "cleanup-rotation",
            }
            with patch.dict(
                environment.globals,
                {"_safe_remove_tree": fail_retired},
            ):
                first = decoded(environment.agent, **arguments)
            self.assertFalse(first["ok"])
            switched = environment.globals["_load_state"](twin)
            self.assertEqual(switched["transport"]["generation"], 2)
            recovered = decoded(environment.agent, **arguments)
            self.assertTrue(recovered["ok"])
            self.assertEqual(recovered["generation"], 2)


if __name__ == "__main__":
    unittest.main()
