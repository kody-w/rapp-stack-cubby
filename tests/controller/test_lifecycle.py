from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from ._support import (
    ControllerEnvironment,
    IDENTITY_HASH,
    RAPPID,
    REPOSITORY_ROOT,
    decoded,
)


class ControllerLifecycleTests(unittest.TestCase):
    def test_mutations_require_gate_but_read_only_list_does_not(self):
        with ControllerEnvironment(mutations=False) as environment:
            read_only = decoded(environment.agent, action="list")
            mutation = decoded(
                environment.agent,
                action="archive",
                rappid=RAPPID,
                idempotency_key="archive-one",
            )

        self.assertTrue(read_only["ok"])
        self.assertFalse(mutation["ok"])
        self.assertEqual(mutation["error"]["code"], "mutation_disabled")

    def test_explicit_root_layout_modes_and_workspace_key(self):
        with ControllerEnvironment() as environment:
            root = environment.initialize()
            identity = environment.globals["parse_rappid"](RAPPID)

            self.assertEqual(identity["identity_hash"], IDENTITY_HASH)
            self.assertEqual(
                environment.globals["workspace_key"](RAPPID),
                IDENTITY_HASH,
            )
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            for relative in (
                "twins/active",
                "twins/archive",
                "twins/purged",
                "staging",
                "locks",
                "receipts",
                "sessions",
                "loadout",
            ):
                self.assertEqual(
                    stat.S_IMODE((root / relative).stat().st_mode),
                    0o700,
                )

    def test_symlink_component_in_controller_root_is_rejected(self):
        with ControllerEnvironment() as environment:
            real = environment.root / "real"
            real.mkdir()
            linked = environment.root / "linked"
            linked.symlink_to(real, target_is_directory=True)
            with patch.dict(
                os.environ,
                {
                    "RAPP_STACK_CONTROLLER_DATA_DIR": str(
                        linked / "controller"
                    )
                },
                clear=False,
            ):
                result = decoded(
                    environment.agent,
                    action="archive",
                    rappid=RAPPID,
                    idempotency_key="archive-symlink",
                )

        self.assertFalse(result["ok"])
        self.assertEqual(
            result["error"]["code"], "controller_root_invalid"
        )

    def test_archive_unarchive_and_purge_exact_state_machine(self):
        with ControllerEnvironment() as environment:
            environment.create_twin()
            archived = decoded(
                environment.agent,
                action="archive",
                rappid=RAPPID,
                idempotency_key="archive-state",
            )
            replay = decoded(
                environment.agent,
                action="archive",
                rappid=RAPPID,
                idempotency_key="archive-state",
            )
            unarchived = decoded(
                environment.agent,
                action="unarchive",
                rappid=RAPPID,
                idempotency_key="unarchive-state",
            )
            archived_again = decoded(
                environment.agent,
                action="archive",
                rappid=RAPPID,
                idempotency_key="archive-again",
            )
            wrong_confirmation = decoded(
                environment.agent,
                action="purge",
                rappid=RAPPID,
                confirmation="not-the-rappid",
                idempotency_key="purge-wrong",
            )
            purged = decoded(
                environment.agent,
                action="purge",
                rappid=RAPPID,
                confirmation=RAPPID,
                idempotency_key="purge-state",
            )
            status = decoded(
                environment.agent,
                action="status",
                rappid=RAPPID,
            )
            tombstone = json.loads(
                (
                    environment.controller_data
                    / "twins/purged"
                    / (IDENTITY_HASH + ".json")
                ).read_text(encoding="utf-8")
            )
            private_keys = list(
                environment.controller_data.rglob("private.pem")
            )

        self.assertEqual(archived["lifecycle_state"], "archived")
        self.assertTrue(replay["idempotent_replay"])
        self.assertFalse(unarchived["started"])
        self.assertEqual(archived_again["lifecycle_state"], "archived")
        self.assertEqual(
            wrong_confirmation["error"]["code"], "confirmation_required"
        )
        self.assertEqual(purged["lifecycle_state"], "purged")
        self.assertTrue(purged["tombstone"])
        self.assertEqual(status["lifecycle_state"], "purged")
        self.assertRegex(tombstone["transport_key_id"], r"^[0-9a-f]{64}$")
        self.assertGreaterEqual(tombstone["transport_generation"], 1)
        self.assertEqual(private_keys, [
            environment.controller_data / "transport/private.pem"
        ])

    def test_purge_never_accepts_active_or_bulk_identity(self):
        with ControllerEnvironment() as environment:
            environment.create_twin()
            active = decoded(
                environment.agent,
                action="purge",
                rappid=RAPPID,
                confirmation=RAPPID,
                idempotency_key="purge-active",
            )
            bulk = decoded(
                environment.agent,
                action="purge",
                rappid="*",
                confirmation="*",
                idempotency_key="purge-bulk",
            )

        self.assertEqual(active["error"]["code"], "not_archived")
        self.assertEqual(bulk["error"]["code"], "identity_invalid")

    def test_transport_rotation_invalidates_sessions_and_retains_only_fingerprint(self):
        with ControllerEnvironment() as environment:
            twin = environment.create_twin()
            root = environment.controller_data
            state = environment.globals["_load_state"](twin)
            _controller, pairing = environment.globals[
                "_ensure_twin_transport"
            ](root, twin, state)
            state = dict(state)
            state["transport"] = environment.globals["_transport_state"](
                pairing
            )
            environment.globals["_write_state"](twin, state)
            environment.globals["_record_signed_session"](
                root,
                IDENTITY_HASH,
                "rotation-test",
                "synthetic-session",
            )
            old_key_id = pairing["child_key_id"]

            rotated = decoded(
                environment.agent,
                action="rotate_keys",
                rappid=RAPPID,
                idempotency_key="rotate-transport",
            )
            replay = decoded(
                environment.agent,
                action="rotate_keys",
                rappid=RAPPID,
                idempotency_key="rotate-transport",
            )
            state = environment.globals["_load_state"](twin)
            transport_dir = (
                twin / "workspace/data/twin-chat"
            )
            session_exists = (
                root / "sessions" / IDENTITY_HASH
            ).exists()
            private_mode = stat.S_IMODE(
                (transport_dir / "private.pem").stat().st_mode
            )

        self.assertTrue(rotated["ok"])
        self.assertEqual(rotated["status"], "stopped")
        self.assertFalse(rotated["auto_started"])
        self.assertNotEqual(rotated["new_child_key_id"], old_key_id)
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(state["transport"]["generation"], 2)
        self.assertEqual(state["transport"]["key_epoch"], 2)
        self.assertEqual(
            state["transport_key_audit"][-1]["key_id"], old_key_id
        )
        self.assertFalse(session_exists)
        self.assertEqual(private_mode, 0o600)

    def test_conflicting_controller_lock_fails_explicitly(self):
        with ControllerEnvironment() as environment:
            root = environment.initialize()
            entered = threading.Event()
            release = threading.Event()

            def hold_lock():
                with environment.globals["_controller_locks"](
                    root, IDENTITY_HASH
                ):
                    entered.set()
                    release.wait(3)

            thread = threading.Thread(target=hold_lock)
            thread.start()
            self.assertTrue(entered.wait(2))
            try:
                with self.assertRaisesRegex(RuntimeError, "busy"):
                    with environment.globals["_controller_locks"](
                        root, IDENTITY_HASH
                    ):
                        pass
            finally:
                release.set()
                thread.join(3)
            self.assertFalse(thread.is_alive())

    def test_restart_status_reconciles_dead_pid_without_killing_by_name(self):
        process = {
            "pid": 2147483646,
            "pgid": 2147483646,
            "port": 65534,
            "started_at": "2026-07-12T00:00:00Z",
            "instance_id": "dead-instance",
            "command_sha256": "a" * 64,
        }
        with ControllerEnvironment() as environment:
            environment.create_twin(runtime_status="running", process=process)
            status = decoded(
                environment.agent,
                action="status",
                rappid=RAPPID,
            )

        self.assertEqual(status["runtime_status"], "stopped")
        self.assertFalse(status["healthy"])

    def test_development_hatch_promotes_atomically_and_rolls_back_failure(self):
        with ControllerEnvironment() as environment:
            template_owner = tempfile.TemporaryDirectory(
                prefix=".test-hatch-template-",
                dir=REPOSITORY_ROOT,
            )
            template = Path(template_owner.name)
            agents = (
                template
                / "cubbies/kody-w/rapplications/rapp-stack/twin/agents"
            )
            agents.mkdir(parents=True)
            (agents / "sample_agent.py").write_text(
                '"""sample"""\\n',
                encoding="utf-8",
            )
            soul = (
                template
                / "cubbies/kody-w/rapplications/rapp-stack/twin/soul.md"
            )
            soul.write_text("test soul\n", encoding="utf-8")
            (template / "README.md").write_text("source\n", encoding="utf-8")
            digest = environment.globals["deterministic_tree_digest"](template)

            def fake_checkout(destination, repository_url, commit):
                shutil.copytree(template, destination)

            try:
                with patch.dict(
                    environment.globals,
                    {"_checkout_exact": fake_checkout},
                ):
                    result = decoded(
                        environment.agent,
                        action="hatch_repo",
                        repository_url=(
                            "https://github.com/kody-w/rapp-stack-cubby.git"
                        ),
                        commit="a" * 40,
                        expected_tree_digest=digest,
                        development_rappid=RAPPID,
                        idempotency_key="hatch-success",
                    )
                self.assertTrue(result["ok"])
                self.assertNotEqual(result["workspace_key"], IDENTITY_HASH)
                self.assertEqual(result["product_rappid"], RAPPID)
                self.assertEqual(
                    result["instance_rappid"], result["rappid"]
                )
                self.assertFalse(result["release_eligible"])
                root = environment.controller_data
                installed_hash = result["identity_hash"]
                self.assertTrue(
                    (root / "twins/active" / installed_hash).is_dir()
                )

                shutil.rmtree(root / "twins/active" / installed_hash)

                def fail_prepare(*args, **kwargs):
                    raise RuntimeError("transition_failed")

                with patch.dict(
                    environment.globals,
                    {
                        "_checkout_exact": fake_checkout,
                        "_prepare_twin": fail_prepare,
                    },
                ):
                    failed = decoded(
                        environment.agent,
                        action="hatch_repo",
                        repository_url=(
                            "https://github.com/kody-w/rapp-stack-cubby.git"
                        ),
                        commit="a" * 40,
                        expected_tree_digest=digest,
                        development_rappid=RAPPID,
                        idempotency_key="hatch-failure",
                    )
                self.assertFalse(failed["ok"])
                self.assertEqual(
                    list((root / "twins/active").iterdir()), []
                )
                self.assertEqual(list((root / "staging").iterdir()), [])
            finally:
                template_owner.cleanup()


if __name__ == "__main__":
    unittest.main()
