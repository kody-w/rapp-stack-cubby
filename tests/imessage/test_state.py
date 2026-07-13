from __future__ import annotations

import os
import sqlite3
import stat
import unittest

from rapp_stack_cubby.imessage.state import IMessageState, StateError

from ._support import WorkDirectory, make_config


def payload(state: IMessageState, text: str = "synthetic content") -> dict[str, object]:
    return {
        "created_at": "",
        "is_from_me": True,
        "service": "imessage",
        "target_hmac": state.target_hmac("synthetic-owner-chat"),
        "target_kind": "chat_id",
        "text": text,
    }


class IMessageStateTests(unittest.TestCase):
    def test_legacy_schema_migrates_atomically(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            config.state_dir.mkdir(mode=0o700)
            database = config.state_dir / "state.sqlite3"
            connection = sqlite3.connect(database)
            connection.executescript(
                """
                PRAGMA user_version=2;
                CREATE TABLE inbox(
                  guid_hash TEXT PRIMARY KEY,
                  rowid_value INTEGER NOT NULL,
                  event_json TEXT,
                  processed INTEGER NOT NULL
                );
                INSERT INTO inbox VALUES('logical-only',7,NULL,1);
                CREATE TABLE outbox(
                  record_id TEXT,
                  status TEXT,
                  opaque_payload TEXT
                );
                INSERT INTO outbox VALUES('legacy-ambiguous','flushed','private');
                """
            )
            connection.close()
            os.chmod(database, 0o600)
            state = IMessageState(config)
            self.assertEqual(
                state._db.execute("PRAGMA user_version").fetchone()[0],
                4,
            )
            self.assertEqual(state.cursor_rowid, 7)
            columns = {
                row[1] for row in state._db.execute("PRAGMA table_info(inbox)")
            }
            self.assertIn("event_digest", columns)
            recovery = state._db.execute(
                "SELECT status,payload_json FROM legacy_outbox_recovery"
            ).fetchone()
            self.assertEqual(recovery["status"], "unknown")
            self.assertIn("legacy-ambiguous", recovery["payload_json"])
            self.assertEqual(state.counts()["outbox_unknown"], 0)
            state.close()

    def test_modes_hmac_and_no_raw_identifiers(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            state = IMessageState(config)
            event = state.claim_event(1, "synthetic-raw-guid", payload(state))
            self.assertIsNotNone(event)
            state.complete_event(event, "accepted")
            state.close()
            self.assertEqual(stat.S_IMODE(config.state_dir.stat().st_mode), 0o700)
            for path in config.state_dir.iterdir():
                if path.is_file():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            combined = b"".join(
                path.read_bytes()
                for path in config.state_dir.iterdir()
                if path.is_file()
            )
            self.assertNotIn(b"synthetic-raw-guid", combined)
            self.assertNotIn(b"synthetic-owner-chat", combined)

    def test_writer_lease_conflict(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            first = IMessageState(config)
            second = IMessageState(config)
            self.assertTrue(first.acquire_lease("first"))
            self.assertFalse(second.acquire_lease("second"))
            first.release_lease("first")
            self.assertTrue(second.acquire_lease("second"))
            second.release_lease("second")
            first.close()
            second.close()

    def test_claim_dedupe_and_cursor_waits_for_lower_row(self) -> None:
        with WorkDirectory() as root:
            state = IMessageState(make_config(root))
            low = state.claim_event(4, "guid-low", payload(state, "low"))
            high = state.claim_event(5, "guid-high", payload(state, "high"))
            self.assertIsNone(state.claim_event(8, "guid-low", payload(state, "dup")))
            state.complete_event(high, "accepted")
            self.assertIsNone(state.cursor_rowid)
            self.assertEqual(state.watch_resume_rowid, 3)
            state.complete_event(low, "accepted")
            self.assertEqual(state.cursor_rowid, 5)
            state.close()

    def test_staged_response_and_outbox_transitions(self) -> None:
        with WorkDirectory() as root:
            state = IMessageState(make_config(root))
            event = state.claim_event(1, "guid-stage", payload(state))
            state.stage_controller_result(
                event,
                conversation_hmac=state.owner_session_key(),
                target_hmac=state.target_hmac("synthetic-owner-chat"),
                target_kind="chat_id",
                user_text="synthetic content",
                response_text="synthetic response",
                global_session_id="global-session",
            )
            state.stage_controller_result(
                event,
                conversation_hmac=state.owner_session_key(),
                target_hmac=state.target_hmac("synthetic-owner-chat"),
                target_kind="chat_id",
                user_text="synthetic content",
                response_text="different response",
                global_session_id="global-session",
            )
            self.assertEqual(state.staged_dispatch(event)["response"], "synthetic response")
            record = state.begin_outbound(
                event,
                state.owner_session_key(),
                "synthetic response",
            )
            self.assertEqual(state.outbound_record(record)["status"], "staged")
            state.mark_outbound_flushed(record)
            state.finish_outbound(
                record,
                status="submitted",
                outbound_guid="outbound-guid",
            )
            self.assertEqual(state.outbound_record(record)["status"], "submitted")
            with self.assertRaises(StateError):
                state.finish_outbound(record, status="unknown")
            state.close()

    def test_restart_flushed_is_unknown_and_never_retried(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            state = IMessageState(config)
            event = state.claim_event(1, "guid-restart", payload(state))
            state.stage_controller_result(
                event,
                conversation_hmac=state.owner_session_key(),
                target_hmac=state.target_hmac("synthetic-owner-chat"),
                target_kind="chat_id",
                user_text="synthetic content",
                response_text="synthetic response",
                global_session_id="global-session",
            )
            record = state.begin_outbound(event, state.owner_session_key(), "synthetic response")
            state.mark_outbound_flushed(record)
            state.close()
            recovered = IMessageState(config)
            result = recovered.recover_after_restart()
            self.assertEqual(result["flushed_to_unknown"], 1)
            self.assertEqual(recovered.outbound_record(record)["status"], "unknown")
            self.assertEqual(recovered.raw_state_for_tests()["inbox"][0]["outcome"], "send_unknown")
            recovered.close()

    def test_echo_is_exact_once_and_remote_same_text_is_retained(self) -> None:
        with WorkDirectory() as root:
            state = IMessageState(make_config(root))
            event = state.claim_event(1, "inbound-guid", payload(state))
            state.stage_controller_result(
                event,
                conversation_hmac=state.owner_session_key(),
                target_hmac=state.target_hmac("synthetic-owner-chat"),
                target_kind="chat_id",
                user_text="synthetic content",
                response_text="same text",
                global_session_id="global-session",
            )
            record = state.begin_outbound(event, state.owner_session_key(), "same text")
            state.mark_outbound_flushed(record)
            state.finish_outbound(record, status="submitted", outbound_guid="echo-guid")
            arguments = {
                "conversation_key": state.owner_session_key(),
                "guid": "echo-guid",
                "text": "same text",
                "target_hmac": state.target_hmac("synthetic-owner-chat"),
            }
            self.assertFalse(state.consume_outbound_echo(**arguments, is_from_me=False))
            self.assertTrue(state.consume_outbound_echo(**arguments, is_from_me=True))
            self.assertFalse(state.consume_outbound_echo(**arguments, is_from_me=True))
            state.close()

    def test_echo_claim_is_transactional_and_recovers_guid_hmac(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            state = IMessageState(config)
            source = state.claim_event(1, "source-guid", payload(state))
            state.stage_controller_result(
                source,
                conversation_hmac=state.owner_session_key(),
                target_hmac=state.target_hmac("synthetic-owner-chat"),
                target_kind="chat_id",
                user_text="synthetic content",
                response_text="bot output",
                global_session_id="global-session",
            )
            record = state.begin_outbound(
                source,
                state.owner_session_key(),
                "bot output",
            )
            state.mark_outbound_flushed(record)
            state.finish_outbound(
                record,
                status="submitted",
                outbound_guid="bot-output-guid",
            )
            echo_payload = payload(state, "bot output")
            echo = state.claim_event(
                2,
                "bot-output-guid",
                echo_payload,
            )
            self.assertEqual(state.event_outcome(echo), "outbound_echo")
            state.close()

            recovered = IMessageState(config)
            self.assertEqual(
                recovered.event_outcome(echo),
                "outbound_echo",
            )
            remote_payload = dict(echo_payload)
            remote_payload["is_from_me"] = False
            remote = recovered.claim_event(
                3,
                "remote-same-text-guid",
                remote_payload,
            )
            self.assertIsNone(recovered.event_outcome(remote))
            self.assertEqual(
                recovered.event_for_processing(remote)["guid_hmac"],
                recovered.logical_id(
                    "message-guid",
                    "remote-same-text-guid",
                ),
            )
            recovered.close()


if __name__ == "__main__":
    unittest.main()
