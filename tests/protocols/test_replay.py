from __future__ import annotations

import concurrent.futures
import json
import sqlite3
import unittest

from rapp_stack_cubby.protocols.replay import ReplayJournal, ReplayJournalError
from rapp_stack_cubby.protocols.twin_chat import request_digest

from ._support import ProtocolFixture


class ReplayJournalTests(unittest.TestCase):
    def test_claim_complete_exact_replay_and_digest_conflict(self):
        with ProtocolFixture() as fixture:
            request = fixture.request()
            digest = request_digest(request["body"])
            journal = ReplayJournal(fixture.root / "journal/replay.sqlite3")
            key = (
                fixture.controller_rappid,
                fixture.controller.key_id,
                request["body"]["nonce"],
            )
            self.assertEqual(journal.claim(*key, digest).outcome, "claimed")
            self.assertEqual(journal.claim(*key, digest).outcome, "processing")
            response = '{"synthetic":"signed-response"}'
            journal.finish(*key, digest, response)
            replay = journal.claim(*key, digest)
            self.assertEqual(replay.outcome, "replay")
            self.assertEqual(replay.response_json, response)
            self.assertEqual(
                journal.claim(*key, "0" * 64).outcome,
                "digest_conflict",
            )

    def test_crash_restart_never_reclaims_processing(self):
        with ProtocolFixture() as fixture:
            request = fixture.request()
            digest = request_digest(request["body"])
            path = fixture.root / "journal/replay.sqlite3"
            key = (
                fixture.controller_rappid,
                fixture.controller.key_id,
                request["body"]["nonce"],
            )
            ReplayJournal(path).claim(*key, digest)
            restarted = ReplayJournal(path)
            self.assertEqual(restarted.claim(*key, digest).outcome, "processing")
            self.assertEqual(restarted.counts()["processing"], 1)

    def test_expired_pre_dispatch_claim_is_reclaimed(self):
        with ProtocolFixture() as fixture:
            request = fixture.request()
            digest = request_digest(request["body"])
            path = fixture.root / "journal/replay.sqlite3"
            key = (
                fixture.controller_rappid,
                fixture.controller.key_id,
                request["body"]["nonce"],
            )
            first = ReplayJournal(path, owner_id="first-owner-identifier")
            self.assertEqual(first.claim(*key, digest).outcome, "claimed")
            with sqlite3.connect(path) as connection:
                connection.execute(
                    """
                    UPDATE twin_chat_replay
                    SET lease_deadline = '2000-01-01T00:00:00Z'
                    """
                )
            restarted = ReplayJournal(
                path, owner_id="second-owner-identifier"
            )
            recovered = restarted.claim(*key, digest)
            self.assertEqual(recovered.outcome, "reclaimed")
            self.assertTrue(recovered.dispatch_allowed)
            restarted.mark_dispatched(*key, digest)
            restarted.finish(*key, digest, '{"terminal":true}')
            self.assertEqual(
                restarted.lookup(*key, digest).response_json,
                '{"terminal":true}',
            )

    def test_expired_post_dispatch_claim_becomes_ambiguous_terminal(self):
        with ProtocolFixture() as fixture:
            request = fixture.request()
            digest = request_digest(request["body"])
            path = fixture.root / "journal/replay.sqlite3"
            key = (
                fixture.controller_rappid,
                fixture.controller.key_id,
                request["body"]["nonce"],
            )
            first = ReplayJournal(path, owner_id="first-owner-identifier")
            first.claim(*key, digest)
            first.mark_dispatched(*key, digest)
            with sqlite3.connect(path) as connection:
                connection.execute(
                    """
                    UPDATE twin_chat_replay
                    SET lease_deadline = '2000-01-01T00:00:00Z'
                    """
                )
            restarted = ReplayJournal(
                path, owner_id="second-owner-identifier"
            )
            recovered = restarted.claim(*key, digest)
            self.assertEqual(recovered.outcome, "ambiguous")
            self.assertFalse(recovered.dispatch_allowed)
            restarted.finish(
                *key,
                digest,
                '{"status":"rejected"}',
                rejected=True,
            )
            replay = restarted.claim(*key, digest)
            self.assertEqual(replay.state, "rejected")
            self.assertEqual(replay.response_json, '{"status":"rejected"}')

    def test_processing_rows_include_owner_lease_and_epoch(self):
        with ProtocolFixture() as fixture:
            request = fixture.request(key_epoch=4)
            digest = request_digest(request["body"])
            path = fixture.root / "journal/replay.sqlite3"
            journal = ReplayJournal(path, key_epoch=4)
            journal.claim(
                fixture.controller_rappid,
                fixture.controller.key_id,
                request["body"]["nonce"],
                digest,
            )
            with sqlite3.connect(path) as connection:
                row = connection.execute(
                    """
                    SELECT key_epoch, dispatch_phase, owner_id, owner_pid,
                           owner_started_at, lease_deadline
                    FROM twin_chat_replay
                    """
                ).fetchone()
            self.assertEqual(row[0:2], (4, "claimed"))
            self.assertTrue(row[2])
            self.assertGreater(row[3], 0)
            self.assertLess(row[4], row[5])
            with self.assertRaises(ReplayJournalError):
                ReplayJournal(path, key_epoch=5)

    def test_concurrent_claim_has_one_winner(self):
        with ProtocolFixture() as fixture:
            request = fixture.request()
            digest = request_digest(request["body"])
            journal = ReplayJournal(fixture.root / "journal/replay.sqlite3")
            key = (
                fixture.controller_rappid,
                fixture.controller.key_id,
                request["body"]["nonce"],
            )

            def claim():
                return journal.claim(*key, digest).outcome

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                outcomes = list(pool.map(lambda _: claim(), range(8)))
            self.assertEqual(outcomes.count("claimed"), 1)
            self.assertEqual(outcomes.count("processing"), 7)

    def test_terminal_rejection_is_replayed(self):
        with ProtocolFixture() as fixture:
            request = fixture.request()
            digest = request_digest(request["body"])
            journal = ReplayJournal(fixture.root / "journal/replay.sqlite3")
            key = (
                fixture.controller_rappid,
                fixture.controller.key_id,
                request["body"]["nonce"],
            )
            journal.claim(*key, digest)
            journal.finish(*key, digest, '{"rejected":true}', rejected=True)
            result = journal.lookup(*key, digest)
            self.assertEqual(result.state, "rejected")
            self.assertEqual(result.response_json, '{"rejected":true}')
            with self.assertRaises(ReplayJournalError):
                journal.finish(*key, digest, "{}")


if __name__ == "__main__":
    unittest.main()
