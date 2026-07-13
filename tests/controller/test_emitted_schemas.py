from __future__ import annotations

import json
import unittest

from rapp_stack_cubby.context import validate_schema_instance

from ._support import (
    ControllerEnvironment,
    IDENTITY_HASH,
    RAPPID,
    REPOSITORY_ROOT,
    decoded,
)


class ControllerEmittedSchemaTests(unittest.TestCase):
    def _validate(self, value, schema_name):
        schema_path = REPOSITORY_ROOT / "schemas" / schema_name
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        errors = validate_schema_instance(
            value, schema, schema_path=schema_path
        )
        self.assertFalse(errors, "\n".join(errors))

    def test_real_state_receipt_journal_and_tombstone_validate(self):
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
            state = environment.globals["_write_state"](twin, state)
            self._validate(state, "controller-state.schema.json")

            archived = decoded(
                environment.agent,
                action="archive",
                rappid=RAPPID,
                idempotency_key="schema-archive",
            )
            self.assertTrue(archived["ok"])
            receipt = json.loads(
                (
                    environment.controller_data
                    / "receipts"
                    / f"{archived['receipt_id']}.json"
                ).read_text(encoding="utf-8")
            )
            journal = json.loads(
                (
                    environment.controller_data
                    / "locks"
                    / f"{IDENTITY_HASH}.journal.json"
                ).read_text(encoding="utf-8")
            )
            self._validate(receipt, "controller-receipt.schema.json")
            self._validate(journal, "controller-journal.schema.json")

            purged = decoded(
                environment.agent,
                action="purge",
                rappid=RAPPID,
                confirmation=RAPPID,
                idempotency_key="schema-purge",
            )
            self.assertTrue(purged["ok"])
            tombstone = json.loads(
                (
                    environment.controller_data
                    / "twins/purged"
                    / f"{IDENTITY_HASH}.json"
                ).read_text(encoding="utf-8")
            )
            self._validate(
                tombstone, "controller-tombstone.schema.json"
            )


if __name__ == "__main__":
    unittest.main()
