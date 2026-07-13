from __future__ import annotations

import json
import unittest
from pathlib import Path

from rapp_stack_cubby.packaging.common import PackagingError
from rapp_stack_cubby.packaging.identity import (
    build_identity,
    validate_identity,
)
from rapp_stack_cubby.packaging.indexes import (
    build_super_rar_index,
    deduplicate_by_sha,
)

from ._support import REPOSITORY_ROOT


class ProductIdentityTests(unittest.TestCase):
    EXPECTED = (
        "rappid:@kody-w/rapp-stack-cubby:"
        "8019c0b7a40f31c046796b7a30f55dfd3b4331d91875276dc5c572176ec19c83"
    )

    def test_committed_identity_is_stable_and_has_no_transport_material(self):
        birth = json.loads((REPOSITORY_ROOT / "birth.json").read_text())
        identity = json.loads((REPOSITORY_ROOT / "rappid.json").read_text())
        fixture = json.loads(
            (
                REPOSITORY_ROOT / "tests/fixtures/product-identity.json"
            ).read_text()
        )
        self.assertEqual(fixture, {"birth": birth, "identity": identity})
        self.assertEqual(validate_identity(birth, identity)["rappid"], self.EXPECTED)
        serialized = json.dumps([birth, identity]).casefold()
        self.assertNotIn("private_key", serialized)
        self.assertNotIn("transport_key", serialized)

    def test_self_referential_and_legacy_fields_do_not_change_mint(self):
        facts = {"kind": "public", "name": "Synthetic"}
        first = build_identity(facts)
        second = build_identity(
            {
                **facts,
                "rappid": "legacy-value",
                "signature": "excluded",
                "transport": {"private_key": "excluded"},
            }
        )
        self.assertEqual(first, second)
        legacy = dict(first[1])
        legacy["rappid"] = "rappid:" + "a" * 32
        with self.assertRaises(PackagingError):
            validate_identity(first[0], legacy)


class SuperRarTests(unittest.TestCase):
    def test_sha_join_ranking_and_only_controller_streams(self):
        digest = "a" * 64
        joined = deduplicate_by_sha(
            [
                {
                    "kind": "controller-agent",
                    "rank": 5,
                    "sha256": digest,
                    "sources": ["b"],
                    "streamable": True,
                },
                {
                    "kind": "controller-agent",
                    "rank": 1,
                    "sha256": digest,
                    "sources": ["a"],
                    "streamable": True,
                },
            ]
        )
        self.assertEqual(len(joined), 1)
        self.assertEqual(joined[0]["rank"], 1)
        self.assertEqual(joined[0]["sources"], ["a", "b"])

        value = build_super_rar_index(
            [
                {
                    "kind": "controller-agent",
                    "rank": 0,
                    "sha256": "a" * 64,
                    "sources": ["controller"],
                    "streamable": True,
                },
                {
                    "kind": "rapplication",
                    "rank": 1,
                    "sha256": "b" * 64,
                    "sources": ["application"],
                    "streamable": False,
                },
            ],
            source_tree_digest="c" * 64,
        )
        self.assertEqual(value["streamable_entry_count"], 1)
        with self.assertRaises(PackagingError):
            build_super_rar_index(
                [
                    {
                        "kind": "rapplication",
                        "rank": 1,
                        "sha256": "b" * 64,
                        "sources": ["application"],
                        "streamable": True,
                    }
                ],
                source_tree_digest="c" * 64,
            )

    def test_controller_singleton_parity(self):
        controller = REPOSITORY_ROOT / (
            "cubbies/kody-w/agents/rapp_stack_cubby_agent.py"
        )
        singleton = REPOSITORY_ROOT / (
            "cubbies/kody-w/rapplications/rapp-stack/singleton/"
            "rapp_stack_cubby_agent.py"
        )
        self.assertEqual(controller.read_bytes(), singleton.read_bytes())


if __name__ == "__main__":
    unittest.main()
