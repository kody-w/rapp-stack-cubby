from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

from rapp_stack_cubby.protocols.crypto import (
    create_transport_keypair,
    load_private_key,
)
from rapp_stack_cubby.protocols.twin_chat import sign_request

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class ProtocolFixture:
    def __init__(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(
            prefix=".test-twin-chat-",
            dir=REPOSITORY_ROOT,
        )
        self.root = Path(self._temporary.name)
        os.chmod(self.root, 0o700)
        self.controller = create_transport_keypair(
            self.root / "controller/private.pem",
            self.root / "controller/public.jwk",
        )
        self.child = create_transport_keypair(
            self.root / "child/private.pem",
            self.root / "child/public.jwk",
        )
        self.controller_rappid = (
            "rappid:@kody-w/rapp-stack-cubby-controller:"
            + self.controller.key_id
        )
        self.twin_rappid = (
            "rappid:@kody-w/synthetic-test-twin:"
            + hashlib.sha256(b"synthetic test twin").hexdigest()
        )

    def request(self, **changes):
        values = {
            "private_key": load_private_key(self.controller.private_key_path),
            "public_jwk": self.controller.public_jwk,
            "from_rappid": self.controller_rappid,
            "to_rappid": self.twin_rappid,
            "payload": {"user_input": "synthetic hello"},
            "facets": ("synthetic-test",),
        }
        values.update(changes)
        return sign_request(**values)

    def cleanup(self) -> None:
        self._temporary.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.cleanup()


def clone(value):
    return json.loads(json.dumps(value))
