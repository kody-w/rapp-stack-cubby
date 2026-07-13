from __future__ import annotations

import base64
import datetime as dt
import json
import stat
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from rapp_stack_cubby.protocols.canonical import (
    CanonicalJSONError,
    canonical_json_bytes,
    canonical_json_text,
    parse_canonical_wire,
    parse_json,
)
from rapp_stack_cubby.protocols.crypto import (
    KeyMaterialError,
    b64url_decode,
    b64url_encode,
    create_transport_keypair,
    load_private_key,
    public_jwk_from_key,
)
from rapp_stack_cubby.protocols.twin_chat import (
    ProtocolFreshnessError,
    ProtocolValidationError,
    request_digest,
    sign_response,
    verify_request,
    verify_response,
)

from ._support import ProtocolFixture, REPOSITORY_ROOT, clone


class CanonicalJSONTests(unittest.TestCase):
    def test_canonical_subset_preserves_unicode_and_sorts(self):
        self.assertEqual(
            canonical_json_bytes({"z": "λ", "a": [True, None, 1]}),
            '{"a":[true,null,1],"z":"λ"}'.encode(),
        )

    def test_float_duplicate_depth_size_and_integer_are_rejected(self):
        for raw in ('{"x":1.0}', '{"x":NaN}', '{"x":1,"x":2}'):
            with self.subTest(raw=raw):
                with self.assertRaises(CanonicalJSONError):
                    parse_json(raw)
        value = "x"
        for _ in range(17):
            value = [value]
        with self.assertRaises(CanonicalJSONError):
            canonical_json_bytes(value)
        with self.assertRaises(CanonicalJSONError):
            canonical_json_bytes({"x": "a" * (1024 * 1024 + 1)})
        with self.assertRaises(CanonicalJSONError):
            canonical_json_bytes({"x": 2**63})

    def test_canonical_wire_rejects_whitespace_order_and_alternate_escapes(self):
        value = {"schema": "rapp-commons-event/1.0", "unicode": "λ"}
        canonical = canonical_json_bytes(value)
        self.assertEqual(parse_canonical_wire(canonical), value)
        variants = (
            b'{"unicode":"\xce\xbb","schema":"rapp-commons-event/1.0"}',
            b' {\"schema\":\"rapp-commons-event/1.0\",\"unicode\":\"\xce\xbb\"}',
            b'{"schema":"rapp-commons-\\u0065vent/1.0","unicode":"\xce\xbb"}',
        )
        for wire in variants:
            with self.subTest(wire=wire):
                with self.assertRaises(CanonicalJSONError):
                    parse_canonical_wire(wire)


class KeyAndProtocolTests(unittest.TestCase):
    def test_key_creation_modes_and_no_overwrite(self):
        with ProtocolFixture() as fixture:
            self.assertEqual(
                stat.S_IMODE(fixture.controller.private_key_path.stat().st_mode),
                0o600,
            )
            self.assertEqual(
                stat.S_IMODE(fixture.controller.public_jwk_path.stat().st_mode),
                0o644,
            )
            self.assertEqual(
                stat.S_IMODE(fixture.controller.private_key_path.parent.stat().st_mode),
                0o700,
            )
            original = fixture.controller.private_key_path.read_bytes()
            with self.assertRaises(FileExistsError):
                create_transport_keypair(
                    fixture.controller.private_key_path,
                    fixture.controller.public_jwk_path,
                )
            self.assertEqual(
                fixture.controller.private_key_path.read_bytes(), original
            )

    def test_private_loader_accepts_only_unencrypted_p256_pkcs8(self):
        with ProtocolFixture() as fixture:
            cases = {
                "sec1.pem": ec.generate_private_key(
                    ec.SECP256R1()
                ).private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                ),
                "encrypted.pem": ec.generate_private_key(
                    ec.SECP256R1()
                ).private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.BestAvailableEncryption(b"synthetic"),
                ),
                "wrong-curve.pem": ec.generate_private_key(
                    ec.SECP384R1()
                ).private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
            }
            for name, encoded in cases.items():
                path = fixture.root / name
                path.write_bytes(encoded)
                path.chmod(0o600)
                with self.subTest(name=name):
                    with self.assertRaises(KeyMaterialError):
                        load_private_key(path)

    def test_fixed_public_synthetic_vector_verifies(self):
        vector = json.loads(
            (
                REPOSITORY_ROOT / "tests/fixtures/twin-chat-vector.json"
            ).read_text(encoding="utf-8")
        )
        request = verify_request(
            vector["signed_request"],
            paired_public_jwk=vector["controller_public_jwk"],
            paired_controller_rappid=vector["controller_rappid"],
            twin_rappid=vector["twin_rappid"],
            enforce_freshness=False,
            expected_key_epoch=vector["key_epoch"],
        )
        self.assertEqual(request.digest, vector["request_digest"])
        response = verify_response(
            vector["signed_response"],
            paired_child_public_jwk=vector["child_public_jwk"],
            expected_child_rappid=vector["twin_rappid"],
            expected_controller_rappid=vector["controller_rappid"],
            expected_request_nonce=request.nonce,
            expected_request_digest=request.digest,
            enforce_freshness=False,
            expected_key_epoch=vector["key_epoch"],
        )
        self.assertEqual(response["payload"]["response"], "synthetic vector reply")
        order = (
            0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        )
        for signed in (
            vector["signed_request"],
            vector["signed_response"],
        ):
            raw = b64url_decode(signed["sig"], expected_length=64)
            self.assertLessEqual(
                int.from_bytes(raw[32:], "big"), order // 2
            )

    def test_signature_tamper_der_noncanonical_and_bad_point_fail(self):
        with ProtocolFixture() as fixture:
            request = fixture.request()
            tampered = clone(request)
            tampered["body"]["payload"]["user_input"] = "tampered"
            with self.assertRaises(ProtocolValidationError):
                self._verify(fixture, tampered)

            der = load_private_key(
                fixture.controller.private_key_path
            ).sign(b"not-canonical-wrapper", ec.ECDSA(hashes.SHA256()))
            der_wire = clone(request)
            der_wire["sig"] = base64.urlsafe_b64encode(der).rstrip(b"=").decode()
            with self.assertRaises(ProtocolValidationError):
                self._verify(fixture, der_wire)

            noncanonical = clone(request)
            noncanonical["sig"] += "="
            with self.assertRaises(ProtocolValidationError):
                self._verify(fixture, noncanonical)

            bad_jwk = clone(request)
            bad_jwk["pub"]["x"] = "A" * 43
            with self.assertRaises(ProtocolValidationError):
                self._verify(fixture, bad_jwk)

    def test_signatures_are_low_s_and_high_s_equivalent_is_rejected(self):
        order = (
            0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        )
        with ProtocolFixture() as fixture:
            request = fixture.request()
            raw = b64url_decode(request["sig"], expected_length=64)
            s = int.from_bytes(raw[32:], "big")
            self.assertLessEqual(s, order // 2)
            high = clone(request)
            high["sig"] = b64url_encode(
                raw[:32] + (order - s).to_bytes(32, "big")
            )
            with self.assertRaises(ProtocolValidationError):
                self._verify(fixture, high)

    def test_request_and_response_text_require_exact_canonical_bytes(self):
        with ProtocolFixture() as fixture:
            request = fixture.request()
            canonical = canonical_json_text(request)
            self._verify(fixture, canonical)
            for wire in (
                json.dumps(request, ensure_ascii=False, indent=2),
                canonical.replace(
                    "rapp-commons-event/1.0",
                    "rapp-commons-\\u0065vent/1.0",
                    1,
                ),
            ):
                with self.assertRaises(ProtocolValidationError):
                    self._verify(fixture, wire)

            verified = self._verify(fixture, request)
            response = sign_response(
                private_key=load_private_key(
                    fixture.child.private_key_path
                ),
                child_public_jwk=fixture.child.public_jwk,
                from_rappid=fixture.twin_rappid,
                to_rappid=fixture.controller_rappid,
                request_nonce=verified.nonce,
                request_digest_value=verified.digest,
                status="rejected",
                payload={
                    "error": {
                        "code": "synthetic_rejection",
                        "message": "Synthetic terminal rejection.",
                    }
                },
            )
            with self.assertRaises(ProtocolValidationError):
                verify_response(
                    json.dumps(response, ensure_ascii=False, indent=2),
                    paired_child_public_jwk=fixture.child.public_jwk,
                    expected_child_rappid=fixture.twin_rappid,
                    expected_controller_rappid=fixture.controller_rappid,
                    expected_request_nonce=verified.nonce,
                    expected_request_digest=verified.digest,
                )

    def test_key_epoch_is_signed_and_bound_in_both_directions(self):
        with ProtocolFixture() as fixture:
            request = fixture.request(key_epoch=9)
            with self.assertRaises(ProtocolValidationError):
                self._verify(fixture, request)
            verified = verify_request(
                request,
                paired_public_jwk=fixture.controller.public_jwk,
                paired_controller_rappid=fixture.controller_rappid,
                twin_rappid=fixture.twin_rappid,
                expected_key_epoch=9,
            )
            response = sign_response(
                private_key=load_private_key(
                    fixture.child.private_key_path
                ),
                child_public_jwk=fixture.child.public_jwk,
                from_rappid=fixture.twin_rappid,
                to_rappid=fixture.controller_rappid,
                request_nonce=verified.nonce,
                request_digest_value=verified.digest,
                status="rejected",
                payload={
                    "error": {
                        "code": "synthetic_rejection",
                        "message": "Synthetic terminal rejection.",
                    }
                },
                key_epoch=9,
            )
            verify_response(
                response,
                paired_child_public_jwk=fixture.child.public_jwk,
                expected_child_rappid=fixture.twin_rappid,
                expected_controller_rappid=fixture.controller_rappid,
                expected_request_nonce=verified.nonce,
                expected_request_digest=verified.digest,
                expected_key_epoch=9,
            )
            with self.assertRaises(ProtocolValidationError):
                verify_response(
                    response,
                    paired_child_public_jwk=fixture.child.public_jwk,
                    expected_child_rappid=fixture.twin_rappid,
                    expected_controller_rappid=fixture.controller_rappid,
                    expected_request_nonce=verified.nonce,
                    expected_request_digest=verified.digest,
                )

    def test_wrong_from_to_time_kind_and_key_id_fail(self):
        with ProtocolFixture() as fixture:
            request = fixture.request()
            cases = []
            wrong_from = clone(request)
            wrong_from["from"] = fixture.twin_rappid
            cases.append(wrong_from)
            wrong_to = fixture.request(to_rappid=fixture.controller_rappid)
            cases.append(wrong_to)
            wrong_kind = clone(request)
            wrong_kind["kind"] = "other"
            cases.append(wrong_kind)
            wrong_key = clone(request)
            wrong_key["key_id"] = "0" * 64
            cases.append(wrong_key)
            for value in cases:
                with self.subTest(value=value):
                    with self.assertRaises(ProtocolValidationError):
                        self._verify(fixture, value)
            stale = fixture.request(utc="2000-01-01T00:00:00Z")
            with self.assertRaises(ProtocolFreshnessError):
                self._verify(fixture, stale)

    def test_signed_response_binds_all_request_fields(self):
        with ProtocolFixture() as fixture:
            request = self._verify(fixture, fixture.request())
            response = sign_response(
                private_key=load_private_key(fixture.child.private_key_path),
                child_public_jwk=fixture.child.public_jwk,
                from_rappid=fixture.twin_rappid,
                to_rappid=fixture.controller_rappid,
                request_nonce=request.nonce,
                request_digest_value=request.digest,
                status="ok",
                payload={
                    "response": "synthetic reply",
                    "session_id": "synthetic-session",
                    "agent_logs": "",
                    "voice_mode": False,
                    "model": "synthetic",
                    "requested_model": "synthetic",
                },
            )
            verified = verify_response(
                response,
                paired_child_public_jwk=fixture.child.public_jwk,
                expected_child_rappid=fixture.twin_rappid,
                expected_controller_rappid=fixture.controller_rappid,
                expected_request_nonce=request.nonce,
                expected_request_digest=request.digest,
            )
            self.assertEqual(verified["status"], "ok")
            stale_response = sign_response(
                private_key=load_private_key(fixture.child.private_key_path),
                child_public_jwk=fixture.child.public_jwk,
                from_rappid=fixture.twin_rappid,
                to_rappid=fixture.controller_rappid,
                request_nonce=request.nonce,
                request_digest_value=request.digest,
                status="ok",
                payload=response["payload"],
                utc="2000-01-01T00:00:00Z",
            )
            with self.assertRaises(ProtocolFreshnessError):
                verify_response(
                    stale_response,
                    paired_child_public_jwk=fixture.child.public_jwk,
                    expected_child_rappid=fixture.twin_rappid,
                    expected_controller_rappid=fixture.controller_rappid,
                    expected_request_nonce=request.nonce,
                    expected_request_digest=request.digest,
                )
            for field in (
                "from_rappid",
                "to_rappid",
                "request_nonce",
                "request_digest",
                "key_id",
                "key_epoch",
                "utc",
            ):
                bad = clone(response)
                if field == "utc":
                    bad[field] = "2000-01-01T00:00:00Z"
                elif field in {"request_digest", "key_id"}:
                    bad[field] = "0" * 64
                elif field == "key_epoch":
                    bad[field] = 2
                elif field == "to_rappid":
                    bad[field] = fixture.twin_rappid
                else:
                    bad[field] = fixture.controller_rappid
                with self.subTest(field=field):
                    with self.assertRaises(ProtocolValidationError):
                        verify_response(
                            bad,
                            paired_child_public_jwk=fixture.child.public_jwk,
                            expected_child_rappid=fixture.twin_rappid,
                            expected_controller_rappid=fixture.controller_rappid,
                            expected_request_nonce=request.nonce,
                            expected_request_digest=request.digest,
                        )

    @staticmethod
    def _verify(fixture, value):
        return verify_request(
            value,
            paired_public_jwk=fixture.controller.public_jwk,
            paired_controller_rappid=fixture.controller_rappid,
            twin_rappid=fixture.twin_rappid,
        )


if __name__ == "__main__":
    unittest.main()
