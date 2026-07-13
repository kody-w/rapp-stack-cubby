from __future__ import annotations

import http.client
import io
import json
import os
import stat
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from rapp_stack_cubby.runtime.auth import (
    bearer_authorization,
    prepare_controller_auth,
)
from rapp_stack_cubby.cli import main
from rapp_stack_cubby.runtime.config import (
    RuntimeConfig,
    RuntimeConfigurationError,
)
from rapp_stack_cubby.runtime.orchestrator import Orchestrator
from rapp_stack_cubby.runtime.provider import ProviderResponse, ScriptedProvider
from rapp_stack_cubby.runtime.registry import AgentRegistry
from rapp_stack_cubby.runtime.server import RuntimeServer
from rapp_stack_cubby.runtime.storage import LocalStorage

from ._support import ECHO_AGENT, RuntimeFixture


class RuntimeAuthenticationTests(unittest.TestCase):
    def test_controller_auth_is_atomic_private_and_verifiable(self) -> None:
        with RuntimeFixture() as fixture:
            private = fixture.root / "controller-auth"
            path, created = prepare_controller_auth(private)
            self.assertTrue(created)
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_size, 32)
            self.assertEqual(prepare_controller_auth(private), (path, False))
            self.assertEqual(
                prepare_controller_auth(private, verify_only=True),
                (path, False),
            )
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeConfigurationError):
                prepare_controller_auth(private, verify_only=True)

    def test_controller_auth_cli_never_prints_token_bytes(self) -> None:
        with RuntimeFixture() as fixture:
            private = fixture.root / "controller-auth-cli"
            output = io.StringIO()
            with redirect_stdout(output):
                status = main(
                    [
                        "controller-auth",
                        "--private-dir",
                        str(private),
                    ]
                )
            self.assertEqual(status, 0)
            value = json.loads(output.getvalue())
            self.assertTrue(value["verified"])
            self.assertEqual(value["token_bytes"], 32)
            token = (private / "controller-auth.token").read_bytes()
            self.assertNotIn(token.hex(), output.getvalue())

    def test_runtime_config_rejects_wrong_token_size_and_mode(self) -> None:
        with RuntimeFixture() as fixture:
            token = fixture.root / "token"
            token.write_bytes(b"x" * 31)
            os.chmod(token, 0o600)
            with self.assertRaises(RuntimeConfigurationError):
                self._config(fixture, token)
            token.write_bytes(b"x" * 32)
            os.chmod(token, 0o644)
            with self.assertRaises(RuntimeConfigurationError):
                self._config(fixture, token)
            os.chmod(token, 0o600)
            self.assertEqual(self._config(fixture, token).auth_token_file, token)

    def test_wrong_missing_or_malformed_bearer_never_reaches_provider(self) -> None:
        with RuntimeFixture() as fixture:
            fixture.write_agent("echo_agent.py", ECHO_AGENT)
            provider = ScriptedProvider(
                [ProviderResponse(content="authenticated")]
            )
            registry = AgentRegistry(
                fixture.agents,
                storage=LocalStorage(fixture.data),
                compatibility_mode=True,
            )
            orchestrator = Orchestrator(
                soul_path=fixture.soul,
                registry=registry,
                provider=provider,
                model="auth-test",
            )
            token = bytes(range(32))
            server = RuntimeServer(
                orchestrator,
                port=0,
                instance_id="auth-test",
                auth_token=token,
            )
            server.start()
            try:
                for authorization in (
                    None,
                    "Bearer " + "A" * 43,
                    "bearer " + "A" * 43,
                    "Bearer  " + "A" * 43,
                    "Bearer " + "A" * 200,
                ):
                    with self.subTest(authorization=authorization):
                        status, payload = self._post(
                            server,
                            authorization=authorization,
                        )
                        self.assertEqual(status, 401)
                        self.assertEqual(
                            payload["error"]["code"], "unauthorized"
                        )
                self.assertEqual(provider.requests, ())
                with patch(
                    "rapp_stack_cubby.runtime.auth.hmac.compare_digest",
                    wraps=__import__("hmac").compare_digest,
                ) as compare:
                    status, payload = self._post(
                        server,
                        authorization=bearer_authorization(token),
                    )
                self.assertEqual(status, 200)
                self.assertEqual(payload["response"], "authenticated")
                compare.assert_called_once()
                self.assertNotIn(
                    bearer_authorization(token),
                    json.dumps(payload),
                )
                status, _ = self._get_health(server)
                self.assertEqual(status, 401)
            finally:
                server.shutdown()

    @staticmethod
    def _config(fixture: RuntimeFixture, token) -> RuntimeConfig:
        return RuntimeConfig(
            soul_path=fixture.soul,
            agent_directories=(fixture.agents,),
            data_root=fixture.data,
            instance_id="auth-config",
            root=fixture.root,
            principal="auth-principal",
            model="auth-model",
            auth_token_file=token,
        )

    @staticmethod
    def _post(
        server: RuntimeServer,
        *,
        authorization: str | None,
    ) -> tuple[int, dict]:
        headers = {"Content-Type": "application/json"}
        if authorization is not None:
            headers["Authorization"] = authorization
        connection = http.client.HTTPConnection(
            "127.0.0.1", server.port, timeout=2
        )
        try:
            connection.request(
                "POST",
                "/chat",
                body=b'{"user_input":"owner content"}',
                headers=headers,
            )
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    @staticmethod
    def _get_health(server: RuntimeServer) -> tuple[int, dict]:
        connection = http.client.HTTPConnection(
            "127.0.0.1", server.port, timeout=2
        )
        try:
            connection.request("GET", "/health")
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
