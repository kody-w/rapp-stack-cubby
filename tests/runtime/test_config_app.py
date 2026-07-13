from __future__ import annotations

import dataclasses
import json
import os
import stat
import unittest
from pathlib import Path
from unittest.mock import patch

from rapp_stack_cubby.runtime.app import RuntimeApp
from rapp_stack_cubby.runtime.config import (
    RuntimeConfig,
    RuntimeConfigurationError,
    validate_loopback_host,
    validate_python_version,
)
from rapp_stack_cubby.runtime.provider import ProviderResponse, ScriptedProvider
from rapp_stack_cubby.runtime.provider import ATTESTATION_MODEL
from rapp_stack_cubby.runtime.registry import RegistryLoadError

from ._support import STRICT_ECHO_AGENT, RuntimeFixture


class RuntimeConfigTests(unittest.TestCase):
    def test_config_is_immutable_and_accepts_ephemeral_port(self) -> None:
        with RuntimeFixture() as fixture:
            config = RuntimeConfig(
                soul_path=fixture.soul,
                agent_directories=(fixture.agents,),
                data_root=fixture.data,
                instance_id="test-instance",
                root=fixture.root,
                principal="test-principal",
                model="test-model",
                port=0,
            )

            self.assertEqual(config.port, 0)
            with self.assertRaises(dataclasses.FrozenInstanceError):
                config.port = 1

    def test_product_config_has_no_compatibility_registry_mode(self) -> None:
        with RuntimeFixture() as fixture:
            with self.assertRaises(TypeError):
                RuntimeConfig(
                    soul_path=fixture.soul,
                    agent_directories=(fixture.agents,),
                    data_root=fixture.data,
                    instance_id="no-compatibility",
                    root=fixture.root,
                    principal="test-principal",
                    model="test-model",
                    registry_compatibility_mode=True,  # type: ignore[call-arg]
                )

    def test_missing_or_symlinked_paths_fail_clearly(self) -> None:
        with RuntimeFixture() as fixture:
            with self.assertRaisesRegex(
                RuntimeConfigurationError, "soul path does not exist"
            ):
                RuntimeConfig(
                    soul_path=fixture.root / "missing.md",
                    agent_directories=(fixture.agents,),
                    data_root=fixture.data,
                    instance_id="test-instance",
                    root=fixture.root,
                    principal="test-principal",
                    model="test-model",
                )
            linked = fixture.root / "linked-agents"
            linked.symlink_to(fixture.agents, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeConfigurationError, "symbolic"):
                RuntimeConfig(
                    soul_path=fixture.soul,
                    agent_directories=(linked,),
                    data_root=fixture.data,
                    instance_id="test-instance",
                    root=fixture.root,
                    principal="test-principal",
                    model="test-model",
                )

    def test_only_loopback_hosts_are_accepted(self) -> None:
        self.assertEqual(validate_loopback_host("localhost"), "localhost")
        self.assertEqual(validate_loopback_host("127.0.0.1"), "127.0.0.1")
        self.assertEqual(validate_loopback_host("[::1]"), "::1")
        for host in ("0.0.0.0", "::", "example.com"):
            with self.subTest(host=host):
                with self.assertRaises(RuntimeConfigurationError):
                    validate_loopback_host(host)

    def test_unsupported_python_fails_before_startup(self) -> None:
        with patch(
            "rapp_stack_cubby.runtime.config.sys.version_info",
            (3, 12, 0),
        ):
            with self.assertRaisesRegex(RuntimeConfigurationError, "3.11"):
                validate_python_version()

    def test_model_and_agent_identity_context_are_explicit(self) -> None:
        with RuntimeFixture() as fixture:
            with self.assertRaises(TypeError):
                RuntimeConfig(  # type: ignore[call-arg]
                    soul_path=fixture.soul,
                    agent_directories=(fixture.agents,),
                    data_root=fixture.data,
                    instance_id="missing-model",
                    root=fixture.root,
                    principal="principal-a",
                )
            config = RuntimeConfig(
                soul_path=fixture.soul,
                agent_directories=(fixture.agents,),
                data_root=fixture.data,
                instance_id="explicit-context",
                root=fixture.root,
                principal="principal-a",
                model="supported-model",
                allow_agent_writes=True,
            )
            self.assertEqual(
                config.generated_agents_dir,
                fixture.data / "generated-agents",
            )
            self.assertEqual(
                stat.S_IMODE(config.generated_agents_dir.stat().st_mode),
                0o700,
            )

    def test_reserved_attestation_model_requires_explicit_signed_mode(self):
        with RuntimeFixture() as fixture:
            values = {
                "soul_path": fixture.soul,
                "agent_directories": (fixture.agents,),
                "data_root": fixture.data,
                "instance_id": "attestation-config",
                "root": fixture.root,
                "principal": "attestation-principal",
                "model": ATTESTATION_MODEL,
            }
            with self.assertRaisesRegex(
                RuntimeConfigurationError, "explicit attestation"
            ):
                RuntimeConfig(**values)
            with self.assertRaisesRegex(
                RuntimeConfigurationError, "signed_only"
            ):
                RuntimeConfig(
                    **values,
                    attestation_mode="offline-self-test",
                )

    def test_live_config_validates_explicit_provider_token_file(self):
        with RuntimeFixture() as fixture:
            token_file = fixture.root / "provider-token.json"
            token_file.write_text(
                json.dumps({"access_token": "synthetic-config-access"})
                + "\n",
                encoding="utf-8",
            )
            os.chmod(token_file, 0o600)
            values = {
                "soul_path": fixture.soul,
                "agent_directories": (fixture.agents,),
                "data_root": fixture.data,
                "instance_id": "provider-token-config",
                "root": fixture.root,
                "principal": "provider-principal",
                "model": "supported-model",
                "github_token_file": token_file,
            }

            config = RuntimeConfig(**values)
            self.assertEqual(config.github_token_file, token_file.resolve())

            os.chmod(token_file, 0o644)
            with self.assertRaisesRegex(
                RuntimeConfigurationError, "0600"
            ):
                RuntimeConfig(**values)


class RuntimeAppTests(unittest.TestCase):
    def test_app_wires_validated_components_without_network(self) -> None:
        with RuntimeFixture() as fixture:
            fixture.write_agent("strict_echo_agent.py", STRICT_ECHO_AGENT)
            config = RuntimeConfig(
                soul_path=fixture.soul,
                agent_directories=(fixture.agents,),
                data_root=fixture.data,
                instance_id="test-instance",
                root=fixture.root,
                principal="test-principal",
                model="test-model",
                port=0,
            )
            app = RuntimeApp(
                config,
                provider=ScriptedProvider([ProviderResponse(content="ok")]),
            )
            try:
                self.assertEqual(app.startup_snapshot.names, ("StrictEcho",))
                self.assertGreater(app.server.port, 0)
                self.assertTrue(app.url.startswith("http://127.0.0.1:"))
            finally:
                app.shutdown()

    def test_app_installs_and_restores_process_agent_environment(self):
        with RuntimeFixture() as fixture:
            fixture.write_agent("strict_echo_agent.py", STRICT_ECHO_AGENT)
            config = RuntimeConfig(
                soul_path=fixture.soul,
                agent_directories=(fixture.agents,),
                data_root=fixture.data,
                instance_id="environment-context",
                root=fixture.root,
                principal="principal-a",
                model="test-model",
                port=0,
                allow_agent_writes=True,
            )
            keys = (
                "RAPP_STACK_ROOT",
                "RAPP_STACK_DATA_DIR",
                "RAPP_STACK_PRINCIPAL",
                "RAPP_STACK_GENERATED_AGENTS_DIR",
                "RAPP_STACK_ALLOW_AGENT_WRITES",
            )
            before = {key: os.environ.get(key) for key in keys}
            app = RuntimeApp(
                config,
                provider=ScriptedProvider(
                    [ProviderResponse(content="ok")]
                ),
            )
            try:
                self.assertEqual(
                    os.environ["RAPP_STACK_ROOT"], str(fixture.root)
                )
                self.assertEqual(
                    os.environ["RAPP_STACK_PRINCIPAL"], "principal-a"
                )
                with self.assertRaises(RuntimeConfigurationError):
                    RuntimeApp(
                        config,
                        provider=ScriptedProvider(
                            [ProviderResponse(content="unused")]
                        ),
                    )
            finally:
                app.shutdown()
            self.assertEqual(
                {key: os.environ.get(key) for key in keys}, before
            )

    def test_app_rejects_invalid_agent_before_serving(self) -> None:
        with RuntimeFixture() as fixture:
            fixture.write_agent(
                "bad_agent.py",
                "class BadAgent:\n"
                "    def perform(self, **kwargs):\n"
                "        return kwargs\n",
            )
            config = RuntimeConfig(
                soul_path=fixture.soul,
                agent_directories=(fixture.agents,),
                data_root=fixture.data,
                instance_id="test-instance",
                root=fixture.root,
                principal="test-principal",
                model="test-model",
                port=0,
            )

            with self.assertRaises(RegistryLoadError):
                RuntimeApp(
                    config,
                    provider=ScriptedProvider([ProviderResponse(content="ok")]),
                )


if __name__ == "__main__":
    unittest.main()
