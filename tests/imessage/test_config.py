from __future__ import annotations

import json
import os
import stat
import unittest

from rapp_stack_cubby.imessage.config import ConfigError, IMessageConfig

from ._support import WorkDirectory, config_payload, make_config


class IMessageConfigTests(unittest.TestCase):
    def test_exact_schema_and_private_mode(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            self.assertEqual(config.config_path, root / "config.json")
            self.assertEqual(
                stat.S_IMODE(config.config_path.stat().st_mode),
                0o600,
            )
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertEqual(IMessageConfig.load(config.config_path), config)

            value = config_payload(root, schema="wrong")
            with self.assertRaises(ConfigError):
                IMessageConfig.from_dict(value)
            value = config_payload(root)
            value["unexpected"] = True
            with self.assertRaises(ConfigError):
                IMessageConfig.from_dict(value)

    def test_owner_only_fields_are_rejected(self) -> None:
        with WorkDirectory() as root:
            unsafe = (
                {"allowed_dm_handles": ["other"]},
                {"allowed_group_chat_ids": ["group"]},
                {"groups_enabled": True},
                {"mention_required": True},
                {"mention_tokens": ["token"]},
                {"sms_fallback": True},
                {"attachments_enabled": True},
                {"reactions_enabled": True},
                {"imsg_version": "0.12.4"},
            )
            for override in unsafe:
                with self.subTest(override=override):
                    with self.assertRaises(ConfigError):
                        IMessageConfig.from_dict(config_payload(root, **override))

    def test_only_uncredentialed_loopback_chat_url_is_allowed(self) -> None:
        with WorkDirectory() as root:
            for url in (
                "https://127.0.0.1:8756/chat",
                "http://remote.invalid/chat",
                "http://user:secret@127.0.0.1/chat",
                "http://127.0.0.1/health",
                "http://127.0.0.1/chat?token=value",
            ):
                with self.subTest(url=url):
                    with self.assertRaises(ConfigError):
                        IMessageConfig.from_dict(
                            config_payload(root, global_controller_url=url)
                        )
            config = IMessageConfig.from_dict(
                config_payload(root, global_controller_url="http://[::1]:8756/chat")
            )
            self.assertEqual(config.global_controller_url, "http://[::1]:8756/chat")

    def test_service_does_not_expand_home_or_follow_state_symlink(self) -> None:
        with WorkDirectory() as root:
            value = config_payload(root, state_dir="~/state")
            with self.assertRaises(ConfigError):
                IMessageConfig.from_dict(value)
            real = root / "real-state"
            real.mkdir()
            link = root / "linked-state"
            os.symlink(real, link)
            with self.assertRaises(ConfigError):
                IMessageConfig.from_dict(config_payload(root, state_dir=str(link)))

    def test_load_rejects_public_mode(self) -> None:
        with WorkDirectory() as root:
            config = make_config(root)
            os.chmod(config.config_path, 0o644)
            with self.assertRaises(ConfigError):
                IMessageConfig.load(config.config_path)
            value = json.loads(config.config_path.read_text(encoding="utf-8"))
            self.assertIn("owner_handles", value)


if __name__ == "__main__":
    unittest.main()
