"""Controller loadout support that never mutates source worktrees."""

from .loadout import (
    ControllerLoadoutError,
    build_controller_loadout,
    verify_controller_loadout,
)

__all__ = [
    "ControllerLoadoutError",
    "build_controller_loadout",
    "verify_controller_loadout",
]
