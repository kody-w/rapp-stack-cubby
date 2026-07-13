#!/usr/bin/env python3.11
"""Build the explicit external controller loadout."""

from __future__ import annotations

import sys

from rapp_stack_cubby.cli import main


if __name__ == "__main__":
    raise SystemExit(main(["controller-loadout", *sys.argv[1:]]))
