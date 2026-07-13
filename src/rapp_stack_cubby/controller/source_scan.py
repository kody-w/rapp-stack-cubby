"""Deterministically scan the single-file controller execution surface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from ..catalog import (
    CONTROLLER_AGENT_RELATIVE,
    CatalogValidationError,
    build_controller_catalog,
)


def main(argv: Sequence[str] | None = None) -> int:
    """Validate the sole top-level controller without importing it."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    arguments = parser.parse_args(argv)
    try:
        catalog = build_controller_catalog(arguments.root)
    except (CatalogValidationError, OSError, UnicodeError) as error:
        print(f"error: {CONTROLLER_AGENT_RELATIVE}: {error}", file=sys.stderr)
        return 1
    print(
        "PASS controller source scan: one streamable BasicAgent; "
        f"{len(catalog['actions'])} fixed actions; "
        "fixed guarded subprocess and loopback surfaces"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
