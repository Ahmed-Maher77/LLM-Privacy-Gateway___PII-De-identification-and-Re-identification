"""Example end-to-end run.

Kept as a convenience entry point. The real interface is the CLI:

    uv run privacy-gateway run test_data/sme_meeting_transcript.txt

Unlike the version this replaces, importing this module does not execute an
LLM call as a side effect.
"""

from __future__ import annotations

import sys
from pathlib import Path

from privacy_gateway.cli import main as cli_main

DEFAULT_INPUT = Path("test_data/sme_meeting_transcript.txt")


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        argv = ["run", str(DEFAULT_INPUT), "--print-answer"]
    return cli_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
