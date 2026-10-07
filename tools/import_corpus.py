"""Scaffold schema-2 sidecars for a directory of real documents.

This does not, and cannot, produce a labelled corpus -- that needs real text
from the intended domain and a human labeller reading it. What it does is the
mechanical part: for each ``.txt`` file in a source directory, write an empty
``.expected.json`` sidecar in the same schema every fixture in this repo
already uses (`must_redact`, `must_keep`, `same_entity`, `gold_complete:
false`), so a labeller has a form to fill in rather than a blank file, and so
`tools/derive_gold_spans.py --check` can validate it the moment values are
added.

The imported documents are never copied into ``tests/fixtures/``. A domain
corpus almost certainly contains real PII.
Point ``--out`` outside the repository, or at a
path this repository's ``.gitignore`` already excludes, and it stays there.

Usage::

    uv run python tools/import_corpus.py --source /path/to/real/transcripts --out /path/to/corpus
    uv run python tools/import_corpus.py --source ... --out ... --check   # validate afterward

Each staged document then needs `must_redact`, `must_keep`,
`same_entity` and `gold_negatives` filled in by hand (tests/fixtures/ has examples).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _skeleton() -> dict:
    return {
        "must_redact": [],
        "must_keep": [],
        "same_entity": [],
        "schema": 2,
        "gold_complete": False,
    }


def import_directory(source: Path, out: Path, *, overwrite: bool = False) -> list[Path]:
    """Copy each ``.txt`` in ``source`` to ``out``, with an empty sidecar.

    A document with an existing sidecar in ``out`` is left alone unless
    ``overwrite`` is set -- re-running this must not erase a labeller's work.
    """
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for source_path in sorted(source.glob("*.txt")):
        text_path = out / source_path.name
        sidecar_path = out / f"{source_path.stem}.expected.json"

        if text_path.exists() and not overwrite:
            print(f"  skip (exists): {source_path.name}")
            continue

        text_path.write_text(source_path.read_text(encoding="utf-8"), encoding="utf-8")

        if sidecar_path.exists() and not overwrite:
            print(f"  wrote text, kept existing sidecar: {source_path.name}")
        else:
            sidecar_path.write_text(
                json.dumps(_skeleton(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            print(f"  wrote text + empty sidecar: {source_path.name}")
        written.append(text_path)

    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, type=Path, help="directory of real .txt documents")
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="destination directory, OUTSIDE this repository or already gitignored",
    )
    parser.add_argument("--overwrite", action="store_true", help="replace existing text and sidecars")
    parser.add_argument(
        "--check",
        action="store_true",
        help="run tools/derive_gold_spans.py --check against --out afterward",
    )
    args = parser.parse_args()

    if not args.source.is_dir():
        parser.error(f"no such directory: {args.source}")

    try:
        args.out.resolve().relative_to(PROJECT_ROOT)
        print(
            f"WARNING: --out ({args.out}) is inside this repository. "
            "Make sure it is covered by .gitignore before adding any real "
            "documents here.",
            file=sys.stderr,
        )
    except ValueError:
        pass  # outside the repo entirely -- the common and recommended case

    written = import_directory(args.source, args.out, overwrite=args.overwrite)
    print(f"\n{len(written)} document(s) staged in {args.out}")
    print("Next: fill in must_redact / must_keep / same_entity per document,")
    print("      by hand, then:")
    print(f"  uv run python tools/derive_gold_spans.py --write --dir {args.out}")
    print(f"  uv run python tools/evaluate.py --dir {args.out}   # score it like any fixture")

    if args.check:
        result = subprocess.run(
            [
                sys.executable,
                str(PROJECT_ROOT / "tools" / "derive_gold_spans.py"),
                "--check",
                "--dir",
                str(args.out),
            ],
        )
        return result.returncode

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
