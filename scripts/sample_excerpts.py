"""Sample turn-aligned excerpts for labelling.

Deterministic: the seed is recorded in the output so the sample is reproducible
and demonstrably not cherry-picked toward passages that are easy to label.

The SME transcript is sampled with a stratification bias toward regions
containing structured identifiers, because those are the rarest classes and an
unstratified sample would leave PHONE and CUSTOMER_ID with a support of one or
two — a count from which no F1 means anything.

Emits unlabelled records. A human fills in `entities`.
"""

from __future__ import annotations

import argparse
import random
import re
from pathlib import Path

from privacy_gateway.evaluation.gold import GoldSet, excerpt, sha256_of
from privacy_gateway.preprocessing.normalizer import Normalizer
from privacy_gateway.preprocessing.transcript import TranscriptParser

REPO = Path(__file__).resolve().parents[1]
IDENTIFIER_RE = re.compile(r"@|https?://|\+\d{2}|\b[A-Z]{2,5}-\d{3,}\b")

MIN_CHARS = 400
MAX_CHARS = 1500


def turn_bounds(text: str) -> list[tuple[int, int]]:
    parsed = TranscriptParser().parse(text)
    if parsed.format == "unstructured":
        return [(0, len(text))]
    return [
        (t.speaker.line_start if t.speaker else t.body_start, t.body_end) for t in parsed.turns
    ]


def build_excerpts(text: str, bounds: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Group whole turns into excerpts of a workable size."""
    out: list[tuple[int, int]] = []
    start = bounds[0][0]
    for _, end in bounds:
        if end - start >= MIN_CHARS:
            out.append((start, min(end, start + MAX_CHARS)))
            start = end
    if start < bounds[-1][1] and bounds[-1][1] - start >= MIN_CHARS // 2:
        out.append((start, bounds[-1][1]))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20260927)
    parser.add_argument("--pod", type=int, default=12)
    parser.add_argument("--sme", type=int, default=10)
    parser.add_argument("--out", type=Path, default=REPO / "evaluation" / "gold")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    normalizer = Normalizer()

    for name, count, stratify in (
        ("pod_meeting.txt", args.pod, False),
        ("sme_meeting_transcript.txt", args.sme, True),
    ):
        source = REPO / "test_data" / name
        raw = source.read_bytes().decode("utf-8")
        normalized = normalizer.normalize(raw)
        candidates = build_excerpts(normalized.text, turn_bounds(normalized.text))

        if stratify:
            rich = [c for c in candidates if IDENTIFIER_RE.search(normalized.text[c[0] : c[1]])]
            plain = [c for c in candidates if c not in rich]
            rng.shuffle(rich)
            rng.shuffle(plain)
            chosen = rich[: max(6, count // 2)] + plain[: count - max(6, count // 2)]
        else:
            chosen = candidates[:]
            rng.shuffle(chosen)
            chosen = chosen[:count]
        chosen.sort()

        stem = name.removesuffix(".txt")
        documents = [
            excerpt(
                normalized.text,
                start,
                end,
                doc_id=f"{stem[:3]}-{index:03d}",
                source_file=f"test_data/{name}",
                source_sha=sha256_of(source),
                split="dev" if index % 4 else "test",
                labeler="",
                labeled_at="",
            )
            for index, (start, end) in enumerate(chosen, 1)
        ]
        path = args.out / f"{stem}.unlabelled.jsonl"
        GoldSet(tuple(documents)).save(path)
        print(f"{len(documents)} excerpts -> {path}")
    print(f"seed={args.seed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
