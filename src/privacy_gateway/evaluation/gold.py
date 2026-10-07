"""Labelled evaluation data.

JSONL, one document per line: line-diffable in review, streamable, and a
corrupt record does not invalidate the file.

Two fields exist to keep the numbers honest rather than to describe the data.

``provenance`` records whether a span was identified independently or merely
accepted from a detector's proposal. If almost every gold span was proposed by the detectors
being measured, recall is close to 100% by construction and the dataset is
measuring itself. A validation check enforces a floor on human-added spans.

``certainty`` marks spans that a careful labeller could not resolve -- noisy
ASR fragments that may or may not be a name. Those are excluded from both the
numerator and the denominator rather than being guessed at, and counted
separately in the report.
"""

from __future__ import annotations

import hashlib
import itertools
import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

Certainty = Literal["certain", "probable", "ambiguous"]
Provenance = Literal["independent", "accepted_candidate"]
Split = Literal["dev", "test"]

#: Spans at this certainty are excluded from scoring entirely.
EXCLUDED_CERTAINTY: frozenset[str] = frozenset({"ambiguous"})


@dataclass(frozen=True, slots=True)
class GoldSpan:
    start: int
    end: int
    entity_type: str
    text: str
    provenance: Provenance = "independent"
    certainty: Certainty = "certain"
    proposed_by: tuple[str, ...] = ()
    note: str = ""

    @property
    def scored(self) -> bool:
        return self.certainty not in EXCLUDED_CERTAINTY


@dataclass(frozen=True, slots=True)
class GoldDocument:
    doc_id: str
    text: str
    entities: tuple[GoldSpan, ...] = ()
    source_file: str = ""
    source_sha256: str = ""
    source_char_start: int = 0
    source_char_end: int = 0
    labeler: str = ""
    labeled_at: str = ""
    guideline_version: str = "1.0"
    split: Split = "dev"

    @property
    def scored_entities(self) -> tuple[GoldSpan, ...]:
        return tuple(e for e in self.entities if e.scored)

    def validate(self) -> list[str]:
        """Structural problems with this record, as human-readable strings."""
        problems: list[str] = []
        if not self.doc_id:
            problems.append("missing doc_id")
        if not self.text:
            problems.append(f"{self.doc_id}: empty text")
        ordered = sorted(self.entities, key=lambda e: (e.start, e.end))
        for entity in self.entities:
            if entity.start < 0 or entity.end > len(self.text) or entity.end <= entity.start:
                problems.append(f"{self.doc_id}: span out of range at {entity.start}")
                continue
            if self.text[entity.start : entity.end] != entity.text:
                problems.append(
                    f"{self.doc_id}: text disagrees with span at {entity.start}"
                )
        for a, b in itertools.pairwise(ordered):
            if a.end > b.start:
                problems.append(f"{self.doc_id}: overlapping gold spans at {b.start}")
        return problems


@dataclass(frozen=True, slots=True)
class GoldSet:
    documents: tuple[GoldDocument, ...] = ()
    path: Path | None = None

    def __len__(self) -> int:
        return len(self.documents)

    def __iter__(self) -> Iterator[GoldDocument]:
        return iter(self.documents)

    def for_split(self, split: str | None) -> GoldSet:
        if not split:
            return self
        return GoldSet(tuple(d for d in self.documents if d.split == split), self.path)

    @property
    def scored_span_count(self) -> int:
        return sum(len(d.scored_entities) for d in self.documents)

    @property
    def excluded_span_count(self) -> int:
        return sum(len(d.entities) - len(d.scored_entities) for d in self.documents)

    def per_type_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for doc in self.documents:
            for entity in doc.scored_entities:
                counts[entity.entity_type] = counts.get(entity.entity_type, 0) + 1
        return dict(sorted(counts.items()))

    def independent_fraction(self) -> float:
        """Share of spans identified without seeing detector candidates.

        The circularity guard. If nearly every gold span was proposed by a
        detector being measured, recall against this set is high by
        construction and means little.
        """
        total = self.scored_span_count
        if not total:
            return 0.0
        added = sum(
            1
            for d in self.documents
            for e in d.scored_entities
            if e.provenance == "independent"
        )
        return added / total

    def validate(self) -> list[str]:
        problems: list[str] = []
        seen: set[str] = set()
        for doc in self.documents:
            if doc.doc_id in seen:
                problems.append(f"duplicate doc_id: {doc.doc_id}")
            seen.add(doc.doc_id)
            problems.extend(doc.validate())
        return problems

    # -- io ---------------------------------------------------------------
    @classmethod
    def load(cls, path: Path | str) -> GoldSet:
        path = Path(path)
        files = sorted(path.glob("*.jsonl")) if path.is_dir() else [path]
        documents: list[GoldDocument] = []
        for file in files:
            for line in file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("//"):
                    continue
                documents.append(cls._document(json.loads(line)))
        return cls(tuple(documents), path)

    @staticmethod
    def _document(row: dict[str, Any]) -> GoldDocument:
        return GoldDocument(
            doc_id=str(row["doc_id"]),
            text=str(row["text"]),
            entities=tuple(
                GoldSpan(
                    start=int(e["start"]),
                    end=int(e["end"]),
                    entity_type=str(e["type"] if "type" in e else e["entity_type"]).upper(),
                    text=str(e["text"]),
                    provenance=str(e.get("provenance", "independent")),  # type: ignore[arg-type]
                    certainty=str(e.get("certainty", "certain")),  # type: ignore[arg-type]
                    proposed_by=tuple(e.get("proposed_by", ())),
                    note=str(e.get("note", "")),
                )
                for e in row.get("entities", ())
            ),
            source_file=str(row.get("source_file", "")),
            source_sha256=str(row.get("source_sha256", "")),
            source_char_start=int(row.get("source_char_start", 0)),
            source_char_end=int(row.get("source_char_end", 0)),
            labeler=str(row.get("labeler", "")),
            labeled_at=str(row.get("labeled_at", "")),
            guideline_version=str(row.get("guideline_version", "1.0")),
            split=str(row.get("split", "dev")),  # type: ignore[arg-type]
        )

    @staticmethod
    def dump_document(doc: GoldDocument) -> str:
        return json.dumps(
            {
                "doc_id": doc.doc_id,
                "source_file": doc.source_file,
                "source_sha256": doc.source_sha256,
                "source_char_start": doc.source_char_start,
                "source_char_end": doc.source_char_end,
                "text": doc.text,
                "entities": [
                    {
                        "start": e.start,
                        "end": e.end,
                        "type": e.entity_type,
                        "text": e.text,
                        "provenance": e.provenance,
                        "certainty": e.certainty,
                        "proposed_by": list(e.proposed_by),
                        "note": e.note,
                    }
                    for e in doc.entities
                ],
                "labeler": doc.labeler,
                "labeled_at": doc.labeled_at,
                "guideline_version": doc.guideline_version,
                "split": doc.split,
            },
            ensure_ascii=True,
        )

    def save(self, path: Path | str) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "\n".join(self.dump_document(d) for d in self.documents) + "\n", encoding="utf-8"
        )
        return path


def sha256_of(path: Path | str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def excerpt(
    text: str, start: int, end: int, doc_id: str, source_file: str, source_sha: str, **kw: Any
) -> GoldDocument:
    """Build an unlabelled excerpt record, ready for a human to annotate."""
    return GoldDocument(
        doc_id=doc_id,
        text=text[start:end],
        source_file=source_file,
        source_sha256=source_sha,
        source_char_start=start,
        source_char_end=end,
        **kw,
    )


#: Minimum share of gold spans identified independently of the detectors.
#: Below this the dataset is largely a mirror of the systems it measures.
MIN_INDEPENDENT_FRACTION = 0.15


def circularity_warning(gold: GoldSet) -> str | None:
    fraction = gold.independent_fraction()
    if fraction < MIN_INDEPENDENT_FRACTION:
        return (
            f"only {fraction:.0%} of gold spans were identified independently of "
            f"the detectors (floor {MIN_INDEPENDENT_FRACTION:.0%}); recall figures "
            "from this dataset may be self-fulfilling"
        )
    return None

