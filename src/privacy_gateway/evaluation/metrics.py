"""Detection metrics.

The headline criterion is **strict**: exact start, exact end, exact type. That
is an opinionated choice and the reason is this project specifically -- the
defect being repaired *is* a boundary defect. Under partial-credit matching,
``<PER_2>ehal Fahmy`` scores as a near-hit on "Rania Fahmy", and the prototype
would report roughly 80% recall while corrupting the document. Strict matching
is the only criterion aligned with the property the gateway must actually hold.

Looser criteria are computed too, because the gap between them is informative:
strict versus overlap isolates the boundary-error budget, and strict versus
type-agnostic isolates type confusion.

Two figures are reported *above* F1, because for a privacy gateway they matter
more:

``docs_with_any_leak``  documents where at least one gold entity was missed
                        entirely. The number a reviewer asks for first.
``char_recall``         the share of gold sensitive *characters* covered.
                        Missing two characters of a surname is a partial
                        breach, and F1 cannot express that.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from ..entities.entity import DetectedEntity
from .gold import GoldDocument, GoldSet, GoldSpan

#: Types excluded from scoring on both sides. Dates are policy-allowed by
#: default and would otherwise dominate every count.
EXCLUDED_TYPES: frozenset[str] = frozenset({"DATE"})

#: Below this many gold spans a per-type F1 has a confidence interval wider
#: than the differences it is meant to show, so raw counts are reported.
MIN_SUPPORT_FOR_F1 = 10


@dataclass(frozen=True, slots=True)
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return 2 * p * r / (p + r)

    def to_dict(self, support: int | None = None) -> dict[str, object]:
        out: dict[str, object] = {"tp": self.tp, "fp": self.fp, "fn": self.fn}
        if support is not None and support < MIN_SUPPORT_FOR_F1:
            out["note"] = f"support {support} < {MIN_SUPPORT_FOR_F1}; counts only"
            return out
        out["precision"] = _round(self.precision)
        out["recall"] = _round(self.recall)
        out["f1"] = _round(self.f1)
        return out


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 4)


@dataclass(frozen=True, slots=True)
class Error:
    doc_id: str
    start: int
    end: int
    entity_type: str
    text: str
    context: str
    detectors: tuple[str, ...] = ()
    confidence: float | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "doc_id": self.doc_id,
            "start": self.start,
            "end": self.end,
            "type": self.entity_type,
            "text": self.text,
            "context": self.context,
            "detectors": list(self.detectors),
            "confidence": self.confidence,
        }


@dataclass(frozen=True, slots=True)
class Evaluation:
    strict: Counts = field(default_factory=Counts)
    type_agnostic: Counts = field(default_factory=Counts)
    overlap_typed: Counts = field(default_factory=Counts)
    boundary_relaxed: Counts = field(default_factory=Counts)
    per_type: Mapping[str, Counts] = field(default_factory=dict)
    per_type_support: Mapping[str, int] = field(default_factory=dict)
    char_recall: float | None = None
    docs_with_any_leak: int = 0
    docs_total: int = 0
    false_positives: tuple[Error, ...] = ()
    false_negatives: tuple[Error, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            # Reported first, deliberately.
            "docs_with_any_leak": self.docs_with_any_leak,
            "docs_total": self.docs_total,
            "char_recall": _round(self.char_recall),
            "strict": self.strict.to_dict(),
            "type_agnostic_strict": self.type_agnostic.to_dict(),
            "overlap_typed": self.overlap_typed.to_dict(),
            "boundary_relaxed": self.boundary_relaxed.to_dict(),
            "by_type": {
                t: c.to_dict(self.per_type_support.get(t))
                for t, c in sorted(self.per_type.items())
            },
            "false_positive_count": len(self.false_positives),
            "false_negative_count": len(self.false_negatives),
        }


def _context(text: str, start: int, end: int, width: int = 50) -> str:
    left = max(0, start - width)
    right = min(len(text), end + width)
    return (
        text[left:start].replace("\n", " ")
        + "»"
        + text[start:end].replace("\n", " ")
        + "«"
        + text[end:right].replace("\n", " ")
    )


def _strip(text: str) -> str:
    return text.strip(" \t\r\n`\"'*_()[]{}.,;:!?").removesuffix("'s")


def _scored_gold(doc: GoldDocument) -> list[GoldSpan]:
    return [e for e in doc.scored_entities if e.entity_type not in EXCLUDED_TYPES]


def _scored_pred(entities: Sequence[DetectedEntity]) -> list[DetectedEntity]:
    return [e for e in entities if e.entity_type not in EXCLUDED_TYPES]


def evaluate_document(
    doc: GoldDocument, predictions: Sequence[DetectedEntity]
) -> tuple[Evaluation, set[int]]:
    """Score one document. Returns the evaluation and the covered gold indices."""
    gold = _scored_gold(doc)
    pred = _scored_pred(predictions)

    gold_keys = {(g.start, g.end, g.entity_type) for g in gold}
    pred_keys = {(p.start, p.end, p.entity_type) for p in pred}
    strict_tp = len(gold_keys & pred_keys)

    gold_spans = {(g.start, g.end) for g in gold}
    pred_spans = {(p.start, p.end) for p in pred}
    agnostic_tp = len(gold_spans & pred_spans)

    gold_relaxed = {(_strip(g.text).casefold(), g.entity_type) for g in gold}
    pred_relaxed = {(_strip(p.text).casefold(), p.entity_type) for p in pred}
    relaxed_tp = len(gold_relaxed & pred_relaxed)

    # Greedy one-to-one overlap assignment, deterministic by (gold, pred) start.
    matched_gold: set[int] = set()
    matched_pred: set[int] = set()
    pairs = []
    for gi, g in enumerate(gold):
        for pi, p in enumerate(pred):
            if p.entity_type != g.entity_type:
                continue
            overlap = min(g.end, p.end) - max(g.start, p.start)
            if overlap > 0:
                union = max(g.end, p.end) - min(g.start, p.start)
                pairs.append((-overlap / union, g.start, p.start, gi, pi))
    for _, _, _, gi, pi in sorted(pairs):
        if gi not in matched_gold and pi not in matched_pred:
            matched_gold.add(gi)
            matched_pred.add(pi)
    overlap_tp = len(matched_gold)

    # Character-level recall, type-agnostic and position-sensitive.
    covered = 0
    total_chars = 0
    covered_indices: set[int] = set()
    for _i, p in enumerate(pred):
        covered_indices.update(range(p.start, p.end))
    leaked_docs = 0
    for g in gold:
        total_chars += g.end - g.start
        covered += sum(1 for i in range(g.start, g.end) if i in covered_indices)
    missed = [g for g in gold if not any(i in covered_indices for i in range(g.start, g.end))]
    if missed:
        leaked_docs = 1

    per_type: dict[str, Counts] = {}
    support: dict[str, int] = {}
    for entity_type in {g.entity_type for g in gold} | {p.entity_type for p in pred}:
        g_keys = {k for k in gold_keys if k[2] == entity_type}
        p_keys = {k for k in pred_keys if k[2] == entity_type}
        per_type[entity_type] = Counts(
            tp=len(g_keys & p_keys), fp=len(p_keys - g_keys), fn=len(g_keys - p_keys)
        )
        support[entity_type] = len(g_keys)

    false_positives = tuple(
        Error(
            doc_id=doc.doc_id,
            start=p.start,
            end=p.end,
            entity_type=p.entity_type,
            text=p.text,
            context=_context(doc.text, p.start, p.end),
            detectors=(p.detector,),
            confidence=round(p.confidence, 4),
        )
        for p in pred
        if (p.start, p.end, p.entity_type) not in gold_keys
    )
    false_negatives = tuple(
        Error(
            doc_id=doc.doc_id,
            start=g.start,
            end=g.end,
            entity_type=g.entity_type,
            text=g.text,
            context=_context(doc.text, g.start, g.end),
        )
        for g in gold
        if (g.start, g.end, g.entity_type) not in pred_keys
    )

    evaluation = Evaluation(
        strict=Counts(strict_tp, len(pred_keys) - strict_tp, len(gold_keys) - strict_tp),
        type_agnostic=Counts(
            agnostic_tp, len(pred_spans) - agnostic_tp, len(gold_spans) - agnostic_tp
        ),
        overlap_typed=Counts(overlap_tp, len(pred) - overlap_tp, len(gold) - overlap_tp),
        boundary_relaxed=Counts(
            relaxed_tp, len(pred_relaxed) - relaxed_tp, len(gold_relaxed) - relaxed_tp
        ),
        per_type=per_type,
        per_type_support=support,
        char_recall=(covered / total_chars) if total_chars else None,
        docs_with_any_leak=leaked_docs,
        docs_total=1,
        false_positives=false_positives,
        false_negatives=false_negatives,
    )
    return evaluation, covered_indices


def _sum(counts: Sequence[Counts]) -> Counts:
    return Counts(
        tp=sum(c.tp for c in counts),
        fp=sum(c.fp for c in counts),
        fn=sum(c.fn for c in counts),
    )


def evaluate(
    gold: GoldSet, predictions: Mapping[str, Sequence[DetectedEntity]]
) -> Evaluation:
    """Aggregate over a whole gold set."""
    per_doc = [evaluate_document(doc, predictions.get(doc.doc_id, ()))[0] for doc in gold]
    if not per_doc:
        return Evaluation()

    per_type: dict[str, list[Counts]] = {}
    support: dict[str, int] = {}
    for evaluation in per_doc:
        for entity_type, counts in evaluation.per_type.items():
            per_type.setdefault(entity_type, []).append(counts)
        for entity_type, value in evaluation.per_type_support.items():
            support[entity_type] = support.get(entity_type, 0) + value

    chars = [e.char_recall for e in per_doc if e.char_recall is not None]
    return Evaluation(
        strict=_sum([e.strict for e in per_doc]),
        type_agnostic=_sum([e.type_agnostic for e in per_doc]),
        overlap_typed=_sum([e.overlap_typed for e in per_doc]),
        boundary_relaxed=_sum([e.boundary_relaxed for e in per_doc]),
        per_type={t: _sum(c) for t, c in per_type.items()},
        per_type_support=support,
        char_recall=(sum(chars) / len(chars)) if chars else None,
        docs_with_any_leak=sum(e.docs_with_any_leak for e in per_doc),
        docs_total=len(per_doc),
        false_positives=tuple(x for e in per_doc for x in e.false_positives),
        false_negatives=tuple(x for e in per_doc for x in e.false_negatives),
    )


#: A span sitting on a structural speaker-label line. These are the easiest
#: entities in a transcript and the most numerous -- 144 of the 168 scored gold
#: spans here -- so an aggregate F1 is dominated by them. Metrics are reported
#: both ways so the headline number is not carried by repeated headers.
_TEAMS_LABEL_RE = re.compile(r"^[ \t]*\S.*?[ \t]{2,}\d{1,3}:\d{2}[ \t]*$", re.MULTILINE)
_MD_LABEL_RE = re.compile(r"^\*\*\d{1,2}:\d{2}[^\r\n]*:\*\*[ \t]*$", re.MULTILINE)


def speaker_label_spans(text: str) -> list[tuple[int, int]]:
    """Character ranges of every structural speaker-label line."""
    return [m.span() for m in _TEAMS_LABEL_RE.finditer(text)] + [
        m.span() for m in _MD_LABEL_RE.finditer(text)
    ]


def on_speaker_line(start: int, end: int, lines: Sequence[tuple[int, int]]) -> bool:
    return any(ls <= start and end <= le for ls, le in lines)


def without_speaker_lines(
    gold: GoldSet, predictions: Mapping[str, Sequence[DetectedEntity]]
) -> tuple[GoldSet, dict[str, list[DetectedEntity]]]:
    """Drop everything that sits on a speaker-label line, from both sides."""
    from .gold import GoldDocument as _Doc

    documents = []
    filtered: dict[str, list[DetectedEntity]] = {}
    for doc in gold:
        lines = speaker_label_spans(doc.text)
        documents.append(
            _Doc(
                doc_id=doc.doc_id,
                text=doc.text,
                entities=tuple(
                    e for e in doc.entities if not on_speaker_line(e.start, e.end, lines)
                ),
                source_file=doc.source_file,
                source_sha256=doc.source_sha256,
                source_char_start=doc.source_char_start,
                source_char_end=doc.source_char_end,
                labeler=doc.labeler,
                labeled_at=doc.labeled_at,
                guideline_version=doc.guideline_version,
                split=doc.split,
            )
        )
        filtered[doc.doc_id] = [
            p
            for p in predictions.get(doc.doc_id, ())
            if not on_speaker_line(p.start, p.end, lines)
        ]
    return GoldSet(tuple(documents)), filtered
