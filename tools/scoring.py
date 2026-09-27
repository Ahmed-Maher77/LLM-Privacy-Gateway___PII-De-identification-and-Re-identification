"""Entity-level scoring for the redaction corpus.

The harness this replaces asked two questions per document: did every string
in ``must_redact`` disappear, and did every string in ``must_keep`` survive.
Both are useful regression checks and both are kept. Neither is a precision
estimate, because neither can see a redaction nobody thought to label. On the
twelve production fixtures the pipeline redacted 112 entities while the labels
covered 71 of them; the other 41 -- "14 days", "$75,000", "French", a bare
"14" -- were invisible, and precision still printed 100%.

Scoring every span the pipeline actually produced is what makes an
over-redaction countable. That requires gold that is exhaustive, so a document
carries ``gold_complete`` and unmatched predictions are only charged as false
positives once it is set. Until then they are reported as ``unverified``, which
is an honest "nobody has looked at this yet" rather than a silent pass.

This module is deliberately free of model imports so its tests run in the fast
suite: it may read ``pii.spans``, ``pii.vault`` and ``pii.patterns``, but never
``pii.middleware``.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from pii.policy import _normalize
from pii.vault import ESCAPE_LABEL


# A gold span whose type could not be inferred mechanically. It matches a
# prediction of any label, so a derived label that nobody verified cannot
# manufacture a false positive and a false negative out of one correct
# redaction.
WILDCARD_LABEL = "PII"

# Labels that name the same underlying thing. The pipeline resolves overlaps by
# specificity (pii/spans.py:LABEL_PRIORITY), so the label it lands on is not
# always the one a human wrote down -- an address fragment may come back as
# LOCATION, and a routing number as BANK_ACCOUNT. Treating these as agreement
# keeps the metric measuring detection rather than taxonomy.
LABEL_EQUIVALENCE: dict[str, frozenset[str]] = {
    "ADDRESS": frozenset({"LOCATION"}),
    "LOCATION": frozenset({"ADDRESS"}),
    "BANK_ACCOUNT": frozenset({"IBAN", "ROUTING_NUMBER"}),
    "IBAN": frozenset({"BANK_ACCOUNT"}),
    "ROUTING_NUMBER": frozenset({"BANK_ACCOUNT"}),
    "PERSON": frozenset({"EPONYMOUS_ORG"}),
    "ORG": frozenset({"EPONYMOUS_ORG"}),
    "CUSTOM_ID": frozenset({"ID", "JOB_ID", "PASSPORT"}),
    "ID": frozenset({"CUSTOM_ID"}),
    "DOB": frozenset({"DATE"}),
    "CONNECTION_STRING": frozenset({"CREDENTIAL", "URL"}),
    "CREDENTIAL": frozenset({"CONNECTION_STRING"}),
    "PHONE": frozenset({"FAX"}),
}

# A recall drop on any of these is a hard failure regardless of what the
# aggregate does. They are the identifiers that are directly actionable
# against a person: losing one is not a rounding error in an F1 score.
CRITICAL_LABELS = frozenset({
    "EMAIL", "SSN", "CREDIT_CARD", "CVV", "CREDENTIAL", "CONNECTION_STRING",
    "IBAN", "BANK_ACCOUNT", "ROUTING_NUMBER", "PASSPORT", "PHONE", "DOB",
})


@dataclass(frozen=True, slots=True)
class GoldSpan:
    """A span of the source that a human or a generator says is PII."""

    start: int
    end: int
    label: str
    text: str
    entity: str = ""          # cluster id; "" means unclustered
    origin: str = "derived"   # derived | manual | generated

    @property
    def length(self) -> int:
        return self.end - self.start

    @classmethod
    def from_dict(cls, raw: dict) -> GoldSpan:
        return cls(
            start=int(raw["start"]),
            end=int(raw["end"]),
            label=str(raw["label"]),
            text=str(raw["text"]),
            entity=str(raw.get("entity", "")),
            origin=str(raw.get("origin", "derived")),
        )

    def as_dict(self) -> dict:
        return {
            "start": self.start,
            "end": self.end,
            "label": self.label,
            "text": self.text,
            "entity": self.entity,
            "origin": self.origin,
        }


@dataclass(frozen=True, slots=True)
class PredSpan:
    """A span the pipeline actually replaced with a placeholder."""

    start: int
    end: int
    label: str
    text: str
    source: str = "model"
    identity: str | None = None

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass(frozen=True, slots=True)
class Match:
    gold: GoldSpan
    pred: PredSpan
    overlap: int

    @property
    def exact(self) -> bool:
        return self.gold.start == self.pred.start and self.gold.end == self.pred.end

    @property
    def contains(self) -> bool:
        """Whether the redaction fully covered the labelled identifier."""
        return self.pred.start <= self.gold.start and self.pred.end >= self.gold.end

    def surviving(self, source: str) -> tuple[str, str]:
        """The parts of the labelled identifier the redaction did not cover."""
        if self.contains:
            return "", ""
        left = source[self.gold.start : min(self.pred.start, self.gold.end)]
        right = source[max(self.pred.end, self.gold.start) : self.gold.end]
        return left, right

    def substantive_remainder(self, source: str) -> str:
        """Surviving text that carries content, not just punctuation.

        A trailing "." left behind by a span that stopped one character short
        of "ROBERT CHEN JR." is a label that is one character too wide, not a
        disclosure. A surviving "14 ... , 75002 Paris, France" is most of a
        street address. Grading on the remainder keeps the gate pointed at the
        second kind without an allowlist that could quietly swallow the first.
        """
        left, right = self.surviving(source)
        remainder = f"{left} {right}".strip()
        return remainder if any(c.isalnum() for c in remainder) else ""


@dataclass
class Alignment:
    matches: list[Match] = field(default_factory=list)
    false_positives: list[PredSpan] = field(default_factory=list)
    false_negatives: list[GoldSpan] = field(default_factory=list)
    unverified: list[PredSpan] = field(default_factory=list)
    gold_complete: bool = False

    @property
    def partial(self) -> list[Match]:
        """Matches where part of the identifier survived in plaintext."""
        return [m for m in self.matches if not m.contains]

    def partial_substantive(self, source: str) -> list[Match]:
        """Partial matches where what survived still carries content.

        This is the gate. A prediction that overlaps a gold span without
        covering it left characters of a real identifier in the output, and
        when those characters are a house number, a postcode or a first name
        that is a disclosure -- one that whole-string substring checks cannot
        see, because the labelled string as a whole did disappear.
        """
        return [m for m in self.partial if m.substantive_remainder(source)]

    @property
    def tp(self) -> int:
        """Gold spans that were covered -- the recall numerator."""
        return len({(m.gold.start, m.gold.end) for m in self.matches})

    @property
    def tp_pred(self) -> int:
        """Predictions that were justified -- the precision numerator."""
        return len({(m.pred.start, m.pred.end) for m in self.matches})

    @property
    def fp(self) -> int:
        return len(self.false_positives)

    @property
    def fn(self) -> int:
        return len(self.false_negatives)


@dataclass(frozen=True, slots=True)
class Counts:
    """Precision and recall counted over different populations.

    One prediction can legitimately satisfy several gold spans: redacting
    "12 Rue Victor Hugo, Paris, 75001" as one ADDRESS covers a separately
    labelled postcode, and redacting a whole connection string covers the
    password inside it. Forcing a one-to-one alignment would charge a miss for
    every gold span after the first, which is the opposite of the truth --
    the wider redaction is the safer one.

    So recall is counted over gold spans (how many were covered) and precision
    over predictions (how many were justified). ``tp_pred`` defaults to ``tp``
    because the two coincide whenever the alignment happens to be one-to-one.
    """

    tp: int = 0
    fp: int = 0
    fn: int = 0
    unverified: int = 0
    tp_pred: int | None = None

    @property
    def justified(self) -> int:
        return self.tp if self.tp_pred is None else self.tp_pred

    @property
    def precision(self) -> float:
        return _ratio(self.justified, self.justified + self.fp)

    @property
    def recall(self) -> float:
        return _ratio(self.tp, self.tp + self.fn)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 0.0 if p + r == 0 else 2 * p * r / (p + r)

    @property
    def defined(self) -> bool:
        """Whether anything was actually measured.

        A zero-PII control has no gold spans and produces no predictions, so
        precision and recall are both vacuously 1.0. Averaging that in is how
        the previous baseline came to sit at a ceiling of 1.0 across the board
        while measuring nothing on two of its documents. Callers exclude
        undefined rows from macro averages and print them as n/a; those
        documents are gated on byte-identical output instead.
        """
        return (self.tp + self.fp + self.fn + self.justified) > 0


@dataclass
class ClusterScore:
    """Whether entities were merged correctly, measured pairwise.

    The check this replaces intersected ``same_entity`` groups against the
    vault's *values*, which hold only one canonical surface per placeholder. A
    group whose members never appear as a canonical value matched zero
    placeholders and passed as "no split" while saying nothing at all.
    """

    pairwise_precision: float = 1.0
    pairwise_recall: float = 1.0
    wrong_merges: list[str] = field(default_factory=list)
    missed_merges: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.wrong_merges and not self.missed_merges


def _ratio(numerator: int, denominator: int) -> float:
    return 1.0 if denominator == 0 else numerator / denominator


def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    counts = Counts(tp=tp, fp=fp, fn=fn)
    return counts.precision, counts.recall, counts.f1


def labels_compatible(
    gold_label: str,
    pred_label: str,
    equivalence: dict[str, frozenset[str]] = LABEL_EQUIVALENCE,
) -> bool:
    if gold_label == WILDCARD_LABEL or pred_label == WILDCARD_LABEL:
        return True
    if gold_label == pred_label:
        return True
    return pred_label in equivalence.get(gold_label, frozenset())


def predictions_from_result(result, *, drop_escapes: bool = True) -> list[PredSpan]:
    """The spans the pipeline replaced, in source coordinates.

    ``AnonymizationResult.spans`` is the resolved list that was zipped into the
    replacements, so it is exactly what was redacted. Offsets index the source;
    they cannot be located in ``sanitized`` because substitution rewrites it.

    Escape spans are dropped by default. They neutralize placeholder-shaped
    literals in the *input* and are not redactions of anything, so counting
    them would make every injection-control document report phantom
    over-redactions.
    """
    out: list[PredSpan] = []
    for span in getattr(result, "spans", []):
        if drop_escapes and span.label == ESCAPE_LABEL:
            continue
        out.append(
            PredSpan(
                start=span.start,
                end=span.end,
                label=span.label,
                text=span.text,
                source=getattr(span, "source", "model"),
                identity=getattr(span, "identity", None),
            )
        )
    return out


def align(
    gold: Sequence[GoldSpan],
    pred: Sequence[PredSpan],
    *,
    gold_complete: bool,
    equivalence: dict[str, frozenset[str]] = LABEL_EQUIVALENCE,
) -> Alignment:
    """Greedy one-to-one matching on overlap, gated by label compatibility.

    Overlap rather than exact offsets, because the pipeline deliberately
    redacts more than the label says: gold derived from "Aris Thorne" is met by
    a prediction covering "Dr. Aris Thorne", since honorifics are stripped
    before a label is written but not before text is replaced. Scoring that as
    a miss *and* a false alarm would charge two penalties for a redaction that
    is strictly safer than the label, and honorifics, clitics and legal
    suffixes are common enough that the effect would dominate the corpus.

    Boundary quality does not go unmeasured -- ``boundary_exact_rate`` and
    ``Alignment.partial`` report it, kept out of P/R so that a drifting edge
    and a missed entity stay distinguishable.
    """
    candidates: list[tuple[int, int, int]] = []  # (overlap, gold idx, pred idx)
    for gi, g in enumerate(gold):
        for pi, p in enumerate(pred):
            overlap = min(g.end, p.end) - max(g.start, p.start)
            if overlap <= 0:
                continue
            if not labels_compatible(g.label, p.label, equivalence):
                continue
            candidates.append((overlap, gi, pi))

    # Longest overlap first; ties settled by position so the result does not
    # depend on iteration order.
    candidates.sort(key=lambda c: (-c[0], c[1], c[2]))

    used_gold: set[int] = set()
    used_pred: set[int] = set()
    matches: list[Match] = []
    for overlap, gi, pi in candidates:
        if gi in used_gold:
            continue
        contains = pred[pi].start <= gold[gi].start and pred[pi].end >= gold[gi].end
        # A prediction already spoken for may still satisfy another gold span,
        # but only by covering it outright. Allowing a *partial* overlap to be
        # reused would let one narrow redaction claim credit for several
        # identifiers it only clipped.
        if pi in used_pred and not contains:
            continue
        used_gold.add(gi)
        used_pred.add(pi)
        matches.append(Match(gold=gold[gi], pred=pred[pi], overlap=overlap))

    matches.sort(key=lambda m: m.gold.start)
    unmatched_pred = [p for i, p in enumerate(pred) if i not in used_pred]
    alignment = Alignment(
        matches=matches,
        false_negatives=[g for i, g in enumerate(gold) if i not in used_gold],
        gold_complete=gold_complete,
    )
    # An unmatched prediction is only a false positive against exhaustive gold.
    # Charging one against a partially-labelled document would invent a
    # precision number out of the labeller's stamina.
    if gold_complete:
        alignment.false_positives = unmatched_pred
    else:
        alignment.unverified = unmatched_pred
    return alignment


def counts_by_label(alignment: Alignment) -> dict[str, Counts]:
    tp: dict[str, int] = defaultdict(int)
    fp: dict[str, int] = defaultdict(int)
    fn: dict[str, int] = defaultdict(int)
    unver: dict[str, int] = defaultdict(int)

    for match in alignment.matches:
        # Credit the gold label, except where gold was the wildcard and the
        # prediction is the only opinion available.
        label = match.pred.label if match.gold.label == WILDCARD_LABEL else match.gold.label
        tp[label] += 1
    for span in alignment.false_positives:
        fp[span.label] += 1
    for span in alignment.false_negatives:
        fn[span.label] += 1
    for span in alignment.unverified:
        unver[span.label] += 1

    justified: dict[str, int] = defaultdict(int)
    seen: set[tuple[int, int, str]] = set()
    for match in alignment.matches:
        key = (match.pred.start, match.pred.end, match.pred.label)
        if key in seen:
            continue
        seen.add(key)
        label = match.pred.label if match.gold.label == WILDCARD_LABEL else match.gold.label
        justified[label] += 1

    labels = set(tp) | set(fp) | set(fn) | set(unver) | set(justified)
    return {
        label: Counts(
            tp=tp[label],
            fp=fp[label],
            fn=fn[label],
            unverified=unver[label],
            tp_pred=justified[label],
        )
        for label in sorted(labels)
    }


def merge_counts(per_label: Iterable[dict[str, Counts]]) -> dict[str, Counts]:
    """Sum per-label counts across documents, for the corpus table."""
    totals: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0, 0, 0])
    for mapping in per_label:
        for label, counts in mapping.items():
            row = totals[label]
            row[0] += counts.tp
            row[1] += counts.fp
            row[2] += counts.fn
            row[3] += counts.unverified
            row[4] += counts.justified
    return {
        label: Counts(tp=row[0], fp=row[1], fn=row[2], unverified=row[3], tp_pred=row[4])
        for label, row in sorted(totals.items())
    }


def boundary_exact_rate(matches: Sequence[Match]) -> float:
    if not matches:
        return 1.0
    return sum(1 for m in matches if m.exact) / len(matches)


def cluster_metrics(matches: Sequence[Match]) -> ClusterScore:
    """Pairwise agreement between gold entity clusters and minted identities.

    Two gold spans in the same cluster should share a predicted identity; two
    in different clusters should not. Pairwise counting makes both failures
    visible and names examples of each, which the old boolean could not.
    """
    usable = [m for m in matches if m.gold.entity]
    if len(usable) < 2:
        return ClusterScore()

    def pred_key(match: Match) -> str:
        # Fall back to the normalized surface when no identity was minted, so
        # two unlinked mentions of one name still count as agreeing.
        return match.pred.identity or f"~{_normalize(match.pred.text)}"

    same_gold_same_pred = same_gold_diff_pred = 0
    diff_gold_same_pred = 0
    wrong: list[str] = []
    missed: list[str] = []

    for i in range(len(usable)):
        for j in range(i + 1, len(usable)):
            a, b = usable[i], usable[j]
            gold_same = a.gold.entity == b.gold.entity
            pred_same = pred_key(a) == pred_key(b)
            if gold_same and pred_same:
                same_gold_same_pred += 1
            elif gold_same and not pred_same:
                same_gold_diff_pred += 1
                missed.append(f"{a.gold.text!r} / {b.gold.text!r} (entity {a.gold.entity})")
            elif not gold_same and pred_same:
                diff_gold_same_pred += 1
                wrong.append(
                    f"{a.gold.text!r} ({a.gold.entity}) + {b.gold.text!r} ({b.gold.entity})"
                    f" -> one identity"
                )

    return ClusterScore(
        pairwise_precision=_ratio(same_gold_same_pred, same_gold_same_pred + diff_gold_same_pred),
        pairwise_recall=_ratio(same_gold_same_pred, same_gold_same_pred + same_gold_diff_pred),
        wrong_merges=sorted(set(wrong)),
        missed_merges=sorted(set(missed)),
    )


# --- Integrity and structure -------------------------------------------------

def integrity_issues(source: str, sanitized: str) -> list[str]:
    """Damage a redactor must not do to the text around the entities.

    Balance, not absolute count: the parentheses in "+1 (555) 019-2834" are
    part of the phone number and correctly vanish with it. What must never
    happen is an unbalanced result.
    """
    issues: list[str] = []
    for opener, closer in (("(", ")"), ("[", "]"), ("{{", "}}")):
        if sanitized.count(opener) != sanitized.count(closer):
            issues.append(f"unbalanced {opener}{closer}")
    if sanitized.count('"') % 2 != source.count('"') % 2:
        issues.append("quote parity changed")
    if len(source.splitlines()) != len(sanitized.splitlines()):
        issues.append("line count changed")
    if re.search(r"\}\}\w", sanitized) or re.search(r"\w\{\{", sanitized):
        issues.append("placeholder glued mid-word")
    for match in re.finditer(r"\{\{([A-Z][A-Z0-9_]*_\d+)\}\}\s*\{\{\1\}\}", sanitized):
        issues.append(f"placeholder emitted twice: {match.group(1)}")
    return issues


def extract_json_blocks(text: str) -> list[str]:
    """Pull balanced ``{...}`` blocks out of prose, ignoring placeholders.

    ``{{PERSON_1}}`` is a placeholder, not an object, so its braces must not
    open or close a block. Lifted from the production harness, where this
    logic was the one piece worth keeping verbatim.
    """
    blocks: list[str] = []
    i = 0
    while i < len(text):
        if text.startswith("{{", i):
            i += 2
            continue
        if text[i] == "{":
            depth = 0
            start = i
            j = i
            while j < len(text):
                if text.startswith("{{", j):
                    j += 2
                    continue
                if text.startswith("}}", j):
                    j += 2
                    continue
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                    if depth == 0:
                        blocks.append(text[start : j + 1])
                        i = j + 1
                        break
                j += 1
            else:
                break
            continue
        i += 1
    return blocks


def json_blocks_are_valid(sanitized: str) -> tuple[bool | None, list[str]]:
    """Whether every JSON block survived redaction as parseable JSON.

    Returns ``(None, [])`` when the document contains no JSON at all, so that
    "no JSON here" and "the JSON is fine" stay distinguishable.
    """
    blocks = extract_json_blocks(sanitized)
    if not blocks:
        return None, []
    broken: list[str] = []
    for block in blocks:
        # Placeholders are bare tokens where a quoted string used to be; quote
        # them back before parsing, or every redacted payload reads as broken.
        probe = re.sub(r"\{\{[A-Z][A-Z0-9_]*_\d+\}\}", '"redacted"', block)
        try:
            json.loads(probe)
        except (json.JSONDecodeError, ValueError) as exc:
            broken.append(f"{exc}: {block[:60]}...")
    return not broken, broken


def check_assertions(result, gold: Sequence[GoldSpan], assertions: dict) -> list[str]:
    """Generated-corpus expectations that P/R cannot express.

    A wrong merge and a missed merge are both invisible to span metrics -- the
    spans are right either way; what differs is which placeholder they got.
    """
    violations: list[str] = []
    by_entity: dict[str, set[str]] = defaultdict(set)
    preds = predictions_from_result(result)
    alignment = align(gold, preds, gold_complete=True)
    for match in alignment.matches:
        if match.gold.entity:
            key = match.pred.identity or f"~{_normalize(match.pred.text)}"
            by_entity[match.gold.entity].add(key)

    if assertions.get("byte_identical"):
        source = assertions.get("_source", "")
        if source and result.sanitized != source:
            violations.append("document was modified but should be byte-identical")

    for group in assertions.get("expect_distinct_entities", []):
        keys = [k for e in group for k in by_entity.get(e, set())]
        if len(keys) != len(set(keys)):
            violations.append(f"entities {group} collapsed onto one placeholder")

    for group in assertions.get("expect_same_entity", []):
        keys = {k for e in group for k in by_entity.get(e, set())}
        if len(keys) > 1:
            violations.append(f"entities {group} split across {sorted(keys)}")

    for literal in assertions.get("expect_escaped_literals", []):
        if literal not in result.escapes.values():
            violations.append(f"placeholder literal {literal!r} was not escaped")

    return violations
