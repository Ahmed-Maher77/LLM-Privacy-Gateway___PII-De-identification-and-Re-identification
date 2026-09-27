"""Occurrence sweep: protect every instance of a value, not just detected ones.

Detection is positional. A statistical detector may label "Exampleco" in one
sentence and miss it two lines later, and a transcript repeats names constantly.
Without this sweep the mapping would contain a value while the document still
showed it in plain text -- which the pre-send gate correctly treats as a leak.

The sweep is deliberately conservative:

* only values already chosen for a *transforming* action are swept, so this
  cannot introduce a new kind of entity;
* matching is exact and word-bounded, never fuzzy, so it cannot spread to a
  different word;
* very short values are skipped, because a two-character value would match
  everywhere and reintroduce the over-replacement the gateway exists to fix;
* the recovered spans are fed back through the ordinary aggregation rules
  rather than being applied directly, so they cannot create an overlap.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from ..entities.entity import DetectedEntity, make_entity
from ..policy.engine import PolicyDecision

#: Below this length an exact match is far more likely to be a coincidence
#: than a missed mention.
MIN_SWEEP_CHARS = 4

#: Priority just below the injection guard: a recovered occurrence is as
#: trustworthy as the detection it was derived from, but must never outrank a
#: real detector that saw something more specific at the same offset.
SWEEP_PRIORITY = 95


def expand_occurrences(
    text: str, decisions: Sequence[PolicyDecision]
) -> tuple[DetectedEntity, ...]:
    """Find occurrences of protected values that no detector reported."""
    protected: dict[str, tuple[str, float]] = {}
    case_sensitive: dict[str, bool] = {}
    covered: list[tuple[int, int]] = []

    for decision in decisions:
        entity = decision.entity
        covered.append((entity.start, entity.end))
        if not decision.transforms:
            continue
        value = entity.text.strip()
        if len(value) < MIN_SWEEP_CHARS:
            continue
        current = protected.get(value)
        if current is None or entity.confidence > current[1]:
            protected[value] = (entity.entity_type, entity.confidence)
        case_sensitive[value] = decision.rule.case_sensitive

    if not protected:
        return ()

    out: list[DetectedEntity] = []
    for value, (entity_type, confidence) in protected.items():
        # Case-insensitivity must match the policy rule, otherwise a
        # lower-cased re-occurrence would be left in the text while the
        # scanner -- which searches case-insensitively -- flags it as a leak.
        flags = 0 if case_sensitive.get(value, False) else re.IGNORECASE
        pattern = re.compile(r"(?<!\w)" + re.escape(value) + r"(?!\w)", flags)
        for m in pattern.finditer(text):
            if any(s <= m.start() and m.end() <= e for s, e in covered):
                continue  # already handled by a detection
            out.append(
                make_entity(
                    text_source=text,
                    start=m.start(),
                    end=m.end(),
                    entity_type=entity_type,
                    confidence=confidence,
                    detector="consistency",
                    source="occurrence_sweep",
                    priority=SWEEP_PRIORITY,
                    metadata={"recovered": True},
                )
            )
    return tuple(out)
