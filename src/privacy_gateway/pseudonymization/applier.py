"""Applying policy decisions to the text.

The single most important property of this module: **replacement is by offset,
applied right to left, and there is no ``str.replace`` anywhere in it.**

The prototype replaced by surface string:

    for placeholder, original in sorted(mapping.items(), key=len, reverse=True):
        anonymized = anonymized.replace(original, placeholder)

so a one-character entity replaced every occurrence of that character in the
document -- 138 corrupted sites, 24 words that do not exist in the source.
Splicing by offset makes that impossible by construction: an entity at
``[start, end)`` can only ever affect ``[start, end)``.

Right-to-left order means every not-yet-applied span keeps valid offsets,
because only text after it has changed. Left-to-right would need running-delta
bookkeeping, which is the classic source of off-by-N corruption.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ..errors import AggregationInvariantError
from ..policy.actions import Action
from ..policy.engine import PolicyDecision
from .mapping_store import MappingStore

REDACTED_TEMPLATE = "[REDACTED:{entity_type}]"
MASK_CHAR = "*"
MASK_TAIL = 4


@dataclass(frozen=True, slots=True)
class AppliedReplacement:
    start: int
    end: int
    replacement: str
    action: Action
    entity_type: str
    placeholder: str | None = None
    #: The exact text this replacement covered. Lives inside the trust
    #: boundary alongside the mapping and is never serialised into a report.
    #: It exists so that :func:`invert` can prove the transformation is
    #: lossless, independently of canonical-form restoration.
    original: str = ""

    def __repr__(self) -> str:
        return (
            f"AppliedReplacement({self.entity_type} {self.start}:{self.end} "
            f"-> {self.action} {self.placeholder or ''})"
        )


@dataclass(frozen=True, slots=True)
class SanitizationResult:
    text: str
    store: MappingStore
    applied: tuple[AppliedReplacement, ...] = ()


def _mask(value: str) -> str:
    """Keep the last few characters so a human can still reconcile a record."""
    digits = [c for c in value if c.isalnum()]
    if len(digits) <= MASK_TAIL:
        return MASK_CHAR * len(value)
    return MASK_CHAR * (len(digits) - MASK_TAIL) + "".join(digits[-MASK_TAIL:])


class Pseudonymizer:
    """Rewrites text according to policy decisions."""

    def __init__(self, store: MappingStore) -> None:
        self.store = store

    def apply(self, text: str, decisions: Sequence[PolicyDecision]) -> SanitizationResult:
        transforming = [d for d in decisions if d.transforms]
        ordered = sorted(transforming, key=lambda d: (d.entity.start, d.entity.end))
        self._assert_disjoint(ordered, text)

        # Assign in ascending order so placeholder numbering follows document
        # order: <PERSON_001> is the first person mentioned. Stable, reviewable,
        # and diff-friendly across runs.
        replacements = [self._render(decision) for decision in ordered]

        # Apply in descending order so untouched spans keep valid offsets.
        pieces: list[str] = []
        cursor = len(text)
        for replacement in reversed(replacements):
            pieces.append(text[replacement.end : cursor])
            pieces.append(replacement.replacement)
            cursor = replacement.start
        pieces.append(text[:cursor])
        return SanitizationResult(
            text="".join(reversed(pieces)), store=self.store, applied=tuple(replacements)
        )

    def _render(self, decision: PolicyDecision) -> AppliedReplacement:
        entity = decision.entity
        placeholder = None
        if decision.action is Action.PSEUDONYMIZE:
            placeholder = replacement = self.store.assign(entity, decision.rule)
        elif decision.action is Action.REDACT:
            replacement = REDACTED_TEMPLATE.format(entity_type=entity.entity_type)
        elif decision.action is Action.MASK:
            replacement = _mask(entity.text)
        else:
            raise AssertionError(f"non-transforming action reached the applier: {decision.action}")
        return AppliedReplacement(
            entity.start, entity.end, replacement, decision.action,
            entity.entity_type, placeholder, entity.text,
        )

    @staticmethod
    def _assert_disjoint(decisions: Sequence[PolicyDecision], text: str) -> None:
        """Independent re-check at the point where a violation would corrupt.

        Aggregation guarantees this already. It is asserted again here because
        this is the exact place where an overlapping span turns into mangled
        output, and a cheap assertion beats a silent corruption.
        """
        previous_end = -1
        for decision in decisions:
            entity = decision.entity
            if entity.start < previous_end:
                raise AggregationInvariantError(
                    f"overlapping spans reached the pseudonymizer at offset {entity.start}"
                )
            if entity.start < 0 or entity.end > len(text):
                raise AggregationInvariantError(
                    f"span out of range at the pseudonymizer: {entity.start}:{entity.end}"
                )
            if text[entity.start : entity.end] != entity.text:
                raise AggregationInvariantError(
                    f"entity text disagrees with its span at offset {entity.start}"
                )
            previous_end = entity.end


def invert(sanitized_text: str, applied: Sequence[AppliedReplacement]) -> str:
    """Rebuild the exact input from the sanitized text and the applied list.

    This is the lossless-ness proof. Canonical restoration (the path used on
    model output) emits one agreed spelling per entity, so a case-folded
    variant comes back in the canonical casing. Here every replacement carries
    the exact text it covered, so the reconstruction is byte-identical -- which
    demonstrates that pseudonymization itself discards nothing, and isolates
    canonical-form casing as a property of restoration rather than a loss in
    the transformation.
    """
    pieces: list[str] = []
    cursor = 0
    for replacement in sorted(applied, key=lambda r: r.start):
        # Offsets in `applied` are in ORIGINAL coordinates, so walk the
        # sanitized text with a running delta.
        delta = sum(
            len(r.replacement) - (r.end - r.start)
            for r in applied
            if r.start < replacement.start
        )
        start = replacement.start + delta
        end = start + len(replacement.replacement)
        pieces.append(sanitized_text[cursor:start])
        pieces.append(replacement.original)
        cursor = end
    pieces.append(sanitized_text[cursor:])
    return "".join(pieces)
