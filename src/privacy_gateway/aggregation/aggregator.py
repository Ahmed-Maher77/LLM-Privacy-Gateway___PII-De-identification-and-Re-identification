"""Entity aggregation: validate, repair, then resolve overlaps deterministically.

This stage is the gate. Everything upstream proposes; nothing downstream may
see an overlapping, misaligned or out-of-range span. Its post-conditions are
asserted and fatal in both fail modes, because an overlapping span is exactly
the state that produces corrupted output.

Two rules deserve explanation because the obvious alternative is worse:

* **An overlap loser is dropped entirely, never trimmed to its remainder.**
  Trimming a losing span down to the part that does not overlap is how you
  manufacture a one-character fragment from the other direction -- the same
  class of defect, arrived at by a different route.
* **A container never gets split around a nested entity.** Splitting produces
  two partial spans whose edges fall wherever the inner entity happened to
  land.
"""

from __future__ import annotations

import itertools
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from ..detectors.base import EXPANDING_DETECTORS
from ..entities.entity import DetectedEntity
from ..entities.spans import (
    DEFAULT_TRIM_CHARS,
    SpanVerdict,
    is_asr_noise,
    is_word_aligned,
    realign,
    validate_span,
)
from ..errors import AggregationInvariantError
from .common_words import COMMON_WORDS

#: Statistical detectors, whose single-token output on a noisy transcript is
#: frequently ASR filler rather than a name.
_STATISTICAL = frozenset({"ner", "qwen", "presidio"})


@dataclass(frozen=True, slots=True)
class RejectedEntity:
    entity: DetectedEntity
    verdict: str
    stage: str


@dataclass(frozen=True, slots=True)
class AggregationConfig:
    min_entity_chars: int = 2
    min_person_chars: int = 3
    short_entity_confidence: float = 0.90
    max_entity_chars: int = 96
    require_word_boundary: bool = True
    trim_chars: str = DEFAULT_TRIM_CHARS
    strip_possessives: bool = True
    drop_asr_noise: bool = True
    require_capitalised_proper_nouns: bool = True
    drop_common_words: bool = True
    min_confidence: float = 0.30
    corroboration_bonus: float = 0.02
    max_confidence: float = 0.99


@dataclass(frozen=True, slots=True)
class AggregationResult:
    entities: tuple[DetectedEntity, ...] = ()
    rejected: tuple[RejectedEntity, ...] = ()
    stats: Mapping[str, int] = field(default_factory=dict)

    @property
    def count(self) -> int:
        return len(self.entities)


_PERSON_LIKE = frozenset({"PERSON", "EMPLOYEE", "STAKEHOLDER", "CUSTOMER"})

#: Types whose members are proper nouns in English and are therefore
#: capitalised. Used only to filter statistical detectors.
_CAPITALISED_TYPES = frozenset(
    {"PERSON", "EMPLOYEE", "STAKEHOLDER", "CUSTOMER", "ORGANIZATION", "LOCATION",
     "INTERNAL_SYSTEM", "INTERNAL_SERVICE", "PROJECT"}
)


class EntityAggregator:
    """Combines candidates from every detector into one disjoint list."""

    def __init__(self, config: AggregationConfig | None = None) -> None:
        self.config = config or AggregationConfig()

    # -- stage A: per-entity validation and repair ------------------------
    def _clean(
        self, entities: Sequence[DetectedEntity], text: str
    ) -> tuple[list[DetectedEntity], list[RejectedEntity]]:
        cfg = self.config
        kept: list[DetectedEntity] = []
        rejected: list[RejectedEntity] = []

        for entity in entities:
            if entity.start < 0 or entity.end > len(text) or entity.end <= entity.start:
                rejected.append(RejectedEntity(entity, SpanVerdict.OUT_OF_RANGE, "clean"))
                continue
            if text[entity.start : entity.end] != entity.text:
                rejected.append(RejectedEntity(entity, SpanVerdict.TEXT_MISMATCH, "clean"))
                continue

            repaired = realign(
                entity,
                text,
                expand=entity.detector in EXPANDING_DETECTORS,
                trim_chars=cfg.trim_chars,
                strip_possessives=cfg.strip_possessives,
            )
            if repaired is None:
                rejected.append(RejectedEntity(entity, SpanVerdict.EMPTY_AFTER_TRIM, "clean"))
                continue

            surface = repaired.text.strip()

            if cfg.drop_asr_noise and repaired.detector in _STATISTICAL and is_asr_noise(surface):
                rejected.append(RejectedEntity(repaired, SpanVerdict.ASR_NOISE, "clean"))
                continue

            # English proper nouns are capitalised. A statistical detector
            # labelling an all-lowercase common noun ("operations", "finance")
            # as an ORGANIZATION is a false positive, and pseudonymizing it
            # both destroys the sentence and floods the mapping with words that
            # then appear to "leak" everywhere else in the document.
            # Deterministic and curated detectors are exempt, so a configured
            # lowercase term is still honoured.
            if (
                cfg.require_capitalised_proper_nouns
                and repaired.detector in _STATISTICAL
                and repaired.entity_type in _CAPITALISED_TYPES
                and surface[:1].islower()
            ):
                rejected.append(RejectedEntity(repaired, SpanVerdict.NOT_PROPER_NOUN, "clean"))
                continue

            # A single ordinary English word labelled as a proper noun by a
            # statistical detector is a false positive. Left in place, one such
            # word ("operations") matches case-insensitively across the whole
            # document and produces a leak finding at every occurrence.
            # Curated and deterministic detectors are exempt, so a real company
            # named after a common word is still protected via the lexicon.
            if (
                cfg.drop_common_words
                and repaired.detector in _STATISTICAL
                and repaired.entity_type in _CAPITALISED_TYPES
                and " " not in surface
                and surface.casefold() in COMMON_WORDS
            ):
                rejected.append(RejectedEntity(repaired, SpanVerdict.COMMON_WORD, "clean"))
                continue

            # A very short person-like span is nearly always a fragment or an
            # initial; require it to be near-certain before keeping it.
            if (
                repaired.entity_type in _PERSON_LIKE
                and len(surface) < cfg.min_person_chars
                and repaired.confidence < cfg.short_entity_confidence
            ):
                rejected.append(RejectedEntity(repaired, SpanVerdict.TOO_SHORT, "clean"))
                continue

            if repaired.confidence < cfg.min_confidence:
                rejected.append(RejectedEntity(repaired, SpanVerdict.LOW_CONFIDENCE, "clean"))
                continue

            verdict = validate_span(
                repaired,
                text,
                min_chars=cfg.min_entity_chars,
                max_chars=cfg.max_entity_chars,
                require_word_boundary=cfg.require_word_boundary,
            )
            if verdict is not SpanVerdict.VALID:
                rejected.append(RejectedEntity(repaired, verdict, "clean"))
                continue

            kept.append(repaired)

        return kept, rejected

    # -- stage B: merge exact duplicates ----------------------------------
    def _merge_duplicates(self, entities: Sequence[DetectedEntity]) -> list[DetectedEntity]:
        cfg = self.config
        groups: dict[tuple[str, int, int], list[DetectedEntity]] = {}
        for e in entities:
            groups.setdefault((e.entity_type, e.start, e.end), []).append(e)

        out: list[DetectedEntity] = []
        for group in groups.values():
            if len(group) == 1:
                out.append(group[0])
                continue
            winner = max(group, key=lambda e: (e.priority, e.confidence, e.detector))
            others = tuple(sorted({e.detector for e in group if e is not winner}))
            boosted = min(
                cfg.max_confidence,
                max(e.confidence for e in group) + cfg.corroboration_bonus * (len(group) - 1),
            )
            out.append(
                winner.with_confidence(boosted).with_metadata(
                    also_detected_by=others, detector_count=len(group)
                )
            )
        return out

    # -- stage C: deterministic overlap resolution -------------------------
    @staticmethod
    def _sort_key(e: DetectedEntity) -> tuple:
        # A total order: no two distinct candidates can tie, so the result does
        # not depend on the order detectors happened to run in. Confidence is
        # rounded before use so float noise cannot reorder across platforms.
        return (
            e.start,
            -(e.end - e.start),
            -e.priority,
            -round(e.confidence, 6),
            e.detector,
            e.entity_type,
            e.source,
        )

    @staticmethod
    def _prefer(a: DetectedEntity, b: DetectedEntity) -> DetectedEntity:
        """Pick the survivor of two overlapping candidates."""
        a_start, a_end = a.span
        b_start, b_end = b.span

        a_contains_b = a_start <= b_start and b_end <= a_end
        b_contains_a = b_start <= a_start and a_end <= b_end

        if a_contains_b and b_contains_a:  # identical span
            return max((a, b), key=lambda e: (e.priority, round(e.confidence, 6), e.entity_type))

        if a_contains_b or b_contains_a:
            outer, inner = (a, b) if a_contains_b else (b, a)
            # A high-precision detection nested inside a sloppy one wins: an
            # EMAIL inside an NER ORGANIZATION must not be swallowed.
            return inner if inner.priority > outer.priority else outer

        # Partial (crossing) overlap.
        return max(
            (a, b),
            key=lambda e: (
                e.priority,
                round(e.confidence, 6),
                e.end - e.start,
                -e.start,
                e.detector,
            ),
        )

    def _resolve(
        self, entities: Sequence[DetectedEntity]
    ) -> tuple[list[DetectedEntity], list[RejectedEntity]]:
        selected: list[DetectedEntity] = []
        dropped: list[RejectedEntity] = []

        for candidate in sorted(entities, key=self._sort_key):
            clash = None
            for i, chosen in enumerate(selected):
                if candidate.start < chosen.end and chosen.start < candidate.end:
                    clash = i
                    break
            if clash is None:
                selected.append(candidate)
                continue

            incumbent = selected[clash]
            winner = self._prefer(incumbent, candidate)
            loser = candidate if winner is incumbent else incumbent
            if winner is not incumbent:
                selected[clash] = winner
            dropped.append(RejectedEntity(loser, "overlap", "resolve"))

        selected.sort(key=lambda e: e.start)
        return selected, dropped

    # -- entry point --------------------------------------------------------
    def aggregate(
        self, entities: Sequence[DetectedEntity], text: str
    ) -> AggregationResult:
        candidates = list(entities)
        cleaned, rejected = self._clean(candidates, text)
        merged = self._merge_duplicates(cleaned)
        resolved, dropped = self._resolve(merged)
        rejected.extend(dropped)

        self._assert_invariants(resolved, text)

        stats = {
            "candidates_in": len(candidates),
            "after_clean": len(cleaned),
            "after_merge": len(merged),
            "final": len(resolved),
            "rejected": len(rejected),
        }
        for r in rejected:
            stats[f"rejected_{r.verdict}"] = stats.get(f"rejected_{r.verdict}", 0) + 1

        return AggregationResult(
            entities=tuple(resolved), rejected=tuple(rejected), stats=stats
        )

    # -- post-conditions ----------------------------------------------------
    def _assert_invariants(self, entities: Sequence[DetectedEntity], text: str) -> None:
        """Fatal in both fail modes. Violating any of these produces corruption."""
        for previous, current in itertools.pairwise(entities):
            if previous.end > current.start:
                raise AggregationInvariantError(
                    f"overlapping spans survived aggregation at offset {current.start}"
                )
            if previous.start > current.start:
                raise AggregationInvariantError("aggregation output is not sorted by start")

        for e in entities:
            if e.start < 0 or e.end > len(text):
                raise AggregationInvariantError(f"span out of range at offset {e.start}")
            if text[e.start : e.end] != e.text:
                raise AggregationInvariantError(
                    f"entity text disagrees with its span at offset {e.start}"
                )
            if self.config.require_word_boundary and not is_word_aligned(text, e.start, e.end):
                raise AggregationInvariantError(
                    f"span is not word-aligned at offset {e.start}"
                )
