"""Detector configuration sweep.

Each detector runs **once per document**; configurations are then evaluated as
set-unions over that cache. So configurations E, F and G -- the combinations --
cost essentially nothing beyond the four base runs, and comparing eight
configurations does not mean eight full pipeline executions.

A configuration whose detectors are unavailable is recorded as ``skipped`` with
a reason. It is never silently omitted and never zero-filled: a missing
measurement and a measurement of zero are different claims.
"""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..aggregation.aggregator import EntityAggregator
from ..config import Settings
from ..detectors.base import DetectionContext, build_detector
from ..entities.entity import DetectedEntity
from ..preprocessing.registry import ParticipantRegistry
from ..preprocessing.transcript import TranscriptParser
from .gold import GoldDocument, GoldSet
from .metrics import Evaluation, evaluate


@dataclass(frozen=True, slots=True)
class SweepConfig:
    key: str
    label: str
    detectors: frozenset[str]


#: The configurations the brief asks for.
SWEEP: dict[str, SweepConfig] = {
    "A": SweepConfig("A", "Presidio only", frozenset({"presidio"})),
    "B": SweepConfig("B", "Generic NER only", frozenset({"ner"})),
    "C": SweepConfig("C", "Qwen only", frozenset({"qwen"})),
    "D": SweepConfig("D", "Domain rules only", frozenset({"regex", "domain", "registry"})),
    "E": SweepConfig("E", "Presidio + rules", frozenset({"presidio", "regex", "domain", "registry"})),
    "F": SweepConfig(
        "F", "Presidio + rules + Qwen",
        frozenset({"presidio", "regex", "domain", "registry", "qwen"}),
    ),
    "G": SweepConfig(
        "G", "All four layers",
        frozenset({"presidio", "regex", "domain", "registry", "ner", "qwen"}),
    ),
    # Beyond the seven the brief asks for. With Qwen disabled by default, C, F
    # and G cannot be measured, which would leave no row for the configuration
    # that actually ships. This is it.
    "H": SweepConfig(
        "H", "Presidio + rules + NER (no Qwen)",
        frozenset({"presidio", "regex", "domain", "registry", "ner"}),
    ),
}


@dataclass(frozen=True, slots=True)
class ConfigResult:
    key: str
    label: str
    status: str
    detectors: tuple[str, ...]
    reason: str = ""
    evaluation: Evaluation | None = None
    seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "key": self.key,
            "label": self.label,
            "status": self.status,
            "detectors": list(self.detectors),
        }
        if self.status != "ok":
            out["reason"] = self.reason
            out["metrics"] = None  # explicitly absent, not zero
            return out
        out["seconds"] = round(self.seconds or 0.0, 4)
        out["metrics"] = self.evaluation.to_dict() if self.evaluation else None
        return out


@dataclass
class DetectionCache:
    """Per-detector output, keyed by ``(detector, doc_id)``."""

    entries: dict[tuple[str, str], tuple[DetectedEntity, ...]] = field(default_factory=dict)
    seconds: dict[str, float] = field(default_factory=dict)
    failures: dict[str, str] = field(default_factory=dict)

    def get(self, detector: str, doc_id: str) -> tuple[DetectedEntity, ...]:
        return self.entries.get((detector, doc_id), ())


def _registry_for(doc: GoldDocument) -> ParticipantRegistry:
    return ParticipantRegistry.from_transcript(TranscriptParser().parse(doc.text))


def populate_cache(
    gold: GoldSet, detector_names: Sequence[str], settings: Settings
) -> DetectionCache:
    """Run each requested detector once per document."""
    cache = DetectionCache()
    for name in sorted(set(detector_names)):
        kwargs: dict[str, Any] = {}
        if name == "qwen":
            kwargs["settings"] = settings.qwen
            if not settings.qwen.enabled:
                cache.failures[name] = "qwen detector is disabled (GATEWAY_QWEN_ENABLED=false)"
                continue
        try:
            detector = build_detector(name, settings.detectors, **kwargs)
            detector.warmup()
        except Exception as exc:
            cache.failures[name] = f"{type(exc).__name__}: unavailable"
            continue

        elapsed = 0.0
        for doc in gold:
            if name == "registry":
                detector.registry = _registry_for(doc)  # type: ignore[attr-defined]
            ctx = DetectionContext(conversation_id=doc.doc_id)
            started = time.perf_counter()
            try:
                found = tuple(detector.detect(doc.text, ctx))
            except Exception as exc:
                cache.failures[name] = f"{type(exc).__name__}: failed during detection"
                found = ()
            elapsed += time.perf_counter() - started
            cache.entries[(name, doc.doc_id)] = found
        cache.seconds[name] = elapsed
    return cache


def run_sweep(
    gold: GoldSet,
    configs: Sequence[SweepConfig],
    settings: Settings,
    cache: DetectionCache | None = None,
) -> tuple[list[ConfigResult], DetectionCache]:
    needed = {name for config in configs for name in config.detectors}
    cache = cache or populate_cache(gold, sorted(needed), settings)
    aggregator = EntityAggregator()

    results: list[ConfigResult] = []
    for config in configs:
        missing = sorted(name for name in config.detectors if name in cache.failures)
        if missing:
            results.append(
                ConfigResult(
                    key=config.key,
                    label=config.label,
                    status="skipped",
                    detectors=tuple(sorted(config.detectors)),
                    reason="; ".join(f"{n}: {cache.failures[n]}" for n in missing),
                )
            )
            continue

        predictions: dict[str, Sequence[DetectedEntity]] = {}
        for doc in gold:
            candidates: list[DetectedEntity] = []
            for name in sorted(config.detectors):
                candidates.extend(cache.get(name, doc.doc_id))
            predictions[doc.doc_id] = aggregator.aggregate(candidates, doc.text).entities

        results.append(
            ConfigResult(
                key=config.key,
                label=config.label,
                status="ok",
                detectors=tuple(sorted(config.detectors)),
                evaluation=evaluate(gold, predictions),
                seconds=sum(cache.seconds.get(n, 0.0) for n in config.detectors),
            )
        )
    return results, cache


def select(keys: str | Sequence[str] | None) -> list[SweepConfig]:
    if not keys:
        return list(SWEEP.values())
    if isinstance(keys, str):
        keys = [k.strip().upper() for k in keys.split(",") if k.strip()]
    return [SWEEP[k] for k in keys if k in SWEEP]


def dataset_summary(gold: GoldSet) -> Mapping[str, Any]:
    from .gold import circularity_warning

    return {
        "documents": len(gold),
        "entities_scored": gold.scored_span_count,
        "entities_excluded_ambiguous": gold.excluded_span_count,
        "per_type_counts": gold.per_type_counts(),
        "independent_fraction": round(gold.independent_fraction(), 4),
        "labelers": sorted({d.labeler for d in gold if d.labeler}),
        "inter_annotator_agreement": None,
        "labeling_note": (
            "Labels were produced by an AI assistant reading each excerpt, NOT by "
            "a human annotator, and have not been human-verified. No "
            "inter-annotator agreement was measured, so none is reported. Treat "
            "these figures as indicative of relative detector behaviour, not as a "
            "validated benchmark."
        ),
        "circularity_warning": circularity_warning(gold),
    }
