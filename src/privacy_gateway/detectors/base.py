"""Detector protocol and the priority ladder.

This module imports nothing heavy on purpose. ``detectors/__init__.py`` is
empty and detectors are built through a string-keyed registry, so a unit test
can construct the pipeline without dragging spaCy, torch or transformers into
the process. A test asserts that property rather than relying on convention.

Construction is also separated from model loading: ``__init__`` stores
configuration, ``warmup()`` loads weights. So even building a detector is cheap.
"""

from __future__ import annotations

import importlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ..entities.entity import DetectedEntity

#: Detector priority. Higher wins an overlap.
#:
#: The ordering is a claim about *evidence quality*, not about model size:
#: a speaker label is a fact about the document's structure, a checksum-validated
#: pattern is arithmetic, a curated lexicon is human knowledge, and everything
#: below that is inference. The semantic layer sits last precisely because it is
#: the most capable -- capability is not reliability, and an LLM's spans are the
#: least trustworthy thing in the pipeline.
DEFAULT_PRIORITIES: Mapping[str, int] = {
    "registry": 100,
    "regex": 90,
    "domain": 80,
    "presidio": 60,
    "ner": 40,
    "qwen": 30,
}

#: Detectors whose offsets are approximate and should be widened to a word
#: boundary rather than dropped.
EXPANDING_DETECTORS = frozenset({"ner", "qwen"})


@dataclass(frozen=True, slots=True)
class DetectionContext:
    """Everything a detector may need beyond the text itself."""

    conversation_id: str = ""
    chunk_index: int = 0
    chunk_offset: int = 0
    transcript_format: str = "unstructured"
    metadata: Mapping[str, Any] = field(default_factory=dict)


@runtime_checkable
class Detector(Protocol):
    """A source of candidate entities."""

    name: str
    layer: int

    def warmup(self) -> None:
        """Load any models. Safe to call repeatedly."""

    def detect(self, text: str, ctx: DetectionContext) -> Sequence[DetectedEntity]:
        """Return candidates with offsets relative to ``text``."""


@dataclass(frozen=True, slots=True)
class DetectorOutcome:
    """The result of running one detector, including failure."""

    name: str
    entities: tuple[DetectedEntity, ...] = ()
    error: BaseException | None = None
    seconds: float = 0.0
    skipped: bool = False

    @property
    def failed(self) -> bool:
        return self.error is not None


#: module path -> factory function. The import happens inside
#: :func:`build_detector`, never at package import time.
_FACTORIES: Mapping[str, str] = {
    "regex": "privacy_gateway.detectors.regex_detector:build",
    "registry": "privacy_gateway.detectors.registry_detector:build",
    "domain": "privacy_gateway.detectors.domain_detector:build",
    "presidio": "privacy_gateway.detectors.presidio_detector:build",
    "ner": "privacy_gateway.detectors.ner_detector:build",
    "qwen": "privacy_gateway.detectors.qwen_detector:build",
}


def available_detectors() -> tuple[str, ...]:
    return tuple(_FACTORIES)


def build_detector(name: str, config: Any = None, **kwargs: Any) -> Detector:
    """Instantiate a detector by name, importing its module only now."""
    try:
        target = _FACTORIES[name]
    except KeyError:
        raise ValueError(
            f"unknown detector {name!r}; known: {', '.join(sorted(_FACTORIES))}"
        ) from None
    module_path, _, factory = target.partition(":")
    module = importlib.import_module(module_path)
    return getattr(module, factory)(config, **kwargs)
