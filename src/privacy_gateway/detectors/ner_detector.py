"""Layer 4: generic transformer NER. Optional, and deliberately low priority.

This is where the prototype's corruption originated, so three things are done
differently here:

1. **Offsets come from the model, text comes from the document.** The pipeline's
   ``word`` field is passed only as ``reported_text``; ``start``/``end`` drive
   the entity. The prototype used ``word`` as a ``str.replace`` key, so the
   sub-word fragment ``"N"`` of "Rania" was replaced at every ``N`` in the
   document.
2. **Aggregation strategy is ``max``, not ``simple``.** ``simple`` is precisely
   the strategy that emits sub-word pieces for this model.
3. **The input is chunked.** ``dslim/bert-base-NER`` truncates at 512 tokens;
   a 14 KB transcript is roughly 4000, so today the back half of both sample
   transcripts is invisible to this layer. That is a correctness bug at any
   input size, not a scaling concern.

Generic NER is a *signal*, not the privacy authority: its label set (PER/ORG/
LOC/MISC) has no concept of an internal system, a customer identifier or a
contract number. The architecture works with this detector disabled.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ..entities.entity import DetectedEntity, make_entity
from ..entities.spans import expand_to_word_boundary
from ..entities.taxonomy import canonical_type
from ..errors import DetectorUnavailableError
from .base import DEFAULT_PRIORITIES, DetectionContext

DEFAULT_MODEL = "dslim/bert-base-NER"

#: Characters per chunk. Chosen to stay well inside the model's 512-token
#: window with room for sub-word expansion on noisy transliterated names.
DEFAULT_CHUNK_CHARS = 1200
DEFAULT_OVERLAP_CHARS = 120


def split_for_model(
    text: str, chunk_chars: int = DEFAULT_CHUNK_CHARS, overlap: int = DEFAULT_OVERLAP_CHARS
) -> list[tuple[int, str]]:
    """Split into overlapping windows that never cut a word in half.

    Returns ``(absolute_offset, chunk_text)`` pairs. The overlap lets an entity
    that straddles a boundary appear complete in the next window; the ordinary
    overlap-resolution step then prefers the complete span, so no special
    boundary handling is needed downstream.
    """
    if len(text) <= chunk_chars:
        return [(0, text)] if text else []
    out: list[tuple[int, str]] = []
    start = 0
    while start < len(text):
        end = min(start + chunk_chars, len(text))
        if end < len(text):
            # Back off to a newline, then a space, so a window never ends
            # mid-token and manufactures a fragment.
            cut = text.rfind("\n", start + chunk_chars // 2, end)
            if cut == -1:
                cut = text.rfind(" ", start + chunk_chars // 2, end)
            if cut > start:
                end = cut
        out.append((start, text[start:end]))
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
    return out


class NERDetector:
    """Hugging Face token-classification pipeline, normalised and chunked."""

    name = "ner"
    layer = 4

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        device: str = "cpu",
        score_threshold: float = 0.60,
        min_chars: int = 2,
        drop_types: Sequence[str] = ("MISC",),
        chunk_chars: int = DEFAULT_CHUNK_CHARS,
    ) -> None:
        self.model = model
        self.device = device
        self.score_threshold = score_threshold
        self.min_chars = min_chars
        self.drop_types = frozenset(drop_types)
        self.chunk_chars = chunk_chars
        self._priority = DEFAULT_PRIORITIES["ner"]
        self._pipeline: Any = None

    def warmup(self) -> None:
        if self._pipeline is not None:
            return
        try:
            from transformers import pipeline

            self._pipeline = pipeline(
                "ner",
                model=self.model,
                # "simple" splits on sub-word boundaries for this model, which
                # is how "Hossam" became "She".
                aggregation_strategy="max",
                device=-1 if self.device == "cpu" else 0,
            )
        except Exception as exc:
            raise DetectorUnavailableError(
                self.name, exc, hint=f"could not load {self.model}"
            ) from exc

    def detect(self, text: str, ctx: DetectionContext | None = None) -> tuple[DetectedEntity, ...]:
        if not text.strip():
            return ()
        self.warmup()
        out: list[DetectedEntity] = []
        for offset, chunk in split_for_model(text, self.chunk_chars):
            try:
                raw = self._pipeline(chunk)
            except Exception as exc:
                # A hole in the middle of a document is more dangerous than an
                # outright failure, so one bad window fails the whole detector.
                raise DetectorUnavailableError(self.name, exc) from exc
            out.extend(self._convert(raw, chunk, offset, text))
        return tuple(out)

    def _convert(
        self, raw: Sequence[dict[str, Any]], chunk: str, offset: int, full_text: str
    ) -> list[DetectedEntity]:
        out: list[DetectedEntity] = []
        for item in raw:
            start = item.get("start")
            end = item.get("end")
            if start is None or end is None:
                continue  # no offsets means no trustworthy span
            start, end = int(start), int(end)
            if start < 0 or end > len(chunk) or end <= start:
                continue

            label = str(item.get("entity_group") or item.get("entity") or "")
            if label in self.drop_types:
                continue
            entity_type = canonical_type(label)
            if entity_type is None:
                continue

            score = float(item.get("score", 0.0))
            if score < self.score_threshold:
                continue

            # Widen a sub-word span to the whole token. This recovers "Hossam"
            # from "She" rather than merely discarding it.
            start, end = expand_to_word_boundary(chunk, start, end)
            surface = chunk[start:end].strip()
            if len(surface) < self.min_chars:
                continue

            abs_start, abs_end = start + offset, end + offset
            if full_text[abs_start:abs_end] != chunk[start:end]:
                continue  # rebasing disagreed with the source; drop it

            out.append(
                make_entity(
                    text_source=full_text,
                    start=abs_start,
                    end=abs_end,
                    entity_type=entity_type,
                    confidence=score,
                    detector=self.name,
                    source=label,
                    priority=self._priority,
                    reported_text=str(item.get("word", "")),
                )
            )
        return out


def build(config: Any = None, **kwargs: Any) -> NERDetector:
    return NERDetector(
        model=getattr(config, "ner_model", DEFAULT_MODEL),
        device=getattr(config, "ner_device", "cpu"),
        score_threshold=getattr(config, "ner_score_threshold", 0.60),
        **kwargs,
    )
