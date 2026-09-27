"""Layer 1: Microsoft Presidio.

Presidio was a declared dependency of the prototype but was never imported; the
whole pipeline ran on one NER model and one email regex. It is wired up here for
the recognisers it does well -- structured identifiers with validators, plus a
spaCy-backed NER pass.

Model loading happens in :meth:`warmup`, not ``__init__``, so building the
detector stays cheap and the fast unit suite never pulls spaCy into the process.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ..entities.entity import DetectedEntity, make_entity
from ..entities.taxonomy import canonical_type
from ..errors import DetectorUnavailableError
from .base import DEFAULT_PRIORITIES, DetectionContext

DEFAULT_SPACY_MODEL = "en_core_web_lg"

#: Presidio recognisers worth running. DATE_TIME is requested so that the policy
#: layer can decide about dates; it is not protected by default, because a
#: transcript's timestamps are its structure.
DEFAULT_ENTITIES: tuple[str, ...] = (
    "PERSON",
    "ORGANIZATION",
    "LOCATION",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "IP_ADDRESS",
    "URL",
    "DATE_TIME",
    "US_SSN",
    "MEDICAL_LICENSE",
    "CRYPTO",
)


class PresidioDetector:
    """Wraps ``AnalyzerEngine`` and normalises its output."""

    name = "presidio"
    layer = 1

    def __init__(
        self,
        spacy_model: str = DEFAULT_SPACY_MODEL,
        entities: Sequence[str] = DEFAULT_ENTITIES,
        language: str = "en",
        score_threshold: float = 0.35,
    ) -> None:
        self.spacy_model = spacy_model
        self.entities = tuple(entities)
        self.language = language
        self.score_threshold = score_threshold
        self._priority = DEFAULT_PRIORITIES["presidio"]
        self._analyzer: Any = None

    def warmup(self) -> None:
        if self._analyzer is not None:
            return
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider

            provider = NlpEngineProvider(
                nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": self.language, "model_name": self.spacy_model}],
                }
            )
            self._analyzer = AnalyzerEngine(
                nlp_engine=provider.create_engine(),
                supported_languages=[self.language],
            )
        except Exception as exc:
            raise DetectorUnavailableError(
                self.name,
                exc,
                hint=f"install the spaCy model, e.g. uv run python -m spacy download {self.spacy_model}",
            ) from exc

    def detect(self, text: str, ctx: DetectionContext | None = None) -> tuple[DetectedEntity, ...]:
        if not text:
            return ()
        self.warmup()
        try:
            results = self._analyzer.analyze(
                text=text,
                language=self.language,
                entities=list(self.entities),
                score_threshold=self.score_threshold,
            )
        except Exception as exc:
            raise DetectorUnavailableError(self.name, exc) from exc

        out: list[DetectedEntity] = []
        for r in results:
            entity_type = canonical_type(r.entity_type)
            if entity_type is None:
                continue
            if r.start < 0 or r.end > len(text) or r.end <= r.start:
                continue
            out.append(
                make_entity(
                    text_source=text,
                    start=r.start,
                    end=r.end,
                    entity_type=entity_type,
                    confidence=float(r.score),
                    detector=self.name,
                    source=str(r.entity_type),
                    priority=self._priority,
                )
            )
        return tuple(out)


def build(config: Any = None, **kwargs: Any) -> PresidioDetector:
    return PresidioDetector(
        spacy_model=getattr(config, "presidio_spacy_model", DEFAULT_SPACY_MODEL),
        score_threshold=getattr(config, "presidio_score_threshold", 0.35),
        **kwargs,
    )
