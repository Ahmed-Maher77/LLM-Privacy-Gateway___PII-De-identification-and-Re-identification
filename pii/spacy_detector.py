"""spaCy as a fast second opinion alongside GLiNER.

The two models fail differently: GLiNER is stronger on transliterated and
non-Western names, spaCy catches short one-word names GLiNER shrugs at. Running
both and taking the union costs under a second and measurably lifts recall --
a miss here means real PII reaches the LLM, so recall is the metric that counts.
"""

from __future__ import annotations

import threading

import warnings

from .chunking import iter_windows
from .detector import build_spans
from .errors import DetectorUnavailable, DetectorUnavailableWarning
from .spans import Span

LABEL_MAP: dict[str, str] = {
    "PERSON": "PERSON",
    "ORG": "ORG",
    "GPE": "LOCATION",
    "LOC": "LOCATION",
    "FAC": "LOCATION",
    # Nationality, ethnic group, religious and political affiliation. Mapping
    # this into LOCATION meant it inherited LOCATION's policy and would be
    # printed by default -- but it is special-category data, not a place name.
    "NORP": "NORP",
}

DEFAULT_MODEL = "en_core_web_lg"

# Below GLiNER's typical confidence, so when the two disagree on an entity's
# type the PII-trained model carries the vote.
SPACY_SCORE = 0.5


class SpacyDetector:
    """Runs a spaCy pipeline over the document and normalizes its labels."""

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        window_chars: int = 40_000,
        overlap_chars: int = 1_000,
    ) -> None:
        self.model_name = model_name
        self.window_chars = window_chars
        self.overlap_chars = overlap_chars
        self._nlp = None
        self._load_lock = threading.Lock()

    @property
    def nlp(self):
        """Double-checked lazy load; see GlinerDetector.model for why."""
        if self._nlp is None:
            with self._load_lock:
                if self._nlp is None:
                    import spacy

                    self._nlp = spacy.load(
                        self.model_name, disable=["lemmatizer", "textcat"]
                    )
        return self._nlp

    @classmethod
    def load_if_available(
        cls,
        model_name: str = DEFAULT_MODEL,
        *,
        required: bool = False,
    ) -> SpacyDetector | None:
        """Return a detector, or ``None`` when the model is not installed.

        The ensemble is an enhancement, not a hard dependency: a missing spaCy
        model should degrade recall, not break the pipeline. It must degrade
        *audibly* though -- a clean run with spaCy missing is a materially
        weaker claim than a full-strength one, and silence made the two
        indistinguishable.

        A corrupt or version-mismatched install is deliberately allowed to
        propagate. Swallowing every exception made a broken spaCy look exactly
        like an absent one.
        """
        try:
            import spacy
        except ImportError as exc:
            return cls._unavailable(
                model_name, "spacy is not installed", "uv add spacy", required, exc
            )

        try:
            spacy.util.get_package_path(model_name)
        except (OSError, LookupError, ImportError) as exc:
            # ModuleNotFoundError is what spaCy raises for an un-downloaded
            # model, and it subclasses ImportError -- so it must be caught
            # here, after the separate check for spaCy itself being absent.
            return cls._unavailable(
                model_name,
                f"model {model_name!r} is not downloaded",
                f"uv run python -m spacy download {model_name}",
                required,
                exc,
            )

        return cls(model_name=model_name)

    @classmethod
    def _unavailable(
        cls,
        model_name: str,
        reason: str,
        hint: str,
        required: bool,
        cause: Exception,
    ) -> None:
        if required:
            raise DetectorUnavailable(cls.__name__, reason=reason, hint=hint) from cause
        warnings.warn(
            f"{cls.__name__} unavailable: {reason}. Recall will be lower. {hint}",
            DetectorUnavailableWarning,
            stacklevel=3,
        )

    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for window in iter_windows(
            text,
            max_chars=self.window_chars,
            overlap_chars=self.overlap_chars,
        ):
            doc = self.nlp(window.text)
            for entity in doc.ents:
                label = LABEL_MAP.get(entity.label_)
                if label is None:
                    continue
                spans.extend(
                    build_spans(
                        text,
                        window.offset + entity.start_char,
                        window.offset + entity.end_char,
                        label,
                        SPACY_SCORE,
                    )
                )
        return spans
