"""Neural PII detection built on GLiNER.

Replaces ``dslim/bert-base-NER``, whose CoNLL-2003 training set (English news
from 2003) mislabels non-Western names badly enough that "Rania Fahmy" came
back as the three fragments 'R', '##an' and '##ia Fah'.

``urchade/gliner_multi_pii-v1`` is multilingual, trained for PII specifically,
and zero-shot: entity types are plain-language labels, so adding a category is
a one-line change rather than a fine-tune.
"""

from __future__ import annotations

import threading

from .chunking import iter_windows
from .policy import has_name_initial
from .roster import COMMON_WORDS, NAME_PARTICLES, _normalize
from .spans import Span

# Prompt labels handed to the model, mapped onto the canonical type used in
# placeholders. Order is not significant.
LABEL_MAP: dict[str, str] = {
    "person": "PERSON",
    "organization": "ORG",
    "location": "LOCATION",
    "address": "ADDRESS",
    "date of birth": "DOB",
    "passport number": "PASSPORT",
    "bank account number": "BANK_ACCOUNT",
    # Detected so it outranks ORG in overlap resolution, then dropped by the
    # profile filter. This is what keeps "HR Operations Specialist" readable.
    "job title": "JOB_TITLE",
}

DEFAULT_LABELS: tuple[str, ...] = tuple(LABEL_MAP)
DEFAULT_MODEL = "urchade/gliner_multi_pii-v1"
DEFAULT_THRESHOLD = 0.45

# Structured identifiers are handled by the regex layer, which is exact and
# checksum-verified. Anything the model reports under these types is dropped
# rather than competing with a detector that cannot be wrong.
# BANK_ACCOUNT, ADDRESS, DOB and PASSPORT are deliberately absent: the regex
# layer only catches those when a keyword is adjacent, so the model remains the
# recall net for unanchored instances. Pattern authority already wins overlaps.
PATTERN_OWNED = frozenset(
    {
        "EMAIL",
        "PHONE",
        "SSN",
        "CREDIT_CARD",
        "CVV",
        "CARD_EXPIRY",
        "ROUTING_NUMBER",
        "IBAN",
        "URL",
        "IP_ADDRESS",
        "MAC_ADDRESS",
        "CUSTOM_ID",
        "CONNECTION_STRING",
        "CREDENTIAL",
        "EU_VAT",
        "SWIFT_BIC",
    }
)

# Types that name a real-world thing, and so must look like a name: at least
# one capital letter, and not an everyday word the model over-reached on.
NAME_LIKE = frozenset({"PERSON", "ORG", "LOCATION", "JOB_TITLE"})

MAX_NAME_TOKENS = 4
MIN_NAME_LETTERS = 2


class GlinerDetector:
    """Runs GLiNER over overlapping windows covering the entire document."""

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        labels: tuple[str, ...] = DEFAULT_LABELS,
        threshold: float = DEFAULT_THRESHOLD,
        window_chars: int = 1600,
        overlap_chars: int = 250,
        batch_size: int = 16,
    ) -> None:
        self.model_name = model_name
        self.labels = list(labels)
        self.threshold = threshold
        self.window_chars = window_chars
        self.overlap_chars = overlap_chars
        self.batch_size = batch_size
        self._model = None
        self._load_lock = threading.Lock()

    @property
    def model(self):
        """Load the weights on first use so importing this module stays cheap.

        Double-checked under a lock. Unsynchronised, two threads sharing one
        detector both enter ``from_pretrained``: the weights load twice, which
        doubles resident memory, and both writers race on the same Hugging
        Face cache files. An uncontended acquire costs nothing next to a
        forward pass. This does not make ``analyze()`` thread-safe -- see the
        Concurrency section of the README -- it only makes the load itself
        survive being reached from two threads at once.
        """
        if self._model is None:
            with self._load_lock:
                if self._model is None:
                    from gliner import GLiNER

                    try:
                        self._model = GLiNER.from_pretrained(
                            self.model_name, local_files_only=True
                        )
                    except Exception:
                        self._model = GLiNER.from_pretrained(self.model_name)
        return self._model

    def detect(self, text: str) -> list[Span]:
        """Return every entity in ``text``, with offsets into the original."""
        windows = iter_windows(
            text,
            max_chars=self.window_chars,
            overlap_chars=self.overlap_chars,
        )
        if not windows:
            return []

        import torch

        with torch.inference_mode():
            predictions = self.model.inference(
                [window.text for window in windows],
                self.labels,
                threshold=self.threshold,
                batch_size=self.batch_size,
            )

        spans: list[Span] = []
        for window, entities in zip(windows, predictions):
            spans.extend(self._to_spans(window.offset, text, entities))
        return spans

    def _to_spans(self, offset: int, text: str, entities: list[dict]) -> list[Span]:
        spans: list[Span] = []
        for entity in entities:
            label = LABEL_MAP.get(entity["label"], entity["label"].upper().replace(" ", "_"))
            spans.extend(
                build_spans(
                    text,
                    offset + entity["start"],
                    offset + entity["end"],
                    label,
                    float(entity.get("score", 0.0)),
                )
            )
        return spans


# Double quotes separate too: a model span that crosses one swallows the
# opening quote and leaves a dangling close, as in: the "Department of No
SEPARATORS = ",;:\"“”"

# Leading determiners the models include in an entity span.
LEADING_ARTICLES = ("the ", "a ", "an ", "The ", "A ", "An ")


def build_spans(
    text: str,
    start: int,
    end: int,
    label: str,
    score: float,
    source: str = "model",
) -> list[Span]:
    """Turn one raw detection into zero or more clean spans.

    Splits on clause separators rather than discarding: GLiNER returns
    "Saint Jude Hospital, NYC" as a single span, and rejecting it outright
    would lose two real entities at once.
    """
    pieces: list[tuple[int, int]] = []
    if label in NAME_LIKE and any(sep in text[start:end] for sep in SEPARATORS):
        cursor = start
        for index in range(start, end):
            if text[index] in SEPARATORS:
                pieces.append((cursor, index))
                cursor = index + 1
        pieces.append((cursor, end))
    else:
        pieces = [(start, end)]

    spans: list[Span] = []
    for piece_start, piece_end in pieces:
        # Trim whitespace and stray punctuation the model sometimes includes,
        # so the placeholder replaces the name and nothing else.
        while piece_start < piece_end and not text[piece_start].isalnum():
            piece_start += 1
        while piece_end > piece_start and not text[piece_end - 1].isalnum():
            piece_end -= 1
        if piece_end <= piece_start:
            continue

        surface = text[piece_start:piece_end]
        for article in LEADING_ARTICLES:
            if surface.startswith(article):
                piece_start += len(article)
                surface = text[piece_start:piece_end]
                break
        if not is_plausible(label, surface):
            continue
        # Caseless scripts (Arabic, Hebrew, CJK, etc.) have no upper/lower case.
        # Zero-shot models have higher false positive rates without casing signal,
        # so require higher confidence (>= 0.60).
        if not any(char.isupper() or char.islower() for char in surface) and score < 0.60:
            continue
        spans.append(
            Span(
                start=piece_start,
                end=piece_end,
                label=label,
                text=surface,
                score=score,
                source=source,
            )
        )
    return spans


def is_plausible(label: str, surface: str) -> bool:
    """Reject model output that cannot really be the entity type it claims.

    Zero-shot NER is generous: without this, ``'phone'``, ``'home'`` and
    ``'local'`` all get redacted as PII and the transcript stops making sense.
    """
    if label in PATTERN_OWNED:
        return False

    # One newline is a hard-wrapped name; two means the span ran away across a
    # paragraph. Rejecting any newline meant "Dr. Elizabeth\nFitzgerald",
    # "Patricia\nO'Brien", "Priya\nDeshpande" and "Nandini\nBhattacharya" were
    # never detectable at all. apply_spans puts the line break back, so the
    # document's layout survives the replacement.
    if surface.count("\n") > 1:
        return False

    tokens = surface.split()
    is_cased = any(char.isupper() or char.islower() for char in surface)
    max_tokens = MAX_NAME_TOKENS if is_cased else 5
    if not tokens or len(tokens) > max_tokens:
        return False

    if label in NAME_LIKE:
        # A name is a contiguous proper noun, not a clause. Callers split on
        # the separator rather than discarding, so nothing is lost here.
        if any(char in surface for char in ",;:"):
            return False
        if not has_name_initial(surface):
            return False
        # Rules out initials and stray punctuation such as "L." or "A".
        if sum(char.isalpha() for char in surface) < MIN_NAME_LETTERS:
            return False
        # COMMON_WORDS and lowercase check are English/cased-only.
        if is_cased:
            if all(_normalize(token) in COMMON_WORDS for token in tokens):
                return False
            for token in tokens:
                clean_tok = token.strip(".'’-")
                if clean_tok.islower() and clean_tok not in NAME_PARTICLES:
                    return False

    return True
