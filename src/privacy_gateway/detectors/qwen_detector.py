"""Layer 3: a local semantic detector.

Qwen contributes *semantic* understanding -- that "the platform the support
team uses" is an internal system, that a name in a sentence is a customer
rather than a vendor -- which no pattern and no generic NER model can supply.
It is a component, not the gateway.

Two design choices carry most of the safety here.

**The model is never asked for offsets.** It returns only ``{type, text}``, and
this module re-grounds each returned string in the source with an exact,
word-bounded search. A model that invents a span cannot produce a valid entity;
a model that invents a *string* produces one that cannot be found, and is
dropped as ungrounded. That inverts the usual failure mode: hallucination
becomes a silent no-op instead of a corrupt span.

**The parser never raises on model output.** Models emit fenced JSON, prose
preambles, thinking blocks and truncated arrays. All of that is handled and
counted; only a response with no locatable JSON at all is an error.

The detector runs against a local Ollama model. The original text stays inside
the trusted environment -- it is never sent to a hosted API for detection.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..entities.entity import DetectedEntity, make_entity
from ..entities.taxonomy import EntityType, canonical_type
from ..errors import DetectorUnavailableError
from .base import DEFAULT_PRIORITIES, DetectionContext

#: The taxonomy the model is allowed to use. Anything else is dropped.
ALLOWED_TYPES: frozenset[str] = frozenset(
    {
        EntityType.PERSON,
        EntityType.CUSTOMER,
        EntityType.STAKEHOLDER,
        EntityType.EMPLOYEE,
        EntityType.PROJECT,
        EntityType.INTERNAL_SYSTEM,
        EntityType.INTERNAL_SERVICE,
        EntityType.CONFIDENTIAL_BUSINESS_INFORMATION,
        EntityType.DATE,
    }
)

_FENCE_RE = re.compile(r"```(?:json)?\s*(?P<body>.*?)\s*```", re.DOTALL | re.IGNORECASE)
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_ARRAY_RE = re.compile(r"\[.*\]", re.DOTALL)

#: Absolute ceiling on a single entity, in characters. Also the floor for
#: the proportional guard, so short documents behave sensibly.
MAX_ENTITY_CHARS = 120
_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)

PROMPT_TEMPLATE = """\
You extract sensitive entities from meeting transcripts and business documents.

Return ONLY a JSON array. No prose, no explanation, no markdown fence.

Each element must be an object with exactly two string fields:
  "text"        the entity exactly as it appears in the document, copied
                character for character
  "entity_type" one of: {types}

Rules:
- Copy "text" verbatim from the document. Do not correct spelling, expand
  abbreviations, or change capitalisation.
- Do not return offsets, positions or explanations.
- Return an empty array [] if there are no entities.
- Do not return ordinary words, job titles, dates or times.

Document:
<<<
{document}
>>>
"""


class QwenParseError(Exception):
    """No JSON could be located in the response at all."""


@dataclass(frozen=True, slots=True)
class QwenCandidate:
    text: str
    entity_type: str


@dataclass(frozen=True, slots=True)
class ParseResult:
    candidates: tuple[QwenCandidate, ...] = ()
    dropped: int = 0
    reasons: Mapping[str, int] = field(default_factory=dict)


def _strip_wrappers(raw: str) -> str:
    """Remove thinking blocks and markdown fences."""
    body = _THINK_RE.sub("", raw).strip()
    fence = _FENCE_RE.search(body)
    if fence is not None:
        return fence.group("body").strip()
    return body


def parse_qwen_response(raw: str) -> ParseResult:
    """Extract candidates from a model response. Never raises on bad content."""
    reasons: dict[str, int] = {}
    dropped = 0

    def note(reason: str) -> None:
        nonlocal dropped
        dropped += 1
        reasons[reason] = reasons.get(reason, 0) + 1

    if raw is None or not raw.strip():
        return ParseResult()

    body = _strip_wrappers(raw)
    if not body:
        return ParseResult()

    payload: Any = None
    for attempt in (body, _ARRAY_RE.search(body), _OBJECT_RE.search(body)):
        text = attempt if isinstance(attempt, str) else (attempt.group() if attempt else None)
        if not text:
            continue
        try:
            payload = json.loads(text)
            break
        except json.JSONDecodeError:
            continue

    if payload is None:
        raise QwenParseError("no JSON array or object found in response")

    if isinstance(payload, Mapping):
        payload = payload.get("entities", payload.get("results", []))
    if not isinstance(payload, list):
        raise QwenParseError("JSON payload is not a list of entities")

    seen: set[tuple[str, str]] = set()
    out: list[QwenCandidate] = []
    for item in payload:
        if not isinstance(item, Mapping):
            note("not_an_object")
            continue
        text = item.get("text")
        entity_type = item.get("entity_type") or item.get("type") or item.get("label")
        if not isinstance(text, str) or not text.strip():
            note("missing_text")
            continue
        if not isinstance(entity_type, str) or not entity_type.strip():
            note("missing_type")
            continue
        canonical = canonical_type(entity_type)
        if canonical is None or canonical not in ALLOWED_TYPES:
            note("unknown_type")
            continue
        value = text.strip()
        key = (canonical, value)
        if key in seen:
            note("duplicate")
            continue
        seen.add(key)
        out.append(QwenCandidate(text=value, entity_type=canonical))

    return ParseResult(candidates=tuple(out), dropped=dropped, reasons=reasons)


def ground_candidates(
    candidates: Sequence[QwenCandidate],
    text: str,
    *,
    priority: int,
    confidence: float = 0.70,
    max_entities: int = 500,
    max_span_ratio: float = 0.10,
    min_chars: int = 2,
) -> tuple[tuple[DetectedEntity, ...], dict[str, int]]:
    """Locate each candidate string in the source. Unfindable ones are dropped.

    This is the hallucination guard. The model supplies a string; the offsets
    come from the document.
    """
    stats: dict[str, int] = {"ungrounded": 0, "too_long": 0, "too_short": 0, "capped": 0}
    out: list[DetectedEntity] = []
    # The ratio guard exists to reject a "span" that is really a summary of a
    # long document. On a short document a plain proportion would reject
    # ordinary names, so it is floored at a length no real entity exceeds.
    span_limit = max(MAX_ENTITY_CHARS, int(len(text) * max_span_ratio))

    for candidate in candidates:
        value = candidate.text
        if len(value) < min_chars:
            stats["too_short"] += 1
            continue
        if len(value) > span_limit:
            # A span covering a large fraction of the document is a summary,
            # not an entity.
            stats["too_long"] += 1
            continue
        pattern = re.compile(r"(?<!\w)" + re.escape(value) + r"(?!\w)")
        matches = list(pattern.finditer(text))
        if not matches:
            stats["ungrounded"] += 1
            continue
        for m in matches:
            if len(out) >= max_entities:
                stats["capped"] += 1
                break
            out.append(
                make_entity(
                    text_source=text,
                    start=m.start(),
                    end=m.end(),
                    entity_type=candidate.entity_type,
                    confidence=confidence,
                    detector="qwen",
                    source="semantic",
                    priority=priority,
                    reported_text=value,
                )
            )
    return tuple(out), stats


def split_for_context(text: str, max_chars: int) -> list[tuple[int, str]]:
    """Window the document so each request fits the model's context."""
    if len(text) <= max_chars:
        return [(0, text)] if text else []
    out: list[tuple[int, str]] = []
    start = 0
    while start < len(text):
        end = min(start + max_chars, len(text))
        if end < len(text):
            cut = text.rfind("\n", start + max_chars // 2, end)
            if cut > start:
                end = cut
        out.append((start, text[start:end]))
        start = end
    return out


class QwenDetector:
    """Semantic detection via a local Ollama model. Disabled by default."""

    name = "qwen"

    def __init__(
        self,
        settings: Any = None,
        client: Any = None,
        *,
        enabled: bool | None = None,
    ) -> None:
        self.settings = settings
        self.enabled = (
            enabled if enabled is not None else bool(getattr(settings, "enabled", False))
        )
        self.model = getattr(settings, "model", "qwen2.5:7b-instruct")
        self.max_chars = int(getattr(settings, "max_chars", 4000))
        self.max_retries = int(getattr(settings, "max_retries", 1))
        self.max_entities = int(getattr(settings, "max_entities", 500))
        self.max_span_ratio = float(getattr(settings, "max_span_ratio", 0.10))
        self._client = client
        self._priority = DEFAULT_PRIORITIES["qwen"]

    def build_prompt(self, document: str) -> str:
        return PROMPT_TEMPLATE.format(
            types=", ".join(sorted(ALLOWED_TYPES)), document=document
        )

    def warmup(self) -> None:
        if not self.enabled or self._client is not None:
            return
        from ..llm.ollama_client import OllamaClient

        self._client = OllamaClient(
            model=self.model,
            base_url=getattr(self.settings, "base_url", None),
            temperature=float(getattr(self.settings, "temperature", 0.0)),
            timeout_seconds=float(getattr(self.settings, "timeout_seconds", 60.0)),
        )

    def detect(self, text: str, ctx: DetectionContext | None = None) -> tuple[DetectedEntity, ...]:
        if not self.enabled or not text.strip():
            return ()
        self.warmup()
        if self._client is None:
            raise DetectorUnavailableError(self.name, hint="no client configured")

        entities: list[DetectedEntity] = []
        for offset, window in split_for_context(text, self.max_chars):
            parsed = self._request(window)
            if parsed is None:
                continue
            found, _ = ground_candidates(
                parsed.candidates,
                window,
                priority=self._priority,
                max_entities=self.max_entities,
                max_span_ratio=self.max_span_ratio,
            )
            entities.extend(e.shifted(offset) for e in found)

        # Rebasing must agree with the source; anything that does not is dropped
        # rather than trusted.
        return tuple(e for e in entities if text[e.start : e.end] == e.text)

    def _request(self, window: str) -> ParseResult | None:
        prompt = self.build_prompt(window)
        for attempt in range(self.max_retries + 1):
            try:
                response = self._client.invoke(prompt)
            except Exception as exc:
                raise DetectorUnavailableError(self.name, exc) from exc
            try:
                return parse_qwen_response(getattr(response, "text", str(response)))
            except QwenParseError:
                if attempt >= self.max_retries:
                    return None
                prompt = (
                    self.build_prompt(window)
                    + "\n\nYour previous reply was not valid JSON. "
                    "Reply with a JSON array and nothing else."
                )
        return None


def build(config: Any = None, settings: Any = None, client: Any = None, **_: Any) -> QwenDetector:
    return QwenDetector(settings=settings, client=client)
