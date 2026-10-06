"""The orchestrator.

Ordering is load-bearing. In particular:

* the injection guard runs **after** normalization (so encoded variants have
  already been folded into the plain form) and **before** detection (so an
  injected token is allocated a placeholder before any real entity, and cannot
  race a victim index);
* the pre-send leak gate runs **after** pseudonymization and **before** the
  model call, and is not governed by the fail mode -- there is no failing open
  on a transmission that has already happened;
* the output scan runs **before** restoration, because afterwards the values
  are supposed to be there.
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from typing import Literal

from .aggregation.aggregator import AggregationResult, EntityAggregator
from .config import Settings
from .detectors.base import DetectionContext, Detector, build_detector
from .entities.entity import DetectedEntity
from .errors import (
    DetectorUnavailableError,
    GatewayError,
    InputTooLargeError,
    LLMError,
    OutputLeakError,
    PlaceholderInjectionError,
)
from .llm.base import LLMClient, build_llm
from .llm.prompt import PromptWrapper
from .observability.timing import Timings
from .policy.engine import PolicyDecision, PolicyEngine
from .preprocessing.normalizer import NormalizedText, Normalizer, NormalizerConfig
from .preprocessing.registry import ParticipantRegistry
from .preprocessing.transcript import ParsedTranscript, TranscriptParser
from .pseudonymization.applier import Pseudonymizer, SanitizationResult
from .pseudonymization.consistency import expand_occurrences
from .pseudonymization.mapping_store import MappingStore
from .pseudonymization.placeholders import PlaceholderFormat
from .reidentification.injection import PlaceholderInjectionGuard
from .reidentification.output_scanner import OutputScanner
from .reidentification.restorer import ReidentificationResult, Reidentifier

Status = Literal["ok", "degraded"]


@dataclass(frozen=True, slots=True)
class GatewayRequest:
    text: str
    conversation_id: str = ""
    instruction: str | None = None


@dataclass(frozen=True, slots=True)
class SanitizeOutcome:
    """Everything produced before the model is called."""

    sanitized_text: str
    normalized: NormalizedText
    entities: tuple[DetectedEntity, ...]
    decisions: tuple[PolicyDecision, ...]
    store: MappingStore
    aggregation: AggregationResult
    sanitization: SanitizationResult
    parsed: ParsedTranscript
    registry: ParticipantRegistry
    injected: int = 0
    degraded_detectors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class GatewayResult:
    status: Status
    output: str
    sanitize: SanitizeOutcome
    reidentification: ReidentificationResult | None = None
    timings: Timings = field(default_factory=Timings)
    warnings: tuple[str, ...] = ()
    llm_retries: int = 0

    @property
    def store(self) -> MappingStore:
        return self.sanitize.store

    @property
    def sanitized_input(self) -> str:
        return self.sanitize.sanitized_text


def new_conversation_id() -> str:
    """At least 128 bits, so a conversation id is not guessable."""
    return "c-" + secrets.token_urlsafe(16)


class PrivacyGateway:
    """Runs the full pipeline."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        llm: LLMClient | None = None,
        detectors: Sequence[Detector] | None = None,
        policy: PolicyEngine | None = None,
        prompt_wrapper: PromptWrapper | None = None,
    ) -> None:
        self.settings = settings or Settings()
        self._llm = llm
        self._explicit_detectors = tuple(detectors) if detectors is not None else None
        self.policy = policy or PolicyEngine.from_paths(
            self.settings.policy_path,
            self.settings.allowlist_path,
            self.settings.denylist_path,
            fail_closed=self.settings.fail_closed,
        )
        self.normalizer = Normalizer(
            NormalizerConfig(
                normalize_newlines=self.settings.preprocessing.normalize_newlines,
                decode_html_entities=self.settings.preprocessing.decode_html_entities,
                strip_zero_width=self.settings.preprocessing.strip_zero_width,
                fold_spaces=self.settings.preprocessing.fold_spaces,
                fold_quotes=self.settings.preprocessing.fold_quotes,
                unicode_form=self.settings.preprocessing.unicode_form,
            )
        )
        self.parser = TranscriptParser()
        self.aggregator = EntityAggregator()
        self.guard = PlaceholderInjectionGuard()
        self.prompt_wrapper = prompt_wrapper or PromptWrapper()
        self.placeholder_format = PlaceholderFormat(
            style=self.settings.reidentification.placeholder_style,  # type: ignore[arg-type]
            pad=self.settings.reidentification.placeholder_pad,
        )

    # -- detectors ---------------------------------------------------------
    def _build_detectors(self, registry: ParticipantRegistry) -> list[Detector]:
        if self._explicit_detectors is not None:
            for det in self._explicit_detectors:
                if getattr(det, "name", "") == "registry":
                    det.registry = registry  # type: ignore[attr-defined]
            return list(self._explicit_detectors)

        out: list[Detector] = []
        for name in self.settings.detectors.enabled:
            kwargs = {}
            if name == "registry":
                kwargs["registry"] = registry
            if name == "qwen":
                kwargs["settings"] = self.settings.qwen
            out.append(build_detector(name, self.settings.detectors, **kwargs))
        return out

    def _is_required(self, name: str) -> bool:
        if name in self.settings.detectors.required:
            return True
        if name == "qwen":
            return self.settings.qwen.required
        # Under fail-closed every configured detector is part of the promised
        # protection level, so losing one means running weaker than configured.
        return self.settings.fail_closed

    def _run_detectors(
        self, detectors: Sequence[Detector], text: str, ctx: DetectionContext, timings: Timings
    ) -> tuple[list[DetectedEntity], list[str]]:
        entities: list[DetectedEntity] = []
        degraded: list[str] = []

        for detector in detectors:
            name = getattr(detector, "name", detector.__class__.__name__)
            try:
                with timings.stage(f"detect.{name}"):
                    found = tuple(detector.detect(text, ctx))
            except Exception as exc:
                if self._is_required(name):
                    raise DetectorUnavailableError(name, exc) from exc
                degraded.append(name)
                continue
            entities.extend(found)
            timings.count(f"entities.{name}", len(found))

        return entities, degraded

    # -- sanitize ----------------------------------------------------------
    def sanitize(
        self, request: GatewayRequest, timings: Timings | None = None
    ) -> SanitizeOutcome:
        timings = timings or Timings()
        limit = self.settings.preprocessing.max_input_chars
        if len(request.text) > limit:
            raise InputTooLargeError(len(request.text), limit)

        with timings.stage("normalize"):
            normalized = self.normalizer.normalize(request.text)
        text = normalized.text

        with timings.stage("parse_transcript"):
            parsed = self.parser.parse(text)
        with timings.stage("build_registry"):
            registry = ParticipantRegistry.from_transcript(parsed)

        # Before detection: an injected placeholder must be allocated first.
        with timings.stage("injection_guard"):
            injected = self.guard.scan(text)
            if injected and self.settings.reidentification.block_on_injection and self.settings.fail_closed:
                raise PlaceholderInjectionError(len(injected))
            injected_entities = self.guard.as_entities(text, injected)

        ctx = DetectionContext(conversation_id=request.conversation_id)
        detectors = self._build_detectors(registry)
        found, degraded = self._run_detectors(detectors, text, ctx, timings)

        with timings.stage("aggregate"):
            aggregation = self.aggregator.aggregate([*injected_entities, *found], text)
        with timings.stage("policy"):
            decisions = self.policy.decide_all(aggregation.entities)

        # Detection is positional: a detector may find "Exampleco" in one
        # sentence and miss it in the next, which would leave the second
        # occurrence in the text while the first is protected. Sweep for the
        # remaining occurrences of every value we are about to protect, then
        # re-aggregate so the new spans go through the same overlap rules.
        with timings.stage("consistency"):
            extra = expand_occurrences(text, decisions)
            if extra:
                timings.count("consistency.recovered", len(extra))
                aggregation = self.aggregator.aggregate(
                    [*injected_entities, *found, *extra], text
                )
                decisions = self.policy.decide_all(aggregation.entities)

        store = MappingStore(
            request.conversation_id or new_conversation_id(), self.placeholder_format
        )
        with timings.stage("pseudonymize"):
            sanitization = Pseudonymizer(store).apply(text, decisions)

        # Unconditional gate. Not governed by fail_mode: a transmission cannot
        # be undone, so there is no meaningful "open" behaviour here.
        with timings.stage("scan.pre_send"):
            OutputScanner(store).assert_clean(sanitization.text, "pre_send")

        return SanitizeOutcome(
            sanitized_text=sanitization.text,
            normalized=normalized,
            entities=aggregation.entities,
            decisions=decisions,
            store=store,
            aggregation=aggregation,
            sanitization=sanitization,
            parsed=parsed,
            registry=registry,
            injected=len(injected),
            degraded_detectors=tuple(degraded),
        )

    # -- full pipeline -----------------------------------------------------
    def run(self, request: GatewayRequest) -> GatewayResult:
        timings = Timings()
        warnings: list[str] = []

        if not request.conversation_id:
            request = replace(request, conversation_id=new_conversation_id())

        outcome = self.sanitize(request, timings)
        if outcome.degraded_detectors:
            warnings.append(
                f"running without detector(s): {', '.join(outcome.degraded_detectors)}"
            )
        if outcome.injected:
            warnings.append(f"neutralised {outcome.injected} injected placeholder token(s)")

        llm = self._llm or build_llm(self.settings.llm)
        prompt = self.prompt_wrapper.wrap(outcome.sanitized_text, request.instruction)

        with timings.stage("llm.invoke"):
            response = llm.invoke(prompt.user, system=prompt.system)

        reidentifier = Reidentifier(
            outcome.store,
            self.policy,
            unknown_action=self.settings.reidentification.unknown_action,  # type: ignore[arg-type]
            scan_output=self.settings.reidentification.scan_output,
            scan_drift=self.settings.reidentification.scan_drift,
        )

        retries = 0
        with timings.stage("scan.output"):
            result = reidentifier.restore(response.text, conversation_id=request.conversation_id)

        # One bounded corrective turn when the model mangled the placeholders.
        if (
            result.drift
            and self.settings.reidentification.on_drift == "retry"
            and self.settings.reidentification.max_drift_retries > 0
        ):
            retries = 1
            correction = self.prompt_wrapper.correction(tuple(d.raw for d in result.drift))
            try:
                with timings.stage("llm.retry"):
                    retry_response = llm.invoke(
                        prompt.user + "\n\n" + correction, system=prompt.system
                    )
                retried = reidentifier.restore(
                    retry_response.text, conversation_id=request.conversation_id
                )
                if len(retried.drift) < len(result.drift):
                    result = retried
                    warnings.append("model mangled placeholders; corrective turn improved it")
                else:
                    warnings.append("model mangled placeholders; corrective turn did not help")
            except LLMError:
                warnings.append("corrective turn failed; reporting original drift")

        status: Status = result.status
        output = result.text

        critical = [f for f in result.leaks if f.severity == "critical"]
        if critical:
            if self.settings.fail_closed:
                # The model reproduced something we believed we had removed.
                # Returning that text would write a secret into a report file.
                raise OutputLeakError(len(critical), tuple(f.entity_type for f in critical))
            status = "degraded"
            warnings.append(f"model output contained {len(critical)} raw sensitive value(s)")

        if result.unknown:
            warnings.append(
                f"model produced {len(result.unknown)} placeholder(s) not in this mapping"
            )

        return GatewayResult(
            status=status,
            output=output,
            sanitize=outcome,
            reidentification=result,
            timings=timings,
            warnings=tuple(warnings),
            llm_retries=retries,
        )

    def restore(
        self, llm_output: str, store: MappingStore, *, conversation_id: str | None = None
    ) -> ReidentificationResult:
        return Reidentifier(
            store,
            self.policy,
            unknown_action=self.settings.reidentification.unknown_action,  # type: ignore[arg-type]
        ).restore(llm_output, conversation_id=conversation_id)


__all__ = [
    "GatewayError",
    "GatewayRequest",
    "GatewayResult",
    "PrivacyGateway",
    "SanitizeOutcome",
    "new_conversation_id",
]
