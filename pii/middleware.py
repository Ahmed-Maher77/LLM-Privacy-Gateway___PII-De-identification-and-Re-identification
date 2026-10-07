"""Orchestration: detect, pseudonymize, verify, restore."""

from __future__ import annotations

import importlib.metadata
import os
import re
import warnings
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from .context import DocumentContext
from .custom_patterns import build_rules, load_config
from .detector import DEFAULT_LABELS, DEFAULT_MODEL, DEFAULT_THRESHOLD, GlinerDetector
from .entities import EntityIndex, has_honorific_prefix, names_from_emails, strip_affixes
from .errors import LeakDetected, LeakWarning, PlaceholderInjection, ReviewRequired
from .patterns import EMAIL_PATTERN, PatternRule, detect_patterns
from .policy import (
    CORPORATE_SUFFIXES,
    DEFAULT_ALLOWLIST,
    DEFAULT_PROFILE,
    PROTECTED_TERMS,
    _normalize,
    allowlist_tokens,
    describe_policy,
    is_non_personal,
    is_protected_term,
    resolve_types,
)
from .residual import DEFAULT_RESIDUAL_POLICY, Finding, ResidualPolicy, scan_residual
from .roster import PropagationTerm, _uninvert, extract_roster, propagate_names, propagate_terms
from .spacy_detector import SpacyDetector
from .spanfix import normalize_spans
from .spans import SOURCE_PRIORITY, Span, SpanSet, apply_spans
from .structure import StructureMap, analyze_structure, protect_spans
from .titles import detect_titles
from .vault import ESCAPE_LABEL, PseudonymVault, find_template_literals
from .vault import restore as restore_text


def package_version(name: str | None) -> str | None:
    """Installed version of a distribution, or None when it is absent.

    Used for provenance only, so a missing package is a blank field rather
    than an error: a detector can be running from a source checkout with no
    distribution metadata at all.
    """
    if not name:
        return None
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _detector_package(detector: object) -> str | None:
    """Which distribution provides a detector's weights."""
    if isinstance(detector, GlinerDetector):
        return "gliner"
    if isinstance(detector, SpacyDetector):
        return "spacy"
    return None


MIN_AUDIT_LENGTH = 3
MIN_SWEEP_LENGTH = 3
PERSON_BIAS = 0.75

OnLeak = Literal["raise", "warn", "ignore"]
EscapePolicy = Literal["neutralize", "reject", "ignore"]
PersonEvidence = Literal["corroborated", "any"]

STATUS_CLEAN = "clean"
STATUS_REVIEW = "review"
STATUS_FAILED = "failed"

_PLACEHOLDER_SEQUENCE_RE = re.compile(
    r"(?P<placeholder>\{\{[A-Z][A-Z0-9_]*_\d+\}\})"
    r"(?:[ \t\r\n]*(?:\d{1,4}[ \t]+)?\1)+"
)


def dedupe_placeholders(text: str) -> str:
    """Collapse adjacent duplicate placeholders produced by overlapping spans."""
    return _PLACEHOLDER_SEQUENCE_RE.sub(r"\g<placeholder>", text)


def validate_output(original: str, redacted: str) -> bool:
    """Validate structural preservation and reject obvious residual secrets."""
    for term in PROTECTED_TERMS:
        expected = original.casefold().count(term.casefold())
        actual = redacted.casefold().count(term.casefold())
        if expected != actual:
            raise AssertionError(f"protected term changed: {term}")
    if "redacted-template-token-" in redacted:
        raise AssertionError("debug placeholder leaked into output")
    if any(f.severity == "high" and not f.suppressed_by for f in scan_residual(redacted)):
        raise AssertionError("high-confidence secret shape remains in output")
    return True


class Detector(Protocol):
    """Anything that can point at the PII in a string."""

    def detect(self, text: str) -> list[Span]: ...


@dataclass
class AnonymizationResult:
    """Everything the caller needs to reason about one anonymization pass."""

    sanitized: str
    mapping: dict[str, str]
    spans: list[Span] = field(default_factory=list)
    roster: list[str] = field(default_factory=list)
    profile: str = DEFAULT_PROFILE
    leaks: list[dict] = field(default_factory=list)
    residual: list[Finding] = field(default_factory=list)
    escapes: dict[str, str] = field(default_factory=dict)
    detector_status: list[dict] = field(default_factory=list)
    uncorroborated: list[dict] = field(default_factory=list)
    structure: dict = field(default_factory=dict)
    dry_run: bool = False
    policy: dict = field(default_factory=dict)

    @property
    def high_severity_leaks(self) -> list[dict]:
        return [leak for leak in self.leaks if leak.get("severity") == "high"]

    @property
    def residual_high(self) -> list[Finding]:
        return [f for f in self.residual if f.severity == "high" and not f.suppressed_by]

    @property
    def residual_medium(self) -> list[Finding]:
        return [f for f in self.residual if f.severity == "medium" and not f.suppressed_by]

    @property
    def status(self) -> str:
        """Three states, because a boolean could not tell the truth here.

        The original report said ``"clean": true`` while six secrets sat in the
        output. That was not a bug in the check but in the word: the check only
        ever knew about values it had detected. "clean" now means both passes
        agree, and "review" means shapes were found that nobody has triaged.
        """
        if self.high_severity_leaks or self.residual_high:
            return STATUS_FAILED
        if self.residual_medium:
            return STATUS_REVIEW
        return STATUS_CLEAN

    @property
    def is_clean(self) -> bool:
        return self.status == STATUS_CLEAN

    @property
    def safe_sanitized(self) -> str:
        """Return sanitized text only if verification status is clean or review.

        Raises LeakDetected if verification failed, guarding callers against
        inadvertently transmitting surviving PII when running under permissive
        modes like on_leak="warn" or "ignore".
        """
        if self.status == STATUS_FAILED:
            raise LeakDetected(
                status=self.status,
                leaks=self.high_severity_leaks,
                residual=[
                    {"rule": f.rule, "severity": f.severity, "line": f.line}
                    for f in self.residual_high
                ],
                reason="refusing to return sanitized text: PII survived redaction",
            )
        return self.sanitized

    def as_tuple(self) -> tuple[str, dict[str, str]]:
        """Return (safe_sanitized, mapping), blocking failed redactions."""
        return self.safe_sanitized, self.mapping


class PIIMiddleware:
    """Detects PII, swaps it for stable placeholders, and puts it back.

    Detection layers, all feeding one span resolver:

    1. ``patterns``  -- regex for structured identifiers, with checksums used
       as confidence signals rather than gates.
    2. ``model``     -- GLiNER plus spaCy over overlapping windows, so the
       whole document is scanned rather than the first 512 tokens.
    3. ``roster``    -- every known participant matched across the full text.
    4. ``lexicon``   -- job and meeting titles, detected so they outrank ORG
       and are then dropped unredacted.

    Verification then runs two independent passes: ``audit`` re-checks what was
    detected, and ``scan_residual`` looks for secret shapes with no reference
    to what was detected. Neither alone is sufficient.

    Concurrency Contract:
        ``PIIMiddleware`` is **not thread-safe** (underlying spaCy and stateful
        context require single-threaded execution). Deployments must isolate
        one instance per worker process or worker thread.

    Policy Configuration:
        - ``profile``: Base entity profile (``"balanced"``, ``"strict"``, ``"minimal"``).
        - ``entities``: Explicit overrides with **overlay semantics**. Omitted entity
          types retain their default setting from ``profile``.
        - ``fixed_names``: Unconditional caller-asserted person names. Names listed here
          are masked everywhere in the document even if ``PERSON`` is disabled in
          ``profile`` or through ``entities={"person": False}``.
    """

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        labels: tuple[str, ...] = DEFAULT_LABELS,
        threshold: float = DEFAULT_THRESHOLD,
        window_chars: int = 1600,
        overlap_chars: int = 250,
        use_roster: bool = True,
        use_spacy: bool = True,
        use_titles: bool = True,
        profile: str = DEFAULT_PROFILE,
        entities: Mapping[str, bool] | None = None,
        fixed_names: Sequence[str] = (),
        allowlist: frozenset[str] | set[str] = DEFAULT_ALLOWLIST,
        detectors: Sequence[Detector] | None = None,
        on_leak: OnLeak = "raise",
        strict: bool = False,
        require_detectors: bool = False,
        escape_placeholders: EscapePolicy = "neutralize",
        person_evidence: PersonEvidence = "corroborated",
        patterns_config: str | Path | None = None,
        residual_policy: ResidualPolicy = DEFAULT_RESIDUAL_POLICY,
    ) -> None:
        self.profile = profile
        self.entities = dict(entities) if entities else {}
        self.allowlist = allowlist_tokens(allowlist)
        self.use_roster = use_roster
        self.use_titles = use_titles
        self.on_leak = on_leak
        self.strict = strict
        self.escape_placeholders = escape_placeholders
        self.person_evidence = person_evidence
        self.residual_policy = residual_policy

        # A fixed name is a caller instruction, not something inferred from
        # the document, so it is validated eagerly: propagate_names() splits
        # on whitespace to find a surname, and an empty or blank entry would
        # raise deep inside the pipeline on the first document, instead of at
        # construction where the mistake is easy to trace.
        seen_fixed: set[str] = set()
        normalized_fixed: list[str] = []
        for name in fixed_names:
            if not name or not name.strip():
                raise ValueError("fixed_names entries must be non-empty strings")
            # Un-inverted here, once, rather than left to propagate_names():
            # this is also where the forced-match key is derived below, and
            # both need to agree that "Raman, Priya" and "Priya Raman" are
            # the same string.
            canonical = _uninvert(name.strip())
            key = _normalize(canonical)
            if key and key not in seen_fixed:
                seen_fixed.add(key)
                normalized_fixed.append(canonical)
        self.fixed_names = normalized_fixed

        config = load_config(patterns_config)
        self.pattern_rules: tuple[PatternRule, ...] = build_rules(config)
        self.min_pattern_score = config.min_score

        # Custom labels from TOML are redacted by construction, otherwise a
        # rule would be detected and then silently discarded by the profile
        # filter, but ``entities`` can still turn one off explicitly, the same
        # as any other type.
        # Validation of both the profile and every ``entities`` key happens
        # here, in the constructor, so a bad key fails at startup rather than
        # at the first call to analyze().
        self._custom_labels = {rule.label for rule in config.rules}
        self.redacted_types = resolve_types(profile, entities, custom_labels=self._custom_labels)

        self._torch_threads: int | None = None

        if detectors is None:
            detector_list: list[Detector] = [
                GlinerDetector(
                    model_name=model_name,
                    labels=labels,
                    threshold=threshold,
                    window_chars=window_chars,
                    overlap_chars=overlap_chars,
                )
            ]
            if use_spacy:
                spacy_detector = SpacyDetector.load_if_available(required=require_detectors)
                if spacy_detector is not None:
                    detector_list.append(spacy_detector)
            self.detectors: list[Detector] = detector_list
        else:
            self.detectors = list(detectors)

    @property
    def detector(self) -> Detector:
        """The primary detector, kept for callers that reach for it directly."""
        return self.detectors[0]

    def describe_detectors(self) -> list[dict]:
        """Which detectors actually ran.

        A clean result with spaCy missing is a weaker claim than a clean result
        at full strength, so the artefact has to record the difference.
        """
        names = {type(detector).__name__ for detector in self.detectors}
        status = [
            {
                "name": type(detector).__name__,
                "available": True,
                # The class name alone cannot be reproduced against. A report
                # that does not say which weights produced it is an artefact
                # nobody can re-run, which is most of what an audit trail is
                # for. The model id is known here; recording it costs nothing.
                "model_id": getattr(detector, "model_name", None),
                "package": _detector_package(detector),
                "package_version": package_version(_detector_package(detector)),
                "torch_threads": self._torch_threads,
            }
            for detector in self.detectors
        ]
        if "SpacyDetector" not in names:
            status.append(
                {
                    "name": "SpacyDetector",
                    "available": False,
                    "model_id": None,
                    "package": "spacy",
                    "package_version": package_version("spacy"),
                    "reason": "model not installed; recall is reduced",
                }
            )
        return status

    @classmethod
    def for_production(
        cls,
        *,
        model_name: str = DEFAULT_MODEL,
        profile: str = DEFAULT_PROFILE,
        entities: Mapping[str, bool] | None = None,
        fixed_names: Sequence[str] = (),
        patterns_config: str | Path | None = None,
        allowlist: frozenset[str] | set[str] = DEFAULT_ALLOWLIST,
    ) -> PIIMiddleware:
        """Create a hardened, fail-closed middleware instance for production deployment.

        Enforces unconditionally:
        - Strict fail-closed verification: ``on_leak="raise"`` (cannot be overridden).
        - Mandatory detector availability: requires both GLiNER and spaCy models to be installed
          and functional at construction time (``require_detectors=True``).
        - Mandatory eager warmup: runs a test inference at startup to verify weight integrity and
          eliminate first-request latency spikes in production workers.
        - Strict mode locked to True: unreviewed medium-confidence findings raise ReviewRequired.
        - PyTorch intra-op parallelism is bounded per worker. Set ``PII_TORCH_THREADS``
          to override the default (half the logical CPUs, minimum one); this avoids
          each process competing for every CPU core under multi-worker load.
        """
        raw_threads = os.environ.get("PII_TORCH_THREADS")
        try:
            torch_threads = (
                int(raw_threads)
                if raw_threads is not None
                else max(1, (os.cpu_count() or 1) // 2)
            )
        except ValueError as exc:
            raise ValueError("PII_TORCH_THREADS must be a positive integer") from exc
        if torch_threads < 1:
            raise ValueError("PII_TORCH_THREADS must be a positive integer")

        import torch

        torch.set_num_threads(torch_threads)

        instance = cls(
            model_name=model_name,
            profile=profile,
            entities=entities,
            fixed_names=fixed_names,
            strict=True,
            on_leak="raise",
            require_detectors=True,
            patterns_config=patterns_config,
            allowlist=allowlist,
        )
        instance._torch_threads = torch_threads
        detector_classes = {type(d).__name__ for d in instance.detectors}
        if "GlinerDetector" not in detector_classes or "SpacyDetector" not in detector_classes:
            missing = {"GlinerDetector", "SpacyDetector"} - detector_classes
            raise RuntimeError(
                f"Production deployment requires full detector ensemble; missing: {sorted(missing)}"
            )

        instance.analyze("System initialization probe: user@example.com", dry_run=True)

        return instance

    def analyze(self, text: str, *, dry_run: bool = False) -> AnonymizationResult:
        """Full pipeline, including both verification passes."""
        structure = analyze_structure(text)
        context = DocumentContext.build(text, self._tagger())

        collected = SpanSet()
        collected.extend(
            detect_patterns(text, rules=self.pattern_rules, min_score=self.min_pattern_score)
        )
        # "Matter No: 2024-AML-0876" and "Session ID: REC-2023-11-14-0092" are
        # identifiers because of the field they sit in, not because of their
        # shape -- which is why a shape-only rule caught one document's
        # reference number and missed two others.
        collected.extend(_id_field_spans(text, context))
        collected.extend(_address_field_spans(text, context))

        escape_spans = self._template_literals(text)
        collected.extend(escape_spans)

        model_spans: list[Span] = []
        for detector in self.detectors:
            model_spans.extend(detector.detect(text))
        # Normalise before anything reads a span's text. The name pool and the
        # entity index both derive identity from it, so one loose edge would
        # otherwise name the entity for every later mention of that person.
        model_spans = normalize_spans(text, model_spans, context)
        collected.extend(model_spans)

        # An address that is already being masked also tells us the person's
        # name: david.lee@example.org is why "Hi David," used to survive.
        email_names = names_from_emails(text, EMAIL_PATTERN)

        fixed_keys = frozenset(_normalize(name) for name in self.fixed_names)

        roster: list[str] = []
        if self.use_roster:
            roster = extract_roster(text, context=context)
        if self.fixed_names:
            # ``use_roster`` governs inference from speaker labels in the
            # document; a fixed name is a caller instruction and is masked
            # whether or not inference is switched on, so it is merged in
            # here rather than gated behind the same flag.
            roster = [
                *self.fixed_names,
                *(name for name in roster if _normalize(name) not in fixed_keys),
            ]
        if self.use_roster or self.fixed_names:
            # Confirmed by the document itself -- a real speaker, or an
            # address someone actually used -- as opposed to a name only a
            # single detector run proposed. ``_name_pool`` below adds
            # model-proposed full names to ``names`` too, but they must not
            # count here: that is exactly the case the confirmed-only
            # relaxations in propagate_names() exist to keep out.
            confirmed_keys = frozenset(_normalize(name) for name in roster) | frozenset(
                _normalize(name) for name in email_names
            )
            names = self._name_pool(roster, model_spans, email_names, protect=fixed_keys)
            collected.extend(
                propagate_names(
                    text,
                    names,
                    forced_names=fixed_keys,
                    confirmed_names=confirmed_keys,
                    context=context,
                )
            )

        protected_tokens = {
            token for name in roster for token in _normalize(name).split()
        }

        # Titles come last and are filtered against the people already found.
        # A title span is dropped by the profile filter, so one that swallowed
        # a name would take the name out of the redaction set with it and leak
        # it -- "Lala Maher head show" matched as a job title, and the surname
        # survived in plaintext.
        if self.use_titles:
            collected.extend(
                self._safe_titles(text, protected_tokens, model_spans)
            )

        collected.spans = self._clean(text, collected.spans, structure, context, protected_tokens)

        # First pass settles overlaps, then labels are made consistent and
        # every accepted term is swept across the whole document so no
        # occurrence is left behind by a detector that fired only once.
        first_pass = unify_labels(collected.resolve())
        collected.extend(propagate_terms(text, _sweep_terms(first_pass)))

        # The sweep mints spans that have never been through any filter.
        collected.spans = self._clean(text, collected.spans, structure, context, protected_tokens)

        # Type filtering happens last: voting sees every detection, then the
        # profile decides which of the agreed types are actually redacted.
        # Fixed names are caller-directed instructions and are always redacted
        # even if PERSON is turned off.
        unified = unify_labels(collected.resolve())
        unified = _demote_org_like_persons(unified, roster)
        unified = _mark_eponymous(unified)
        unified = _scope_norp(unified, context)
        candidates = [
            span for span in unified if span.label in self.redacted_types or span.forced
        ]

        candidates, uncorroborated = self._filter_persons(
            text, candidates, roster, email_names
        )
        resolved = assign_identities(text, candidates)
        resolved.sort(key=lambda span: span.start)

        vault = PseudonymVault()
        replacements = [
            (span, vault.escape_for(span) if span.label == ESCAPE_LABEL else vault.placeholder_for(span))
            for span in resolved
        ]
        sanitized = text if dry_run else dedupe_placeholders(apply_spans(text, replacements))

        audited_roster = roster if "PERSON" in self.redacted_types else self.fixed_names
        leaks = audit(sanitized, vault.all_surface_forms(), audited_roster, context)
        scoped_residual_policy = self.residual_policy.for_scope(self.redacted_types)
        result = AnonymizationResult(
            sanitized=sanitized,
            mapping=vault.mapping,
            spans=resolved,
            roster=roster,
            profile=self.profile,
            leaks=leaks,
            residual=scan_residual(
                sanitized,
                policy=scoped_residual_policy,
                key_zones=structure.key_zones,
                # Only HIGH findings dedupe. A value graded "low" -- an ordinary
                # word that happens to be somebody's name -- must not delete a
                # HIGH structural finding about the same text, which is how the
                # original false-clean worked.
                known_values=[
                    leak["value"] for leak in leaks if leak.get("severity") == "high"
                ],
            ),
            escapes=dict(vault.escapes),
            detector_status=self.describe_detectors(),
            uncorroborated=uncorroborated,
            structure=structure.summary(),
            dry_run=dry_run,
            policy=describe_policy(self.profile, self.entities, custom_labels=self._custom_labels),
        )
        if not dry_run:
            self._enforce(result)
        return result

    def anonymize(self, text: str, *, dry_run: bool = False) -> tuple[str, dict[str, str]]:
        """Return ``(sanitized_text, {placeholder: original})``."""
        return self.analyze(text, dry_run=dry_run).as_tuple()

    def restore(
        self,
        text: str,
        mapping: dict[str, str],
        escapes: Mapping[str, str] | None = None,
    ) -> str:
        """Replace placeholders in an LLM response with the original values."""
        return restore_text(text, mapping, escapes)

    def restore_for(self, text: str, result: AnonymizationResult) -> str:
        """Restore using a result object, so ``escapes`` cannot be forgotten."""
        return restore_text(text, result.mapping, result.escapes)

    # -- internals ---------------------------------------------------------

    def _template_literals(self, text: str) -> list[Span]:
        if self.escape_placeholders == "ignore":
            return []
        spans = find_template_literals(text)
        if spans and self.escape_placeholders == "reject":
            raise PlaceholderInjection(
                f"input contains {len(spans)} placeholder-shaped token(s); "
                "refusing under escape_placeholders='reject'"
            )
        return spans

    @staticmethod
    def _safe_titles(
        text: str,
        protected: set[str],
        model_spans: list[Span],
    ) -> list[Span]:
        """Title spans that cannot take somebody's name down with them.

        A title is detected only so it outranks ORG, and is then dropped
        unredacted. That makes an over-long title span actively dangerous: any
        name inside it leaves the redaction set too. So a candidate is rejected
        if it contains a known participant's name token, or overlaps a span the
        models already called a person.
        """
        people = [span for span in model_spans if span.label == "PERSON"]
        safe: list[Span] = []
        for span in detect_titles(text):
            tokens = set(_normalize(span.text).split())
            if tokens & protected:
                continue
            # Strict containment only. A title that merely coincides with a
            # PERSON span is correcting a misclassification ("CFO"), while one
            # that swallows a shorter name would take that name out of the
            # redaction set along with itself.
            if any(
                span.start <= person.start and person.end <= span.end
                and span.length > person.length
                for person in people
            ):
                continue
            safe.append(span)
        return safe

    def _tagger(self):
        """The spaCy pipeline, if one is loaded, for part-of-speech evidence."""
        for detector in self.detectors:
            if isinstance(detector, SpacyDetector):
                try:
                    return detector.nlp
                except Exception:
                    return None
        return None

    def _clean(
        self,
        text: str,
        spans: list[Span],
        structure: StructureMap,
        context: DocumentContext,
        protected: set[str],
    ) -> list[Span]:
        """Normalise edges, then apply the structural and allowlist filters.

        Edge normalisation runs first and runs on every pass: a span with a
        loose boundary poisons identity resolution downstream, so nothing is
        allowed to see a span before its edges are trustworthy.
        """
        spans = normalize_spans(text, spans, context)
        spans = protect_spans(text, spans, structure)
        spans = [span for span in spans if not is_protected_term(span.text)]
        return self._drop_allowlisted(spans, protected)

    def _filter_persons(
        self,
        text: str,
        spans: list[Span],
        roster: list[str],
        email_names: set[str],
    ) -> tuple[list[Span], list[dict]]:
        """Require corroboration before redacting a single-token person.

        Models label plenty of capitalised nouns PERSON -- Karolinska, FinCEN,
        ICH, Gmail, Oncology, PhD, Owner, Three. Every real person in these
        documents, by contrast, appears in full at least once, or after an
        honorific, or as a speaker, or inside an email address. Asking for one
        of those is a far better filter than a list of words, and it is the
        document that supplies the answer.
        """
        if self.person_evidence == "any":
            return spans, []

        known: set[str] = set()
        for name in [*roster, *email_names]:
            known.update(_normalize(name).split())
        for span in spans:
            if span.label == "PERSON" and len(span.text.split()) > 1:
                known.update(_normalize(strip_affixes(span.text)).split())

        kept: list[Span] = []
        dropped: list[dict] = []
        for span in spans:
            if span.label != "PERSON" or len(span.text.split()) > 1 or span.forced:
                kept.append(span)
                continue
            token = _normalize(strip_affixes(span.text))
            if token in known or has_honorific_prefix(text, span.start):
                kept.append(span)
                continue
            dropped.append(
                {
                    "value": span.text,
                    "line": text.count(chr(10), 0, span.start) + 1,
                    "reason": "single-token PERSON with no corroborating full name, "
                    "honorific, speaker line or email address",
                }
            )
        return kept, dropped

    def _drop_allowlisted(self, spans: list[Span], protected: set[str]) -> list[Span]:
        return [span for span in spans if not self._allowed(span, protected)]

    def _allowed(self, span: Span, protected: set[str]) -> bool:
        """True when the span names something that is not personal data.

        Pattern spans are never allowlisted, so allowlisting the word "mac"
        cannot suppress an actual MAC address value.
        """
        if span.source == "pattern":
            return False
        if _normalize(span.text) in protected:
            return False
        return is_non_personal(span.text, self.allowlist, protected=protected)

    def _enforce(self, result: AnonymizationResult) -> None:
        """One enforcement point, so no caller can forget to check.

        The previous design left this to callers, and the two entry points
        promptly diverged: one refused to send, the other printed a warning and
        sent anyway.
        """
        status = result.status
        if status == STATUS_FAILED:
            error: LeakDetected = LeakDetected(
                status=status,
                leaks=result.high_severity_leaks,
                residual=[
                    {"rule": f.rule, "severity": f.severity, "line": f.line}
                    for f in result.residual_high
                ],
                reason="PII survived redaction",
            )
        elif status == STATUS_REVIEW and self.strict:
            error = ReviewRequired(
                status=status,
                residual=[
                    {"rule": f.rule, "severity": f.severity, "line": f.line}
                    for f in result.residual_medium
                ],
                reason="unreviewed medium-confidence findings",
            )
        else:
            return

        if self.on_leak == "raise":
            raise error
        if self.on_leak == "warn":
            warnings.warn(str(error), LeakWarning, stacklevel=3)

    @staticmethod
    def _name_pool(
        roster: list[str],
        model_spans: list[Span],
        email_names: set[str] | None = None,
        *,
        protect: frozenset[str] = frozenset(),
    ) -> list[str]:
        """Roster names plus any full name the model found, for propagation."""
        names = list(roster)
        seen = {name.casefold() for name in names}
        for span in model_spans:
            if span.label != "PERSON":
                continue
            name = span.text.strip()
            if len(name.split()) < 2 or name.casefold() in seen:
                continue
            seen.add(name.casefold())
            names.append(name)
        for name in sorted(email_names or ()):
            if name.casefold() not in seen:
                seen.add(name.casefold())
                names.append(name)
        return _reconcile_names(names, protect=protect)


def assign_identities(text: str, spans: list[Span]) -> list[Span]:
    """Give every span the identity of the entity it refers to.

    Replaces keying on the exact matched string, which minted a new placeholder
    for each surface form and scattered one person across three ids.
    """
    index = EntityIndex()
    for span in spans:
        if span.source == "pattern":
            continue
        # Register every name, including those the roster already identified.
        # Skipping them left the index with no full names to own the short
        # forms, so "Mr. Smith" stopped linking to "John Smith" the moment the
        # roster started working.
        index.register(span.label, span.text)
    index.link_short_forms()
    index.link_acronyms(text)

    resolved: list[Span] = []
    for span in spans:
        if span.identity is not None or span.source == "pattern":
            resolved.append(span)
            continue
        resolved.append(
            Span(
                start=span.start,
                end=span.end,
                label=span.label,
                text=span.text,
                score=span.score,
                source=span.source,
                identity=index.resolve(span.label, span.text),
            )
        )
    return resolved


def _id_field_spans(text: str, context: DocumentContext) -> list[Span]:
    """Values of fields whose label names a record identifier."""
    return [
        Span(
            start=start,
            end=end,
            label="CUSTOM_ID",
            text=text[start:end],
            score=0.9,
            source="pattern",
        )
        for start, end in context.id_field_values
        if end > start
    ]


def _demote_org_like_persons(spans: list[Span], roster: list[str]) -> list[Span]:
    """Demote PERSON spans to ORG if they end in corporate nouns and aren't in the roster.

    Fixes D-12 ("TechNova Support" -> PERSON, "Tal Exampleco" -> PERSON).
    """

    corporate_endings = frozenset(
        {
            "support",
            "solutions",
            "systems",
            "services",
            "consulting",
            "technologies",
            "software",
            "analytics",
            "exampleco",
        }
        | CORPORATE_SUFFIXES
    )
    roster_tokens = {_normalize(tok) for name in roster for tok in name.split()}

    result: list[Span] = []
    for span in spans:
        if span.label == "PERSON" and not span.forced:
            tokens = span.text.strip().split()
            if tokens:
                last_token = tokens[-1].strip(".,;:").casefold()
                if last_token in corporate_endings:
                    span_tokens = {_normalize(tok) for tok in tokens}
                    if not (span_tokens & roster_tokens):
                        result.append(
                            Span(
                                start=span.start,
                                end=span.end,
                                label="ORG",
                                text=span.text,
                                score=span.score,
                                source=span.source,
                                identity=None,
                            )
                        )
                        continue
        result.append(span)
    return result


def _mark_eponymous(spans: list[Span]) -> list[Span]:
    """Relabel an organisation that carries a person's name.

    With ORG off by default, "{{PERSON_1}}, Esq. (Partner, Whitfield & Barnes)"
    prints the surname one token from its own placeholder, which defeats the
    redaction entirely. Law firms, medical practices and single-member
    companies are a large class, so this is not a corner case -- an ORG sharing
    a name token with a PERSON is always redacted, under its own placeholder so
    the structure does not leak either.
    """
    person_tokens: set[str] = set()
    for span in spans:
        if span.label != "PERSON":
            continue
        tokens = _normalize(strip_affixes(span.text)).split()
        # Single-token people are too weak a signal: one "Brown" would pull in
        # every organisation with "brown" in its name.
        if len(tokens) > 1:
            person_tokens.update(tokens)

    if not person_tokens:
        return spans

    marked: list[Span] = []
    for span in spans:
        if span.label in {"ORG", "LOCATION"} and person_tokens & set(
            _normalize(span.text).split()
        ):
            marked.append(
                Span(
                    start=span.start,
                    end=span.end,
                    label="EPONYMOUS_ORG",
                    text=span.text,
                    score=span.score,
                    source=span.source,
                    identity=None,
                )
            )
        else:
            marked.append(span)
    return marked


def _scope_norp(spans: list[Span], context: DocumentContext) -> list[Span]:
    """Keep NORP only where it actually describes people.

    Nationality, ethnicity and religion are special-category data, so NORP is
    redacted under every profile. But the tagger applies the label to any
    capitalised adjective, and redacting "the European market" or the banking
    product "Finacle" protects nobody while making the text unreadable.

    The discriminator is the noun it modifies: "a Cypriot national" and
    "Yoruba-speaking populations" are about people; "European market" is not.
    """
    # Decide once per surface form, not per occurrence. "Finacle, version
    # 10.2.18" releases on the following noun but "Finacle 11" does not, and
    # redacting one mention while printing the other is worse than either
    # choice made consistently -- the audit rightly reports it as a leak.
    # Digits or colons never belong in nationality or religion terms.
    released = {
        _normalize(span.text)
        for span in spans
        if span.label == "NORP"
        and (
            any(char.isdigit() for char in span.text)
            or ":" in span.text
            or context.releases_norp(span.start, span.end)
        )
    }
    return [
        span
        for span in spans
        if not (span.label == "NORP" and _normalize(span.text) in released)
    ]


def _address_field_spans(text: str, context: DocumentContext) -> list[Span]:
    """Whole value of an ``Address:`` field, in whatever language or format.

    A French address puts the street type first and a postcode last, so the
    English shape rule matched neither "12 Rue Victor Hugo" nor "75001". The
    field label says what the line is without anyone enumerating formats.
    """
    return [
        Span(
            start=start,
            end=end,
            label="ADDRESS",
            text=text[start:end],
            score=0.9,
            source="pattern",
        )
        for start, end in context.address_field_values
        if end > start
    ]


def _is_initial(token: str) -> bool:
    core = token.rstrip(".,;:")
    return len(core) == 1 and core.isalpha()


def _reconcile_names(names: list[str], *, protect: frozenset[str] = frozenset()) -> list[str]:
    """Drop short forms and initial variants when a unique full name covers them.

    A transcript that writes the full name once and the first name thereafter
    ("Sarah Jenkins:" then "Sarah:") puts only the short form in the roster,
    because the long form falls below the speaker-turn threshold. Propagating
    both then mints two identities for one person -- a two-person interview
    came out as four placeholders.

    Similarly, an initial-plus-surname variant ("J. Smith") proposed by a
    detector should defer to the full name ("John Smith") when there is an
    unambiguous owner in the document.

    Keeping only the full name is enough: ``name_variants`` already generates
    "Sarah" and "J. Smith" from "John Smith", and every occurrence inherits
    that one identity. Ambiguous tokens are left alone, so three colleagues
    sharing the first name "Ahmed" still get three placeholders.

    ``protect`` holds normalized fixed names: a caller who explicitly listed
    a bare first name meant for that surface to propagate on its own, so it
    survives reconciliation even when a full name would otherwise absorb it.
    """
    full_names = [name for name in names if len(name.split()) > 1]
    if not full_names:
        return names

    canonical_full_names = [
        name for name in full_names if not _is_initial(name.split()[0])
    ]

    owners: dict[str, set[str]] = {}
    for full_name in (canonical_full_names or full_names):
        for token in _normalize(full_name).split():
            if not _is_initial(token):
                owners.setdefault(token, set()).add(full_name)

    initial_owners: dict[tuple[str, str], set[str]] = {}
    for full_name in canonical_full_names:
        tokens = _normalize(full_name).split()
        if len(tokens) >= 2 and tokens[0]:
            initial = tokens[0][:1]
            surname = tokens[-1].rstrip(".,;:")
            initial_owners.setdefault((initial, surname), set()).add(full_name)

    kept: list[str] = []
    for name in names:
        key = _normalize(name)
        if key in protect:
            kept.append(name)
            continue
        tokens = key.split()
        if len(tokens) == 1 and len(owners.get(key, ())) == 1:
            continue
        if len(tokens) >= 2 and _is_initial(tokens[0]):
            initial = tokens[0][:1]
            surname = tokens[-1].rstrip(".,;:")
            if len(initial_owners.get((initial, surname), ())) == 1:
                continue
        kept.append(name)
    return kept


def unify_labels(spans: list[Span]) -> list[Span]:
    """Give every occurrence of the same surface form the same entity type.

    The model can tag "Lamya" as a person in one window and a location in the
    next, which would otherwise split one human across two placeholders. The
    label backed by the strongest evidence wins for all of them.
    """
    votes: dict[str, dict[str, float]] = {}
    for span in spans:
        key = _normalize(span.text)
        if not key:
            continue
        weight = SOURCE_PRIORITY.get(span.source, 0) + span.score
        if span.label == "PERSON":
            # Ties break toward PERSON on purpose. A person mislabelled as a
            # place escapes redaction under a person-focused profile, while a
            # place mislabelled as a person only costs a little context -- so
            # the two errors are not worth the same.
            weight += PERSON_BIAS
        by_label = votes.setdefault(key, {})
        by_label[span.label] = by_label.get(span.label, 0.0) + weight

    winners = {
        key: max(by_label.items(), key=lambda item: item[1])[0]
        for key, by_label in votes.items()
    }

    unified: list[Span] = []
    for span in spans:
        winner = winners.get(_normalize(span.text), span.label)
        if winner == span.label:
            unified.append(span)
            continue
        unified.append(
            Span(
                start=span.start,
                end=span.end,
                label=winner,
                text=span.text,
                score=span.score,
                source=span.source,
                # The old identity named the losing label, so drop it and let
                # identity linking rebuild it under the winning type.
                identity=None,
            )
        )
    return unified


def _sweep_terms(spans: list[Span]) -> list[PropagationTerm]:
    """Distinct terms worth matching again, one per surface/label pair."""
    terms: dict[tuple[str, str], PropagationTerm] = {}
    for span in spans:
        surface = span.text.strip()
        if span.source == "pattern" and span.label not in ("CUSTOM_ID", "ID", "JOB_ID"):
            continue
        if len(surface) < MIN_SWEEP_LENGTH:
            continue
        key = (_normalize(surface), span.label)
        if key not in terms:
            identity = span.identity or f"{span.label}:{_normalize(surface)}"
            terms[key] = PropagationTerm(surface, span.label, identity)

    # Skip a term whose surface is a strict prefix (token-wise) of another
    # surface already registered for the same identity (e.g. bare "Dear"
    # alongside "Dear Jennifer").
    filtered: list[PropagationTerm] = []
    for term in terms.values():
        term_toks = term.surface.lower().split()
        is_prefix = False
        for other in terms.values():
            if other is term or other.identity != term.identity:
                continue
            other_toks = other.surface.lower().split()
            if len(term_toks) < len(other_toks) and other_toks[:len(term_toks)] == term_toks:
                is_prefix = True
                break
        if not is_prefix:
            filtered.append(term)

    # Longest first, so the fullest form wins any overlap.
    return sorted(filtered, key=lambda item: len(item.surface), reverse=True)


def audit(
    sanitized: str,
    surface_forms: dict[str, set[str]],
    roster: list[str],
    context: DocumentContext | None = None,
) -> list[dict]:
    """Re-scan the sanitized text for values we know we detected.

    This is a completeness-of-application check: did everything we found
    actually get removed? It is blind by construction to anything never
    detected, which is what ``residual.scan_residual`` exists to cover.
    """
    leaks: list[dict] = []
    checked: set[str] = set()

    def check(value: str, origin: str) -> None:
        value = value.strip()
        key = value.casefold()
        if len(value) < MIN_AUDIT_LENGTH or key in checked:
            return
        checked.add(key)

        escaped = re.escape(value)
        exact = len(re.findall(rf"(?<!\w){escaped}(?!\w)", sanitized))
        any_case = len(re.findall(rf"(?<!\w){escaped}(?!\w)", sanitized, re.IGNORECASE))

        if exact:
            # The exact surface form survived: redaction genuinely failed.
            leaks.append(
                {"value": value, "occurrences": exact, "origin": origin, "severity": "high"}
            )
        elif any_case:
            # A differently-cased match remains. Whether that is a failure
            # depends on what the word is, not on how it is spelled.
            #
            # "low" exists so that redacting the name "Mark" does not make
            # every "mark" in the document a leak. But the same grade was
            # being given to "Kwame" matching "KWAME MENSAH", and because
            # is_clean ignores "low", two documents were stamped clean while a
            # participant's name sat in plaintext at every turn.
            #
            # The honest discriminator is whether the document itself uses the
            # word as an ordinary lowercase word. If it does not, a
            # case-variant survival is the entity, and that is a leak.
            ordinary_word = (
                len(value.split()) == 1
                and context is not None
                and context.appears_lowercase(value)
            )
            leaks.append(
                {
                    "value": value,
                    "occurrences": any_case,
                    "origin": origin,
                    "severity": "low" if ordinary_word else "high",
                }
            )

    for placeholder, forms in surface_forms.items():
        for form in forms:
            check(form, placeholder)

    for name in roster:
        check(name, "roster")
        for token in name.split():
            check(token, "roster")

    leaks.sort(key=lambda leak: (leak["severity"] == "high", leak["occurrences"]), reverse=True)
    return leaks
