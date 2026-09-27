"""Orchestration: detect, pseudonymize, verify, restore."""

from __future__ import annotations

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
from .patterns import EMAIL_PATTERN, MIN_PATTERN_SCORE, PatternRule, detect_patterns
from .policy import (
    DEFAULT_ALLOWLIST,
    DEFAULT_PROFILE,
    NO_REDACT_TYPES,
    _normalize,
    allowlist_tokens,
    is_allowlisted,
    is_non_personal,
    is_technical_acronym,
    is_protected_term,
    resolve_types,
)
from .residual import DEFAULT_RESIDUAL_POLICY, Finding, ResidualPolicy, scan_residual
from .roster import extract_roster, propagate_names, propagate_terms
from .spacy_detector import SpacyDetector
from .spanfix import normalize_spans
from .spans import SOURCE_PRIORITY, Span, SpanSet, apply_spans
from .structure import StructureMap, analyze_structure, protect_spans
from .titles import detect_titles
from .vault import ESCAPE_LABEL, PseudonymVault, find_template_literals
from .vault import restore as restore_text

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
    r"(?:[ \t\r\n]*\1)+"
)


def dedupe_placeholders(text: str) -> str:
    """Collapse adjacent duplicate placeholders produced by overlapping spans."""
    return _PLACEHOLDER_SEQUENCE_RE.sub(r"\g<placeholder>", text)


def validate_output(original: str, redacted: str) -> bool:
    """Validate structural preservation and reject obvious residual secrets."""
    from .policy import PROTECTED_TERMS

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

    def as_tuple(self) -> tuple[str, dict[str, str]]:
        return self.sanitized, self.mapping


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
    """

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        labels: tuple[str, ...] = DEFAULT_LABELS,
        threshold: float = DEFAULT_THRESHOLD,
        window_chars: int = 1200,
        overlap_chars: int = 250,
        use_roster: bool = True,
        use_spacy: bool = True,
        use_titles: bool = True,
        profile: str = DEFAULT_PROFILE,
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
        self.allowlist = allowlist_tokens(allowlist)
        self.use_roster = use_roster
        self.use_titles = use_titles
        self.on_leak = on_leak
        self.strict = strict
        self.escape_placeholders = escape_placeholders
        self.person_evidence = person_evidence
        self.residual_policy = residual_policy

        config = load_config(patterns_config)
        self.pattern_rules: tuple[PatternRule, ...] = build_rules(config)
        self.min_pattern_score = config.min_score

        # Custom labels must be added explicitly. Without this a rule loaded
        # from TOML would be detected and then silently discarded by the
        # profile filter -- the easiest way to ship this feature broken.
        # Custom labels from TOML are redacted by construction, otherwise a
        # rule would be detected and then silently discarded. NO_REDACT_TYPES
        # are excluded: DATE and the title types exist to win an overlap
        # against a type that *is* redacted, then to be dropped.
        custom_labels = {rule.label for rule in config.rules}
        self.redacted_types = (resolve_types(profile) | custom_labels) - NO_REDACT_TYPES

        if detectors is None:
            detectors = [
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
                    detectors.append(spacy_detector)

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
            {"name": type(detector).__name__, "available": True}
            for detector in self.detectors
        ]
        if "SpacyDetector" not in names:
            status.append(
                {
                    "name": "SpacyDetector",
                    "available": False,
                    "reason": "model not installed; recall is reduced",
                }
            )
        return status

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

        roster: list[str] = []
        if self.use_roster:
            roster = extract_roster(text)
            names = self._name_pool(roster, model_spans, email_names)
            collected.extend(propagate_names(text, names))

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
        unified = unify_labels(collected.resolve())
        unified = _mark_eponymous(unified)
        unified = _scope_norp(unified, context)
        candidates = [span for span in unified if span.label in self.redacted_types]

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

        leaks = audit(sanitized, vault.all_surface_forms(), roster, context)
        result = AnonymizationResult(
            sanitized=sanitized,
            mapping=vault.mapping,
            spans=resolved,
            roster=roster,
            profile=self.profile,
            leaks=leaks,
            residual=scan_residual(
                sanitized,
                policy=self.residual_policy,
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
            if span.label != "PERSON" or len(span.text.split()) > 1:
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
        return _reconcile_names(names)


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
    released = {
        _normalize(span.text)
        for span in spans
        if span.label == "NORP" and context.releases_norp(span.start, span.end)
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


def _reconcile_names(names: list[str]) -> list[str]:
    """Drop a bare first name when exactly one full name already covers it.

    A transcript that writes the full name once and the first name thereafter
    ("Sarah Jenkins:" then "Sarah:") puts only the short form in the roster,
    because the long form falls below the speaker-turn threshold. Propagating
    both then mints two identities for one person -- a two-person interview
    came out as four placeholders.

    Keeping only the full name is enough: ``name_variants`` already generates
    "Sarah" from "Sarah Jenkins", and every occurrence inherits that one
    identity. Ambiguous tokens are left alone, so three colleagues sharing the
    first name "Ahmed" still get three placeholders.
    """
    full_names = [name for name in names if len(name.split()) > 1]
    if not full_names:
        return names

    owners: dict[str, set[str]] = {}
    for full_name in full_names:
        for token in _normalize(full_name).split():
            owners.setdefault(token, set()).add(full_name)

    kept: list[str] = []
    for name in names:
        key = _normalize(name)
        if len(key.split()) == 1 and len(owners.get(key, ())) == 1:
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


def _sweep_terms(spans: list[Span]) -> list[tuple[str, str, str]]:
    """Distinct ``(surface, label, identity)`` triples worth matching again."""
    terms: dict[tuple[str, str], tuple[str, str, str]] = {}
    for span in spans:
        surface = span.text.strip()
        if span.source == "pattern" or len(surface) < MIN_SWEEP_LENGTH:
            continue
        key = (_normalize(surface), span.label)
        if key not in terms:
            identity = span.identity or f"{span.label}:{_normalize(surface)}"
            terms[key] = (surface, span.label, identity)

    # Longest first, so the fullest form wins any overlap.
    return sorted(terms.values(), key=lambda item: len(item[0]), reverse=True)


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
