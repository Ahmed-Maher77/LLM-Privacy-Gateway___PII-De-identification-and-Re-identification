"""Stable pseudonym assignment, tolerant restoration, and injection defence."""

from __future__ import annotations

import re
from collections.abc import Mapping

from .policy import _normalize
from .spans import Span

# Doubled braces read as a template to every LLM and survive markdown
# rendering, unlike ``<PER_1>`` which chat models happily eat as an HTML tag.
PLACEHOLDER_RE = re.compile(r"\{\{\s*(?P<label>[A-Z][A-Z0-9_]*?)_(?P<index>\d+)\s*\}\}")

# Kept for callers that imported it. Restoration no longer uses it: matching
# "any uppercase token plus digits in almost any bracket" also matches XML
# (<SECTION_1>), config templates (${DB_1}) and form scaffolds ([SSN_1]) that
# a model may legitimately emit. See restore_pattern().
LOOSE_PLACEHOLDER_RE = re.compile(
    r"(?:\{\{|\[\[|\{|\[|<)\s*(?P<label>[A-Z][A-Z0-9_]*?)[_\s](?P<index>\d+)\s*(?:\}\}|\]\]|\}|\]|>)"
)

# What we hunt for in the INPUT. Deliberately wider than what we restore:
# for a defence you want maximum recall, so this also covers ${...} and %{...}
# and lowercase labels.
INPUT_TEMPLATE_RE = re.compile(
    r"(?:\{\{|\[\[|\{|\[|<|%\{|\$\{)\s*"
    r"(?P<label>[A-Za-z][A-Za-z0-9_]*)[\s_-]*(?P<index>\d+)\s*"
    r"(?:\}\}|\]\]|\}|\]|>)"
)

ESCAPE_LABEL = "PLACEHOLDER_LITERAL"

# Lowercase and parenthesised on purpose. Neither PLACEHOLDER_RE nor
# LOOSE_PLACEHOLDER_RE can match this shape, because both require an uppercase
# run immediately before the index -- so even if a model re-brackets it as
# {{redacted-template-token-3}} it still cannot be restored into a real name.
ESCAPE_TEMPLATE = "(literal-template-{index})"


_LAYOUT_GAP_RE = re.compile("[ \t]{2,}|\n")
_WHITESPACE_RE = re.compile(r"\s+")


def _canonical_rank(surface: str) -> tuple:
    """Order surface forms by how well they represent the entity."""
    tokens = surface.split()
    return (
        _LAYOUT_GAP_RE.search(surface) is None,  # not a column-spanning span
        1 <= len(tokens) <= 4,                   # a name, not a clause
        # Prefer the mixed-case form. Ranking by length alone let the shouted
        # speaker label "MARGARET O'SULLIVAN" outrank "Margaret O'Sullivan",
        # so restoration shouted every mention of that person.
        any(char.islower() for char in surface),
        len(surface),
    )


def format_placeholder(label: str, index: int) -> str:
    return f"{{{{{label}_{index}}}}}"


def find_template_literals(text: str) -> list[Span]:
    """Locate placeholder-shaped text in the *input*.

    Without this, a document containing the literal ``{{PERSON_1}}`` passes
    straight through anonymization, and ``restore()`` then splices a real
    person's name into attacker-chosen context -- inside a markdown link, say,
    which turns re-identification into exfiltration the moment it is rendered.

    Emitted as ordinary spans with ``source="pattern"`` so the existing
    resolver handles them: pattern spans are authoritative, so no longer model
    span can shadow the escape, and no offset arithmetic is needed.
    """
    protected_labels = {"page", "pages", "job", "exhibit", "case", "csr"}
    return [
        Span(
            start=match.start(),
            end=match.end(),
            label=ESCAPE_LABEL,
            text=match.group(),
            score=1.0,
            source="pattern",
        )
        for match in INPUT_TEMPLATE_RE.finditer(text)
        if match.group("label").casefold() not in protected_labels
    ]


class PseudonymVault:
    """Hands out one placeholder per real-world entity and maps back again."""

    def __init__(self) -> None:
        self._by_identity: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        # Placeholder -> the fullest surface form we saw for that entity.
        self.mapping: dict[str, str] = {}
        self._surface_forms: dict[str, set[str]] = {}
        # Sentinel -> the neutralized literal. Deliberately separate from
        # `mapping`: keeping them apart is what makes a sentinel unreachable
        # through the placeholder substitution path.
        self.escapes: dict[str, str] = {}
        self._escape_index: dict[str, str] = {}

    def identity_of(self, span: Span) -> str:
        return span.identity or f"{span.label}:{_normalize(span.text) or span.text}"

    def placeholder_for(self, span: Span) -> str:
        identity = self.identity_of(span)
        placeholder = self._by_identity.get(identity)

        if placeholder is None:
            index = self._counters[span.label] = self._counters.get(span.label, 0) + 1
            placeholder = format_placeholder(span.label, index)
            self._by_identity[identity] = placeholder
            self.mapping[placeholder] = _WHITESPACE_RE.sub(" ", span.text)
            self._surface_forms[placeholder] = set()

        # A name wrapped across a line is one name. Storing the break would
        # splice it into the middle of a restored sentence.
        surface = _WHITESPACE_RE.sub(" ", span.text)
        self._surface_forms[placeholder].add(surface)
        # Rank by well-formedness, not by length. Longest-wins is precisely why
        # a loose span became unrecoverable data loss: "Samuel Adeyemi
        # <7 spaces> Oncology" outranked "Samuel Adeyemi", and restoring the
        # other site then emitted a person's name where only a specialty
        # belonged. Even if every earlier guard fails, this keeps the restore
        # correct.
        if _canonical_rank(surface) > _canonical_rank(self.mapping[placeholder]):
            self.mapping[placeholder] = surface

        return placeholder

    def escape_for(self, span: Span) -> str:
        """Return a stable inert sentinel for a placeholder-shaped literal."""
        literal = span.text
        sentinel = self._escape_index.get(literal)
        if sentinel is None:
            sentinel = ESCAPE_TEMPLATE.format(index=len(self._escape_index) + 1)
            self._escape_index[literal] = sentinel
            self.escapes[sentinel] = literal
        return sentinel

    def surface_forms(self, placeholder: str) -> set[str]:
        return self._surface_forms.get(placeholder, set())

    def all_surface_forms(self) -> dict[str, set[str]]:
        return dict(self._surface_forms)


def link_person_identities(spans: list[Span]) -> list[Span]:
    """Fold partial person names onto the full name when it is unambiguous.

    "Farid" becomes the same entity as "Ahmed Farid" -- but "Ahmed" stays
    separate, because Farid, Maher and Hamed all share it and guessing would
    merge three different people into one.
    """
    full_names: dict[str, list[str]] = {}
    for span in spans:
        if span.label != "PERSON" or span.identity:
            continue
        tokens = _normalize(span.text).split()
        if len(tokens) > 1:
            full_names.setdefault(" ".join(tokens), []).extend(tokens)

    # token -> the full names containing it; only a unique owner may claim it.
    owners: dict[str, set[str]] = {}
    for full_name, tokens in full_names.items():
        for token in tokens:
            owners.setdefault(token, set()).add(full_name)

    linked: list[Span] = []
    for span in spans:
        if span.label != "PERSON" or span.identity:
            linked.append(span)
            continue

        key = _normalize(span.text)
        tokens = key.split()
        target = key
        if key in full_names:
            target = key
        elif len(tokens) == 1:
            candidates = owners.get(key, set())
            if len(candidates) == 1:
                target = next(iter(candidates))

        linked.append(
            Span(
                start=span.start,
                end=span.end,
                label=span.label,
                text=span.text,
                score=span.score,
                source=span.source,
                identity=f"PERSON:{target}",
            )
        )

    return linked


def restore_pattern(mapping: Mapping[str, str]) -> re.Pattern[str]:
    """Build a matcher for only the placeholders this run actually minted.

    Tolerant of the brackets an LLM might reformat to, but restricted to the
    handful of (label, index) pairs in ``mapping``. That shrinks the matchable
    surface from "any uppercase token beside a digit" -- which occurs naturally
    in XML, config templates and log format strings -- to exactly what we
    issued.
    """
    pairs: set[tuple[str, str]] = set()
    for placeholder in mapping:
        match = PLACEHOLDER_RE.fullmatch(placeholder.strip())
        if match:
            pairs.add((match.group("label"), match.group("index")))

    if not pairs:
        # A pattern that cannot match anything, rather than one that matches
        # everything.
        return re.compile(r"(?!x)x")

    alternation = "|".join(
        sorted((rf"{re.escape(label)}[_\s]{re.escape(index)}" for label, index in pairs),
               key=len, reverse=True)
    )
    return re.compile(
        rf"(?P<open>\{{\{{|\[\[|\{{|\[|<)\s*(?P<body>{alternation})\s*"
        rf"(?P<close>\}}\}}|\]\]|\}}|\]|>)"
    )


_BRACKET_PAIRS = {"{{": "}}", "[[": "]]", "{": "}", "[": "]", "<": ">"}


def restore(
    text: str,
    mapping: dict[str, str],
    escapes: Mapping[str, str] | None = None,
) -> str:
    """Swap placeholders back for their original values.

    Placeholders first, sentinels second. **The order is the security
    property**: restoring a neutralized ``{{PERSON_1}}`` literal before the
    placeholder pass would hand an attacker exactly the substitution the
    escape exists to prevent.

    The restored text is *untrusted*. Escaping the input removes the forgery
    vector, but a prompt-injected model can still be steered into emitting a
    legitimate placeholder inside an attacker-chosen URL, so callers must not
    auto-render links or auto-execute anything from this output.
    """
    lookup: dict[tuple[str, str], str] = {}
    for placeholder, original in mapping.items():
        match = PLACEHOLDER_RE.fullmatch(placeholder.strip())
        if match:
            lookup[(match.group("label"), match.group("index"))] = original

    def substitute(match: re.Match[str]) -> str:
        # Mismatched brackets ("{PERSON_1]") are not a placeholder we wrote.
        if _BRACKET_PAIRS.get(match.group("open")) != match.group("close"):
            return match.group()
        label, _, index = match.group("body").replace(" ", "_").rpartition("_")
        return lookup.get((label, index), match.group())

    out = restore_pattern(mapping).sub(substitute, text)

    for sentinel, literal in (escapes or {}).items():
        out = out.replace(sentinel, literal)
    return out
