"""Resolve surface forms to canonical entities.

Placeholders used to be keyed on the exact string a detector matched, so one
person collected several ids: "Samuel Adeyemi" was ``{{PERSON_1}}``,
``{{PERSON_9}}`` and ``{{PERSON_10}}``; "Ms. Whitfield" was a different person
from "Karen M. Whitfield"; "Verdant Holdings Ltd." and "Verdant Holdings" were
two companies. A reader -- or a summarising model -- cannot recover who is who
from that, and it is the redaction, not the document, that introduced the
confusion.

This module builds one entity per real-world referent and folds the variants
into it: honorifics, first-name and surname short forms, possessives, legal
suffixes and parenthetical acronyms.

The load-bearing constraint is the opposite one. Folding too eagerly destroys
data: a bad span once put "Oncology" and a doctor under one placeholder, and
only one of the two could be restored. Every merge below therefore requires an
*unambiguous* owner, and anything ambiguous keeps its own identity.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .policy import _normalize

# Titles that precede a name. Stripped for identity so "Dr. Adeyemi" and
# "Samuel Adeyemi" resolve to the same person.
HONORIFICS = frozenset(
    """
    mr mrs ms miss mx dr prof professor sir madam lord lady rev father sister
    capt captain col colonel gen general lt sgt hon judge justice eng
    """.split()
)

# Legal forms, so "Verdant Holdings Ltd." folds into "Verdant Holdings".
LEGAL_SUFFIXES = frozenset(
    """
    inc llc llp ltd plc gmbh ag nv bv srl spa oy ab pty corp corporation
    limited incorporated
    """.split()
)

# Post-nominals that are not part of a name.
POST_NOMINALS = frozenset(
    "md phd mba msc bsc ma ba jd llm rn do dds esq cpa cfa pe mph cfe "
    "jr sr ii iii iv v".split()
)

# "European Medicines Agency (EMA)" -- the bracketed acronym is the same thing.
ACRONYM_DEFINITION_RE = re.compile(
    r"(?P<full>(?:[A-Z][\w'’-]*[ \t]+){1,6}[A-Z][\w'’-]*)"
    r"[ \t]*\(\s*(?P<acronym>[A-Z][A-Z0-9&.-]{1,9})\s*\)"
)


def strip_affixes(name: str) -> str:
    """Remove honorifics, post-nominals and legal suffixes from a surface form."""
    tokens = [token for token in re.split(r"\s+", name.strip()) if token]
    while tokens and _bare(tokens[0]) in HONORIFICS:
        tokens.pop(0)
    while tokens and (
        _bare(tokens[-1]) in POST_NOMINALS or _bare(tokens[-1]) in LEGAL_SUFFIXES
    ):
        tokens.pop()
    if tokens:
        tokens[-1] = tokens[-1].rstrip(",;:.")
    return " ".join(token for token in tokens if token)


def _bare(token: str) -> str:
    return re.sub(r"[^\w]", "", token).casefold()


def _initial_only(token: str) -> bool:
    """True for a middle initial such as "M." in "Karen M. Whitfield"."""
    return len(_bare(token)) == 1


@dataclass
class Entity:
    """One real-world referent and every way this document names it."""

    label: str
    canonical: str
    key: str
    surfaces: set[str] = field(default_factory=set)

    def add(self, surface: str) -> None:
        self.surfaces.add(surface)
        if len(surface) > len(self.canonical):
            self.canonical = surface


class EntityIndex:
    """Maps surface forms onto canonical entities, conservatively."""

    def __init__(self) -> None:
        self._entities: dict[str, Entity] = {}
        self._alias: dict[tuple[str, str], str] = {}

    # -- construction ------------------------------------------------------

    def register(self, label: str, surface: str) -> str:
        """Record a surface form and return the key of its entity."""
        core = strip_affixes(surface) or surface.strip()
        key = f"{label}:{_normalize(core)}"
        entity = self._entities.get(key)
        if entity is None:
            entity = Entity(label=label, canonical=core, key=key)
            self._entities[key] = entity
        entity.add(surface)
        self._alias[(label, _normalize(surface))] = key
        self._alias[(label, _normalize(core))] = key
        return key

    def resolve(self, label: str, surface: str) -> str:
        """Key for a surface form, falling back to registering it."""
        for candidate in (surface, strip_affixes(surface)):
            key = self._alias.get((label, _normalize(candidate)))
            if key is not None:
                return key
        return self.register(label, surface)

    # -- merging -----------------------------------------------------------

    def link_short_forms(self) -> None:
        """Fold single-token forms into the one full name that contains them.

        "Adeyemi" joins "Samuel Adeyemi" because exactly one full name owns
        that token. "Ahmed" joins nothing, because Farid, Maher and Hamed all
        answer to it and picking one would merge three colleagues into one.
        """
        for label in {entity.label for entity in self._entities.values()}:
            full_names = {
                key: entity
                for key, entity in self._entities.items()
                if entity.label == label and len(entity.key.split(":", 1)[1].split()) > 1
            }
            owners: dict[str, set[str]] = {}
            for key, entity in full_names.items():
                for token in entity.key.split(":", 1)[1].split():
                    if _initial_only(token):
                        continue
                    owners.setdefault(token, set()).add(key)

            for key, entity in list(self._entities.items()):
                if entity.label != label or key in full_names:
                    continue
                tokens = key.split(":", 1)[1].split()
                if len(tokens) != 1:
                    continue
                candidates = owners.get(tokens[0], set())
                if len(candidates) == 1:
                    self._merge(key, next(iter(candidates)))

            # "Blue Harbor" and "Blue Harbor Consulting Inc." are one company.
            # Requires a unique owner, so a shared prefix across two distinct
            # entities leaves both alone.
            for key, entity in list(self._entities.items()):
                if entity.label != label or key not in self._entities:
                    continue
                name = key.split(":", 1)[1]
                if len(name.split()) < 2:
                    continue
                longer = [
                    other
                    for other in full_names
                    if other in self._entities
                    and other != key
                    and other.split(":", 1)[1].startswith(name + " ")
                ]
                if len(longer) == 1:
                    self._merge(key, longer[0])

    def link_acronyms(self, text: str) -> None:
        """Fold "EMA" into "European Medicines Agency (EMA)".

        Without this, the expansion is masked and the acronym survives beside
        it -- which is how "LUTH" stayed in plaintext next to a redacted
        "Lagos University Teaching Hospital".
        """
        for match in ACRONYM_DEFINITION_RE.finditer(text):
            full = _normalize(strip_affixes(match.group("full")))
            acronym = _normalize(match.group("acronym"))
            for label in {entity.label for entity in self._entities.values()}:
                full_key = self._alias.get((label, full))
                if full_key is None:
                    continue
                acronym_key = self._alias.get((label, acronym))
                if acronym_key is None:
                    self._alias[(label, acronym)] = full_key
                    self._entities[full_key].add(match.group("acronym"))
                elif acronym_key != full_key:
                    self._merge(acronym_key, full_key)

    def _merge(self, source_key: str, target_key: str) -> None:
        source = self._entities.pop(source_key, None)
        target = self._entities.get(target_key)
        if source is None or target is None:
            return
        for surface in source.surfaces:
            target.add(surface)
            self._alias[(target.label, _normalize(surface))] = target_key
        self._alias[(source.label, source_key.split(":", 1)[1])] = target_key
        for alias, key in list(self._alias.items()):
            if key == source_key:
                self._alias[alias] = target_key

    # -- queries -----------------------------------------------------------

    def entity(self, key: str) -> Entity | None:
        return self._entities.get(key)

    def aliases_of(self, key: str) -> set[str]:
        entity = self._entities.get(key)
        return set(entity.surfaces) if entity else set()

    def __len__(self) -> int:
        return len(self._entities)


# --------------------------------------------------------------------------
# Corroboration
# --------------------------------------------------------------------------

HONORIFIC_PREFIX_RE = re.compile(
    r"(?:" + "|".join(sorted(HONORIFICS, key=len, reverse=True)) + r")\.?[ \t]+$",
    re.IGNORECASE,
)

# Name-shaped tokens inside an email local part: david.lee@ -> {david, lee}.
EMAIL_LOCAL_RE = re.compile(r"[^\W\d_]{3,}")


def names_from_emails(text: str, email_pattern: re.Pattern[str]) -> set[str]:
    """Mine given names and surnames out of email addresses.

    "Hi David," went unredacted in a thread addressed to
    david.lee@example.org. The address is already being masked, so the name
    inside it is known PII and costs nothing to learn.
    """
    names: set[str] = set()
    for match in email_pattern.finditer(text):
        local = match.group().split("@", 1)[0]
        for token in EMAIL_LOCAL_RE.findall(local):
            if len(token) >= 3:
                names.add(token.capitalize())
    return names


def has_honorific_prefix(text: str, start: int) -> bool:
    return HONORIFIC_PREFIX_RE.search(text[max(0, start - 24) : start]) is not None


def resolve_aliases(text: str, entities: list[Entity]) -> dict[str, str]:
    """Return conservative surface-form to placeholder aliases.

    This helper mirrors the middleware's identity rules for callers that need
    an alias map before substitution. Ambiguous aliases are left with the
    first canonical owner only when the text supplies an honorific tied to a
    full name; shared bare surnames are intentionally omitted.
    """
    counters: dict[str, int] = {}
    result: dict[str, str] = {}
    surname_owners: dict[str, set[str]] = {}
    for entity in entities:
        surname = strip_affixes(entity.canonical).split()[-1]
        surname_owners.setdefault(_normalize(surname), set()).add(entity.key)

    for entity in entities:
        label = entity.label
        counters[label] = counters.get(label, 0) + 1
        placeholder = f"{{{{{label}_{counters[label]}}}}}"
        aliases = set(entity.surfaces) | name_variants(entity.canonical)
        surname = strip_affixes(entity.canonical).split()[-1]
        if len(surname_owners.get(_normalize(surname), set())) == 1:
            aliases.add(surname)
        for title in ("Mr.", "Ms.", "Mrs.", "Dr."):
            full = re.search(
                rf"(?i)(?<!\w){re.escape(title.rstrip('.'))}\.?[ \t]+"
                rf"{re.escape(entity.canonical)}(?!\w)", text
            )
            if full:
                aliases.add(f"{title} {surname}")
        for alias in aliases:
            if alias:
                result.setdefault(alias, placeholder)
    return result
