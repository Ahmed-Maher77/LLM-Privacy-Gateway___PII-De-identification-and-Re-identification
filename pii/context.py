"""Evidence computed about the document being redacted.

The previous design decided what was a name by asking whether a word appeared
in one of seven hand-written lists. Those lists reached 480 entries and still
failed on every unseen document, because vocabulary is open and lists are not.

This module computes the same judgements from the document itself plus the
models already loaded, so nothing has to be enumerated in advance:

* ``appears_lowercase`` -- "Content", "Composer" and "Business" are ordinary
  words in a document that also writes them in lower case.
* ``pos_at`` -- part of speech, so "Three workers" (NUM + NOUN) is not a name
  while "Sarah Mitchell" (PROPN + PROPN) is.
* ``is_field_label`` -- "Owner:" and "Court Reporter:" are form fields, not
  people, and their position says so.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import cached_property

# "Owner:", "Court Reporter:", "Document Ref:" -- a short title-case run at the
# start of a line, followed by a colon. The label names the field; it is never
# the data.
FIELD_LABEL_RE = re.compile(
    r"^[ \t]*(?P<label>[A-Z][A-Za-z]*(?:[ \t]+[A-Z][A-Za-z]*){0,3})[ \t]*:(?![\d/])",
    re.MULTILINE,
)

# Labels whose *value* is a record identifier whatever shape it happens to take.
# This is what catches "Matter No: 2024-AML-0876" and
# "Session ID: REC-2023-11-14-0092", which no digit-shape regex caught.
ID_LABEL_RE = re.compile(
    r"(?i)\b(?:id|ids|ref|reference|no|number|matter|case|session|ticket|"
    r"record|file|docket|claim|policy|account)\b"
)

# Field labels whose value is a postal address, across the languages these
# documents actually appear in.
ADDRESS_LABEL_RE = re.compile(
    r"(?i)\b(?:address|addr|adresse|adres|direcci|indirizzo|anschrift|"
    r"endere|endereco|postal|residence)"
)

# Nouns that make a nationality, ethnicity or religion describe a PERSON
# rather than a market, a product or a region. "a Cypriot national" is special
# -category data; "the European market" is not, and neither is the banking
# product "Finacle" that a model mislabelled NORP three times.
# Nouns a nationality can modify **without** the phrase being about people.
#
# This list decides when to *release* protected data, so it is deliberately
# the small side of the judgement. Listing person nouns instead was a mistake:
# any construction I failed to think of -- "She is Cypriot", "Rohingya
# refugees", "Nationality: Nigerian" -- silently printed special-category data.
# Enumerating the safe cases fails closed; enumerating the unsafe ones fails
# open, and only one of those is acceptable for Article 9 data.
NON_PERSON_NOUN_RE = re.compile(
    r"(?i)^[\s\-,;:]*(?:\w+[\s\-]+){0,1}(?:market|markets|version|versions|edition|"
    r"region|regions|standard|standards|cuisine|union|language|languages|"
    r"continent|economy|economies|subsidiary|headquarters|office|offices|"
    r"operation|operations|division|division|branch|branches|timezone|"
    r"currency|currencies|law|laws|regulation|regulations)\b"
)

_WORD_RE = re.compile(r"[^\W\d_][\w'’-]*")

# Adjacency that marks a token as part of an identifier, not prose.
_IDENTIFIER_CHARS = frozenset("@._-/+:\\")

# Parts of speech that cannot carry a proper name on their own.
# Mean value length above which a "Label:" is prose (a speaker turn),
# not a form field.
MAX_FIELD_VALUE_CHARS = 48


def _mean(values: list[int]) -> float:
    return sum(values) / len(values) if values else 0.0


NON_NAME_POS = frozenset({"NOUN", "NUM", "ADJ", "VERB", "ADV", "ADP", "DET", "PRON", "AUX"})


@dataclass
class DocumentContext:
    """Per-document evidence, built once and shared by every downstream rule."""

    text: str
    _pos: dict[int, str] = field(default_factory=dict, repr=False)
    _has_pos: bool = False

    @classmethod
    def build(cls, text: str, nlp=None) -> DocumentContext:
        """Compute the context, degrading gracefully without spaCy.

        The tagger is cheap -- the parser and NER are disabled -- so this is a
        fraction of the cost of the detection passes it informs.
        """
        context = cls(text=text)
        if nlp is None:
            return context
        try:
            for chunk_start in range(0, len(text), 90_000):
                chunk = text[chunk_start : chunk_start + 90_000]
                for token in nlp(chunk):
                    context._pos[chunk_start + token.idx] = token.pos_
            context._has_pos = True
        except Exception:
            # POS is an enhancement. Losing it must not stop a redaction.
            context._pos.clear()
            context._has_pos = False
        return context

    # -- lexical evidence --------------------------------------------------

    @cached_property
    def _lowercase_words(self) -> frozenset[str]:
        """Words this document writes in lower case **in prose**.

        Occurrences inside an identifier do not count. "elena" appears in
        lower case in elena.rossi@example.net, and taking that as evidence
        that "Elena" is an ordinary word stopped a real name being redacted.
        """
        words: set[str] = set()
        for match in _WORD_RE.finditer(self.text):
            if not match.group()[:1].islower():
                continue
            before = self.text[match.start() - 1] if match.start() else " "
            after = self.text[match.end()] if match.end() < len(self.text) else " "
            if before in _IDENTIFIER_CHARS or after in _IDENTIFIER_CHARS:
                continue
            words.add(match.group().casefold())
        return frozenset(words)

    @cached_property
    def _titlecase_words(self) -> frozenset[str]:
        """Words this document also writes in Title Case.

        The counterpart to ``appears_lowercase``, and the evidence that tells
        a surname from an acronym without a list. "KWAME" is a name because
        the header says "Kwame Mensah"; "PCI" is not, because the document
        never writes "Pci".
        """
        return frozenset(
            match.group().casefold()
            for match in _WORD_RE.finditer(self.text)
            if len(match.group()) > 1
            and match.group()[0].isupper()
            and any(char.islower() for char in match.group()[1:])
        )

    def appears_titlecased(self, word: str) -> bool:
        return word.casefold() in self._titlecase_words

    def line_is_uncased(self, offset: int) -> bool:
        """True when the line holding ``offset`` has no lowercase letter.

        Casing cannot be evidence of anything in an all-caps line, so the
        acronym test has to stand down there.
        """
        start = self.text.rfind("\n", 0, offset) + 1
        end = self.text.find("\n", offset)
        line = self.text[start : len(self.text) if end == -1 else end]
        return not any(char.islower() for char in line)

    def appears_lowercase(self, word: str) -> bool:
        """True when this document also writes the word in lower case.

        Document-internal evidence beats any dictionary: if the text says
        "inline proxies" somewhere, then "Inline" at the start of a sentence is
        the same ordinary word, whatever a model called it.
        """
        return word.casefold() in self._lowercase_words

    # -- grammatical evidence ----------------------------------------------

    @property
    def has_pos(self) -> bool:
        return self._has_pos

    def pos_at(self, offset: int) -> str | None:
        return self._pos.get(offset)

    def looks_like_name(self, start: int, end: int) -> bool | None:
        """Whether the tagger considers this span proper-noun-like.

        Returns None when tags are unavailable, so callers can tell "no
        evidence" apart from "evidence against".
        """
        if not self._has_pos:
            return None
        tags = [
            tag
            for offset, tag in self._pos.items()
            if start <= offset < end and tag not in {"PUNCT", "SPACE"}
        ]
        if not tags:
            return None
        return any(tag == "PROPN" for tag in tags)

    # -- structural evidence -----------------------------------------------

    @cached_property
    def field_labels(self) -> tuple[tuple[int, int], ...]:
        """Character ranges of every ``Label:`` key at the start of a line.

        "Owner:" and "Sarah Jenkins:" are the same shape, so shape cannot tell
        them apart -- and reading a speaker label as a form field deletes the
        person at every turn of the transcript, which is the highest-value PII
        position in the document.

        What separates them is the value: a form field holds a short value on
        the same line, a speaker label is followed by a sentence. Averaged over
        every occurrence of the label, that is a reliable and computed
        distinction requiring no list of field names.
        """
        remainders: dict[str, list[int]] = {}
        matches = list(FIELD_LABEL_RE.finditer(self.text))
        for match in matches:
            line_end = self.text.find(chr(10), match.end())
            line_end = len(self.text) if line_end == -1 else line_end
            remainders.setdefault(match.group("label").casefold(), []).append(
                len(self.text[match.end() : line_end].strip())
            )

        return tuple(
            (match.start("label"), match.end("label"))
            for match in matches
            if _mean(remainders[match.group("label").casefold()]) <= MAX_FIELD_VALUE_CHARS
        )

    @cached_property
    def id_field_values(self) -> tuple[tuple[int, int], ...]:
        """Value ranges of labels that name a record identifier."""
        values: list[tuple[int, int]] = []
        for match in FIELD_LABEL_RE.finditer(self.text):
            if not ID_LABEL_RE.search(match.group("label")):
                continue
            line_end = self.text.find("\n", match.end())
            line_end = len(self.text) if line_end == -1 else line_end
            value = self.text[match.end() : line_end]
            stripped = value.strip()
            if not stripped or len(stripped) > 64:
                continue
            start = match.end() + (len(value) - len(value.lstrip()))
            values.append((start, start + len(stripped)))
        return tuple(values)

    @cached_property
    def address_field_values(self) -> tuple[tuple[int, int], ...]:
        """Value ranges of fields whose label names a postal address."""
        values: list[tuple[int, int]] = []
        for match in FIELD_LABEL_RE.finditer(self.text):
            if not ADDRESS_LABEL_RE.search(match.group("label")):
                continue
            line_end = self.text.find(chr(10), match.end())
            line_end = len(self.text) if line_end == -1 else line_end
            value = self.text[match.end() : line_end]
            stripped = value.strip()
            if not stripped or len(stripped) > 160:
                continue
            start = match.end() + (len(value) - len(value.lstrip()))
            values.append((start, start + len(stripped)))
        return tuple(values)

    def releases_norp(self, start: int, end: int, window: int = 40) -> bool:
        """Is there positive evidence this NORP mention is *not* about people?

        There is exactly one way to earn release: the mention modifies a noun
        that cannot be a person -- "the European market", "Finacle, version
        10.2.18". Everything else stays redacted.

        A part-of-speech test was tried here and removed: spaCy tags demonyms
        as proper nouns, so "Rohingya refugees" and "Nationality: Nigerian"
        were released as if they were product names. For Article 9 data the
        only safe default is that an unrecognised construction stays masked.
        """
        del start  # kept for call-site symmetry with the other span rules
        return NON_PERSON_NOUN_RE.match(self.text[end : end + window]) is not None

    def is_field_label(self, start: int, end: int) -> bool:
        return any(start < label_end and label_start < end
                   for label_start, label_end in self.field_labels)
