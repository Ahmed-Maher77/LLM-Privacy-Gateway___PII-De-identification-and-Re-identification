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
    r"(?i)(?:\b|_)(?:id|ids|ref|reference|no|number|matter|case|session|ticket|"
    r"record|file|docket|claim|policy|account)(?:\b|_)"
)

# Field labels whose value is a postal address, across the languages these
# documents actually appear in.
ADDRESS_LABEL_RE = re.compile(
    r"(?i)(?:\b|_)(?:address|addr|adresse|adres|direcci|indirizzo|anschrift|"
    r"endere|endereco|postal|residence)"
)

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
    r"operation|operations|division|branch|branches|timezone|"
    r"currency|currencies|law|laws|regulation|regulations|"
    r"localization|localisation|contracts?|partners?|startups?|compan(?:y|ies)|"
    r"teams?|expansions?|distributors?|nuance|regulators?)\b"
)

_WORD_RE = re.compile(r"[^\W\d_][\w'’-]*")

# Adjacency that marks a token as part of an identifier, not prose.
_IDENTIFIER_CHARS = frozenset("@._-/+:\\")

# Mean value length above which a "Label:" is prose (a speaker turn),
# not a form field.
MAX_FIELD_VALUE_CHARS = 48

# Conversational openers that indicate spoken dialogue, not a form field value.
_SPEAKER_PROSE_RE = re.compile(
    r"^[ \t]*(?:"
    r"Hi|Hello|Hey|I|We|You|He|She|They|It|Yes|No|Sure|Okay|Please|Thanks|Can|Could|Would|Should|Let|Let's|Sounds|Agreed|Great|Right|Good|Got|Done|Oof|Well|So|Actually|Honestly|Before|Alright|All\s+right"
    r"|مرحباً|أهلاً|شكراً|نعم|لا|هل|حسناً|طيب|تمام|أكيد|يا|صباح|مساء|سلام|أنا|نحن|هو|هي|هم|أنتم|أنت|ما|إيه|عظيم|كيف|لو"
    r")\b",
    re.IGNORECASE,
)


def _is_speaker_prose(remainder: str) -> bool:
    if not remainder:
        return False
    if _SPEAKER_PROSE_RE.search(remainder):
        return True
    if any(p in remainder for p in ("?", "؟", "!", "،")):
        return True
    return len(remainder.split()) > 6


def _mean(values: list[int]) -> float:
    return sum(values) / len(values) if values else 0.0


_ID_TOKEN_RE = re.compile(
    r"(?<![\w-])[A-Za-z0-9]{2,}(?:[-_/][A-Za-z0-9]+)+(?![\w-])"
)


def _is_identifier_value(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return False
    if not any(c.isspace() for c in stripped):
        return any(c.isdigit() for c in stripped) or any(c in "-_/#:" for c in stripped)
    tokens = stripped.split()
    return len(tokens) <= 3 and any(c.isdigit() for c in stripped)


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

    def line_is_lowercase(self, offset: int) -> bool:
        """True when the line holding ``offset`` has no uppercase letter.

        The mirror image of ``line_is_uncased``, and the signal a lowercase
        ASR transcription of a known name needs: a properly cased document
        still writes capitals *somewhere* on a line that happens to contain
        an ordinary word matching someone's first name, so casing there is
        still evidence against a name. A line with no capitals at all carries
        no casing information either way -- the transcript never capitalises
        anything on that line, a name included -- so it cannot be held
        against a name already confirmed by the roster.
        """
        start = self.text.rfind("\n", 0, offset) + 1
        end = self.text.find("\n", offset)
        line = self.text[start : len(self.text) if end == -1 else end]
        return any(char.isalpha() for char in line) and not any(
            char.isupper() for char in line
        )

    def is_sentence_initial(self, offset: int) -> bool:
        """True when ``offset`` opens a sentence, a line, or the document.

        A capitalised common word here is a grammar artefact -- "Will you
        confirm?" opens with a modal verb, not a name -- rather than
        evidence that this particular occurrence names somebody, however
        confident the roster is that the word is also somebody's name
        elsewhere in the document.
        """
        before = self.text[:offset].rstrip(" \t")
        if not before or before[-1] == "\n":
            return True
        return before[-1] in ".!?:;"

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

    def _header_block_label_spans(self) -> set[tuple[int, int]]:
        """Label spans that sit inside a header block of >= 3 distinct Label: lines."""
        lines: list[tuple[int, int, str]] = []
        offset = 0
        for line in self.text.splitlines(keepends=True):
            line_str = line.rstrip("\r\n")
            lines.append((offset, offset + len(line_str), line_str))
            offset += len(line)

        header_spans: set[tuple[int, int]] = set()
        current_block: list[tuple[str, int, int]] = []

        for line_start, line_end, line_text in lines:
            stripped = line_text.strip()
            if not stripped:
                if len(current_block) >= 3:
                    labels = [item[0] for item in current_block]
                    if len(set(labels)) == len(labels):
                        header_spans.update((item[1], item[2]) for item in current_block)
                current_block = []
                continue

            match = FIELD_LABEL_RE.match(line_text)
            remainder = line_text[match.end() :].strip() if match else ""
            if match and not _is_speaker_prose(remainder):
                current_block.append((
                    match.group("label").casefold(),
                    line_start + match.start("label"),
                    line_start + match.end("label"),
                ))
            else:
                if len(current_block) >= 3:
                    labels = [item[0] for item in current_block]
                    if len(set(labels)) == len(labels):
                        header_spans.update((item[1], item[2]) for item in current_block)
                current_block = []

        if len(current_block) >= 3:
            labels = [item[0] for item in current_block]
            if len(set(labels)) == len(labels):
                header_spans.update((item[1], item[2]) for item in current_block)

        return header_spans

    @cached_property
    def field_labels(self) -> tuple[tuple[int, int], ...]:
        """Character ranges of every ``Label:`` key at the start of a line.

        "Owner:" and "Sarah Jenkins:" are the same shape, so shape cannot tell
        them apart -- and reading a speaker label as a form field deletes the
        person at every turn of the transcript, which is the highest-value PII
        position in the document.

        Two independent acceptance paths classify a Label: as a field label:
        1. It sits inside a header block (>= 3 consecutive lines with distinct Label:).
        2. Its value does not match spoken prose patterns and its mean value length <= 48 chars.
        """
        remainders: dict[str, list[int]] = {}
        raw_remainders: dict[str, list[str]] = {}
        matches = list(FIELD_LABEL_RE.finditer(self.text))
        for match in matches:
            line_end = self.text.find("\n", match.end())
            line_end = len(self.text) if line_end == -1 else line_end
            val = self.text[match.end() : line_end].strip()
            if not val:
                next_line_start = line_end + 1
                if next_line_start < len(self.text):
                    next_line_end = self.text.find("\n", next_line_start)
                    next_line_end = len(self.text) if next_line_end == -1 else next_line_end
                    val = self.text[next_line_start : next_line_end].strip()
            key = match.group("label").casefold()
            remainders.setdefault(key, []).append(len(val))
            raw_remainders.setdefault(key, []).append(val)

        header_spans = self._header_block_label_spans()
        result: list[tuple[int, int]] = []
        for match in matches:
            span = (match.start("label"), match.end("label"))
            if span in header_spans:
                result.append(span)
                continue
            key = match.group("label").casefold()
            if (
                not any(_is_speaker_prose(r) for r in raw_remainders.get(key, []))
                and _mean(remainders[key]) <= MAX_FIELD_VALUE_CHARS
            ):
                result.append(span)

        return tuple(result)

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
            if not stripped or len(stripped) > 120:
                continue
            if _is_identifier_value(stripped):
                start = match.end() + (len(value) - len(value.lstrip()))
                values.append((start, start + len(stripped)))
            else:
                for submatch in _ID_TOKEN_RE.finditer(value):
                    if any(char.isdigit() for char in submatch.group()):
                        sub_start = match.end() + submatch.start()
                        values.append((sub_start, match.end() + submatch.end()))
        return tuple(values)

    @cached_property
    def address_field_values(self) -> tuple[tuple[int, int], ...]:
        """Value ranges of fields whose label names a postal address."""
        values: list[tuple[int, int]] = []
        for match in FIELD_LABEL_RE.finditer(self.text):
            if not ADDRESS_LABEL_RE.search(match.group("label")):
                continue
            line_end = self.text.find("\n", match.end())
            line_end = len(self.text) if line_end == -1 else line_end
            value = self.text[match.end() : line_end]
            stripped = value.strip()
            if not stripped or len(stripped) > 160:
                continue
            start = match.end() + (len(value) - len(value.lstrip()))
            values.append((start, start + len(stripped)))

        json_field_re = re.compile(
            r'^[ \t]*"(?P<label>[\w-]+)"[ \t]*:[ \t]*"(?P<value>[^"\n]+)"',
            re.MULTILINE,
        )
        for match in json_field_re.finditer(self.text):
            if not ADDRESS_LABEL_RE.search(match.group("label")):
                continue
            val = match.group("value").strip()
            if not val or len(val) > 160:
                continue
            values.append((match.start("value"), match.end("value")))

        return tuple(values)

    def releases_norp(self, start: int, end: int, window: int = 40) -> bool:
        """Is there positive evidence this NORP mention is *not* about people?

        There is exactly one way to earn release: the mention modifies a noun
        that cannot be a person -- "the European market", "Finacle, version
        10.2.18", or appears as the value of a Language/Languages field.
        Everything else stays redacted.
        """
        line_start = self.text.rfind("\n", 0, start) + 1
        line_prefix = self.text[line_start:start]
        if re.search(r"(?i)^[ \t]*(?:languages?|idiomas?|langues?|sprachen?)[ \t]*:", line_prefix):
            return True
        return NON_PERSON_NOUN_RE.match(self.text[end : end + window]) is not None

    def is_field_label(self, start: int, end: int) -> bool:
        return any(start < label_end and label_start < end
                   for label_start, label_end in self.field_labels)
