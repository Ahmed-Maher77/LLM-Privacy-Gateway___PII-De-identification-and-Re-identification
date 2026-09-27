"""Job and meeting titles: detected so they win, then never redacted.

"HR Operations Specialist" was being masked as ``{{ORG_3}}``, which protects
nobody and makes the sentence unreadable. A job title is not personal data.

These spans exist purely so that they beat the ORG span in overlap resolution;
because ``JOB_TITLE`` and ``MEETING_TITLE`` are in no profile, the type filter
at the end of ``analyze()`` then drops them and the original text survives.
"""

from __future__ import annotations

import re

from .spans import Span

# Head nouns that end a job title. Honorifics are deliberately absent: "Dr."
# is part of a person's name, not their job, and adding "doctor" here would
# make "Dr. Eleanor Rostova" compete with the PERSON span that must win.
JOB_TITLE_HEADS = frozenset(
    """
    manager engineer developer specialist analyst director officer lead head
    architect designer consultant administrator coordinator supervisor
    president associate intern scientist recruiter controller partner chief
    strategist technician executive assistant advisor auditor
    """.split()
)

_HEAD_ALTERNATION = "|".join(sorted(JOB_TITLE_HEADS, key=len, reverse=True))

# Up to four capitalised modifiers (or an ampersand) before a head noun:
# "HR Operations Specialist", "Lead Security Engineer", "Client Product Manager".
JOB_TITLE_RE = re.compile(
    r"(?<![\w-])"
    r"(?:[A-Z][A-Za-z&/.-]{0,20}[ \t]+){0,4}"
    rf"(?i:{_HEAD_ALTERNATION})"
    r"(?![\w-])"
)

# A document header line: everything after the colon is a title, not an org.
# Tolerates leading decoration, because exporters prefix these lines with
# emoji and bullet characters ("\N{STUDIO MICROPHONE} Transcript: ...").
TITLE_LINE_RE = re.compile(
    r"(?im)^(?:[^\w\n][ \t]*){0,4}"
    r"(?:transcript|subject|title|meeting|topic|re|session|agenda)"
    r"[ \t]*:[ \t]*(?P<title>\S[^\n]{2,120}?)[ \t\r]*$"
)

# Role acronyms the models routinely type as PERSON ("the CFO uploads...").
# A closed set, because these are genuinely ambiguous out of context.
ROLE_ACRONYMS = frozenset(
    """
    CEO CFO CTO COO CIO CISO CMO CHRO CDO CPO CRO CSO
    VP SVP EVP GM MD PM PO BA QA SME SRE DBA DPO
    """.split()
)

ROLE_ACRONYM_RE = re.compile(
    r"(?<![\w-])(?:" + "|".join(sorted(ROLE_ACRONYMS, key=len, reverse=True)) + r")(?![\w-])"
)

MIN_TITLE_TOKENS = 2


def detect_titles(text: str) -> list[Span]:
    """Find job titles and document-header titles.

    Uses ``source="lexicon"`` rather than ``"pattern"`` on purpose: pattern
    spans are authoritative and would beat a PERSON span outright, which is
    the one outcome that must never happen here.
    """
    spans: list[Span] = []

    for match in JOB_TITLE_RE.finditer(text):
        surface = match.group().strip()
        # A bare head noun ("manager") is an ordinary word, not a title.
        if len(surface.split()) < MIN_TITLE_TOKENS:
            continue
        if not surface[0].isupper():
            continue
        spans.append(
            Span(
                start=match.start(),
                end=match.start() + len(surface),
                label="JOB_TITLE",
                text=surface,
                score=0.9,
                source="lexicon",
            )
        )

    for match in ROLE_ACRONYM_RE.finditer(text):
        spans.append(
            Span(
                start=match.start(),
                end=match.end(),
                label="JOB_TITLE",
                text=match.group(),
                score=0.9,
                source="lexicon",
            )
        )

    for match in TITLE_LINE_RE.finditer(text):
        title = match.group("title").rstrip()
        spans.append(
            Span(
                start=match.start("title"),
                end=match.start("title") + len(title),
                label="MEETING_TITLE",
                text=title,
                score=0.9,
                source="lexicon",
            )
        )

    return spans
