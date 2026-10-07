"""Assertion helpers, principally the mapping-isolation check.

``assert_no_secrets`` is layered rather than a single substring test, because
the interesting failure is not "the whole name appeared" -- it is the
prototype's failure, where ``<PER_2>ania Fahmy`` left the surname sitting in
plain text next to a placeholder. A naive check for ``"Rania Fahmy"`` passes
that prompt happily.

There is a negative-control test for this helper in the integration suite. An
assertion helper that has never failed is not evidence.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

_WORD_RE = re.compile(r"[^\W\d_]+", re.UNICODE)
_DIGITS_RE = re.compile(r"\d+")
_SQUASH_RE = re.compile(r"[\s`*_~]+")

DEFAULT_TOKEN_MIN = 4
DEFAULT_DIGIT_RUN_MIN = 6


class SecretLeak(AssertionError):
    """Raised when a protected value is found in text that should not hold it."""


def _squash(text: str) -> str:
    return _SQUASH_RE.sub("", text).casefold()


_GENERIC_TOKENS = frozenset(
    {"example", "test", "invalid", "localhost", "com", "org", "net", "edu", "gov", "mil", "http", "https", "mail", "email"}
)


def find_leaks(
    text: str,
    values: Iterable[str],
    *,
    token_min: int = DEFAULT_TOKEN_MIN,
    digit_run_min: int = DEFAULT_DIGIT_RUN_MIN,
) -> list[tuple[str, str]]:
    """Return ``(check, value)`` pairs for every protected value found."""
    found: list[tuple[str, str]] = []
    lowered = text.casefold()
    squashed = _squash(text)

    for value in values:
        value = value.strip()
        if len(value) < 2:
            continue

        # 1. the value verbatim
        if value in text:
            found.append(("exact", value))
            continue
        # 2. ignoring case
        if value.casefold() in lowered:
            found.append(("casefold", value))
            continue
        # 3. ignoring whitespace and markdown, so "Rania  Fahmy" and
        #    "`Rania Fahmy`" cannot slip past
        if len(value) >= 4 and _squash(value) in squashed:
            found.append(("squashed", value))
            continue
        # 4. any substantial word of the value. This is the check that catches
        #    the real defect: with "<PER_2>ania Fahmy" in the prompt, the token
        #    "Fahmy" is present in plain text.
        for token in _WORD_RE.findall(value):
            if token.casefold() in _GENERIC_TOKENS:
                continue
            if len(token) >= token_min and token.casefold() in lowered:
                found.append(("token", token))
                break
        else:
            # 5. a long digit run with separators removed, so "7700 900123"
            #    cannot hide as "7700900123"
            digits = "".join(_DIGITS_RE.findall(value))
            if len(digits) >= digit_run_min and digits in re.sub(r"\D", "", text):
                found.append(("digits", digits))
    return found


def assert_no_secrets(
    texts: str | Sequence[str],
    values: Iterable[str],
    *,
    context: str = "text",
    token_min: int = DEFAULT_TOKEN_MIN,
) -> None:
    """Fail if any protected value appears in any of ``texts``."""
    if isinstance(texts, str):
        texts = [texts]
    values = list(values)
    for index, text in enumerate(texts):
        leaks = find_leaks(text, values, token_min=token_min)
        if leaks:
            kinds = ", ".join(f"{kind}" for kind, _ in leaks[:5])
            raise SecretLeak(
                f"{len(leaks)} protected value(s) found in {context}[{index}] "
                f"via {kinds}"  # deliberately does not print the values
            )


def placeholder_tokens(text: str) -> set[str]:
    return set(re.findall(r"<[A-Z][A-Z0-9]*_\d{1,6}>", text))


def vocabulary(text: str) -> set[str]:
    """Alphabetic words, used by the anti-fragmentation invariant."""
    return set(_WORD_RE.findall(text))


def assert_no_invented_words(sanitized: str, original: str) -> None:
    """Pseudonymization may only remove words, never invent them.

    This is the generic form of the prototype's fragment bug: replacing a
    sub-word span leaves a remainder ("ania", "ssam", "alaby") that exists
    nowhere in the source. It catches every such defect, including ones nobody
    has enumerated by hand.
    """
    masked = re.sub(r"<[A-Z][A-Z0-9]*_\d{1,6}>", " ", sanitized)
    invented = sorted(vocabulary(masked) - vocabulary(original))
    if invented:
        raise SecretLeak(
            f"pseudonymization invented {len(invented)} word(s) absent from the "
            f"source: {invented[:10]}"
        )


def assert_no_placeholder_adjacency(sanitized: str) -> None:
    """No placeholder may touch a word character on either side."""
    pattern = re.compile(r"<[A-Z][A-Z0-9]*_\d{1,6}>\w|\w<[A-Z][A-Z0-9]*_\d{1,6}>")
    match = pattern.search(sanitized)
    if match is not None:
        raise SecretLeak(f"placeholder is adjacent to a word character: {match.group()!r}")
