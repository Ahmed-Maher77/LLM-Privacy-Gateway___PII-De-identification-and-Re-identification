r"""Text normalization with exact offset preservation.

Everything happens in a **single left-to-right pass**, so the offset map is
built once and never has to be composed. Each region of the source is either
copied verbatim or replaced by a known string, and the replacement is itself
post-processed (folded, composed) before being emitted -- which is how
``&nbsp;`` ends up as a plain space in one step rather than two.

Deliberate non-decisions, each of which costs more than it buys here:

* **NFC, not NFKC.** NFKC rewrites ``No.`` from U+2116, splits ligatures and
  maps fullwidth forms to ASCII. None of that helps privacy detection, and all
  of it multiplies length-changing edits. What actually matters -- non-breaking
  spaces and smart quotes -- is handled below at zero offset cost.
* **Trailing line whitespace is preserved.** Every line of the Teams export
  ends ``" \r\n"``. Stripping it would shift every offset in the document to
  tidy up whitespace the model does not care about.
* **HTML entities require a terminating semicolon.** ``html.unescape`` accepts
  ``&amp`` without one, so ``AT&T`` near a known entity name can be corrupted.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field

from .offsets import EditRecorder, OffsetMap

#: Whitespace variants folded to a plain space. All single characters, so each
#: fold is 1:1 and costs no offset drift at all.
_SPACE_FOLD = {
    " ": " ",  # NO-BREAK SPACE
    " ": " ",  # NARROW NO-BREAK SPACE -- what the model emitted inside
    #                 "**PER 2**", silently defeating restoration
    " ": " ", " ": " ", " ": " ", " ": " ", " ": " ",
    " ": " ", " ": " ", " ": " ", " ": " ", " ": " ",
    " ": " ", " ": " ", "　": " ", " ": " ",
}

_QUOTE_FOLD = {
    "‘": "'", "’": "'", "‚": "'", "‛": "'",
    "“": '"', "”": '"', "„": '"', "‟": '"',
}

#: Zero-width and bidirectional-control characters. Removed outright: they are
#: invisible to a reader but can hide inside a placeholder or a name, which
#: makes them an injection and evasion vector.
_ZERO_WIDTH = frozenset(
    "​‌‍‎‏‪‫‬‭‮"
    "⁠⁡⁢⁣⁤⁪⁫⁬⁭⁮⁯﻿"
)

_HTML_ENTITY_RE = re.compile(r"&(#\d{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});")

_NAMED_ENTITIES: Mapping[str, str] = {
    "amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'",
    "nbsp": " ", "ndash": "–", "mdash": "—",
    "lsquo": "‘", "rsquo": "’", "ldquo": "“", "rdquo": "”",
    "hellip": "…", "copy": "©", "reg": "®", "trade": "™",
    "deg": "°", "eacute": "é", "egrave": "è", "uuml": "ü",
    "ouml": "ö", "auml": "ä", "ccedil": "ç", "ntilde": "ñ",
}


@dataclass(frozen=True, slots=True)
class NormalizedText:
    """Canonical text plus the map back to what the user supplied."""

    original: str
    text: str
    offset_map: OffsetMap
    stats: Mapping[str, int] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.text)

    def to_original(self, start: int, end: int) -> tuple[int, int]:
        return self.offset_map.to_original(start, end)

    def original_slice(self, start: int, end: int) -> str:
        o_start, o_end = self.to_original(start, end)
        return self.original[o_start:o_end]

    def is_exact(self, start: int, end: int) -> bool:
        return self.offset_map.is_exact(start, end)


@dataclass(frozen=True, slots=True)
class NormalizerConfig:
    normalize_newlines: bool = True
    decode_html_entities: bool = True
    strip_zero_width: bool = True
    fold_spaces: bool = True
    fold_quotes: bool = True
    unicode_form: str = "NFC"  # "NFC", "NFKC" or "none"


def _decode_entity(body: str) -> str | None:
    """Decode one entity body (the text between ``&`` and ``;``)."""
    if body.startswith("#"):
        try:
            code = int(body[2:], 16) if body[1:2] in ("x", "X") else int(body[1:])
        except ValueError:
            return None
        # Reject surrogates and out-of-range code points rather than raising.
        if code <= 0 or code > 0x10FFFF or 0xD800 <= code <= 0xDFFF:
            return None
        return chr(code)
    return _NAMED_ENTITIES.get(body)


class Normalizer:
    """Turns raw input into canonical text plus an offset map."""

    def __init__(self, config: NormalizerConfig | None = None) -> None:
        self.config = config or NormalizerConfig()

    def normalize(self, raw: str) -> NormalizedText:
        cfg = self.config
        rec = EditRecorder()
        stats: dict[str, int] = {}
        n = len(raw)
        i = 0

        def bump(key: str) -> None:
            stats[key] = stats.get(key, 0) + 1

        while i < n:
            ch = raw[i]

            # -- byte order mark at the very start -----------------------
            if i == 0 and ch == "﻿":
                rec.copy(raw, 0)
                rec.replace(1, "")
                bump("bom_removed")
                i = 1
                continue

            # -- CRLF / lone CR ------------------------------------------
            if cfg.normalize_newlines and ch == "\r":
                rec.copy(raw, i)
                if i + 1 < n and raw[i + 1] == "\n":
                    rec.replace(i + 2, "\n")  # length-changing: CR removed
                    bump("crlf_normalized")
                    i += 2
                else:
                    rec.replace(i + 1, "\n")  # 1:1, no offset drift
                    bump("cr_normalized")
                    i += 1
                continue

            # -- HTML entity ---------------------------------------------
            if cfg.decode_html_entities and ch == "&":
                m = _HTML_ENTITY_RE.match(raw, i)
                if m is not None:
                    decoded = _decode_entity(m.group(1))
                    if decoded is not None:
                        # Post-process the replacement so &nbsp; lands as a
                        # plain space in this single pass.
                        decoded = self._post_process(decoded)
                        rec.copy(raw, i)
                        rec.replace(m.end(), decoded)
                        bump("html_entities_decoded")
                        i = m.end()
                        continue

            # -- zero-width / bidi controls -------------------------------
            if cfg.strip_zero_width and ch in _ZERO_WIDTH:
                rec.copy(raw, i)
                rec.replace(i + 1, "")
                bump("zero_width_removed")
                i += 1
                continue

            # -- C0 controls other than tab and newline -------------------
            if ord(ch) < 0x20 and ch not in "\n\t":
                rec.copy(raw, i)
                rec.replace(i + 1, "")
                bump("control_removed")
                i += 1
                continue

            # -- whitespace and quote folds (all 1:1) ---------------------
            if cfg.fold_spaces and ch in _SPACE_FOLD:
                rec.copy(raw, i)
                rec.replace(i + 1, _SPACE_FOLD[ch])
                bump("space_folded")
                i += 1
                continue
            if cfg.fold_quotes and ch in _QUOTE_FOLD:
                rec.copy(raw, i)
                rec.replace(i + 1, _QUOTE_FOLD[ch])
                bump("quote_folded")
                i += 1
                continue

            # -- non-ASCII run: normalize locally -------------------------
            if ord(ch) > 0x7F and cfg.unicode_form != "none":
                # A combining mark composes with the character before it, so
                # the run has to start at that base character -- otherwise
                # "e" + U+0301 never becomes "é".
                run_start = i
                if unicodedata.combining(ch) and i > rec.orig_pos:
                    run_start = i - 1
                j = i
                while (
                    j < n
                    and ord(raw[j]) > 0x7F
                    and raw[j] not in _SPACE_FOLD
                    and raw[j] not in _QUOTE_FOLD
                    and raw[j] not in _ZERO_WIDTH
                ):
                    j += 1
                run = raw[run_start:j]
                composed = unicodedata.normalize(cfg.unicode_form, run)
                if composed != run:
                    rec.copy(raw, run_start)
                    rec.replace(j, composed)
                    bump("unicode_normalized")
                i = j
                continue

            i += 1

        text, offset_map = rec.finish(raw)
        return NormalizedText(original=raw, text=text, offset_map=offset_map, stats=stats)

    def _post_process(self, value: str) -> str:
        """Apply the character-level folds to a decoded entity replacement."""
        cfg = self.config
        out = []
        for ch in value:
            if cfg.strip_zero_width and ch in _ZERO_WIDTH:
                continue
            if cfg.fold_spaces and ch in _SPACE_FOLD:
                out.append(_SPACE_FOLD[ch])
            elif cfg.fold_quotes and ch in _QUOTE_FOLD:
                out.append(_QUOTE_FOLD[ch])
            elif cfg.normalize_newlines and ch == "\r":
                out.append("\n")
            else:
                out.append(ch)
        result = "".join(out)
        if cfg.unicode_form != "none":
            result = unicodedata.normalize(cfg.unicode_form, result)
        return result
