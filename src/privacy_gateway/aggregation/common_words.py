"""Loader for the ordinary-English-word filter.

See resources/common_words.txt for what the list is for and why it is curated
rather than scraped.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parents[3] / "resources" / "common_words.txt"


@lru_cache(maxsize=4)
def load_common_words(path: Path | str = DEFAULT_PATH) -> frozenset[str]:
    path = Path(path)
    if not path.exists():
        return frozenset()
    return frozenset(
        line.strip().casefold()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    )


COMMON_WORDS: frozenset[str] = load_common_words()
