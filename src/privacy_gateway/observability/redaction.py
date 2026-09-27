"""Safe rendering of sensitive values for logs and reports.

This module deliberately exposes no function that returns a value intact. If
you find yourself wanting one, the answer is a fingerprint.

The salt defaults to a per-process random value, so hashes correlate *within*
one run -- enough to tie a leak finding to a mapping entry -- but are not a
stable identifier that could be matched across runs or against a precomputed
table. Setting ``GATEWAY_HASH_SALT`` makes them stable on purpose, which is a
deployment decision rather than a default.
"""

from __future__ import annotations

import hashlib
import secrets

_PROCESS_SALT = secrets.token_hex(16)

__all__ = ["fingerprint", "process_salt", "redact", "safe_preview"]


def process_salt() -> str:
    return _PROCESS_SALT


def fingerprint(value: str, salt: str = "") -> str:
    return hashlib.sha256(f"{salt or _PROCESS_SALT}\x1f{value}".encode()).hexdigest()[:16]


def redact(value: str, salt: str = "") -> str:
    """A loggable stand-in: ``sha256:9f2b71c4a83d0e15:len=11``."""
    return f"sha256:{fingerprint(value, salt)}:len={len(value)}"


def safe_preview(value: str, min_length: int = 6) -> str:
    """First and last character only, and only for values long enough to hide.

    Intended for a human triaging a report, not for logs.
    """
    if len(value) < min_length:
        return "*" * len(value)
    return f"{value[0]}{'*' * (len(value) - 2)}{value[-1]}"
