"""Exception hierarchy and process exit codes.

Kept free of any internal imports so every other module can depend on it.

These carry **masked** data only. An exception can end up in a log, a crash
reporter or a CI transcript, and a traceback that prints the whole placeholder
mapping would turn the error path into the leak.
"""

from __future__ import annotations

from typing import ClassVar

# Exit codes, documented in the README and both CLIs' --help.
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_LEAK = 3
EXIT_REVIEW = 4
EXIT_DETECTOR = 5


class PIIError(Exception):
    """Base for every error this package raises deliberately."""

    exit_code: ClassVar[int] = EXIT_ERROR


class LeakDetected(PIIError):
    """Verification found PII surviving in text that was about to be sent."""

    exit_code: ClassVar[int] = EXIT_LEAK

    def __init__(
        self,
        *,
        status: str,
        leaks: list[dict] | None = None,
        residual: list[dict] | None = None,
        reason: str = "",
    ) -> None:
        self.status = status
        self.leaks = leaks or []
        self.residual = residual or []
        self.reason = reason
        super().__init__(self.summary())

    def summary(self) -> str:
        """A reviewer-facing description that reveals no secret values."""
        parts = [f"verification status={self.status}"]
        if self.reason:
            parts.append(self.reason)
        if self.leaks:
            parts.append(f"{len(self.leaks)} detected value(s) survived redaction")
        if self.residual:
            kinds = sorted({str(item.get("rule", "?")) for item in self.residual})
            parts.append(f"{len(self.residual)} residual finding(s): {', '.join(kinds)}")
        return "; ".join(parts)


class ReviewRequired(LeakDetected):
    """Only medium-confidence findings, and the caller asked for strict mode."""

    exit_code: ClassVar[int] = EXIT_REVIEW


class PlaceholderInjection(PIIError):
    """The input contained placeholder-shaped text under a reject policy."""

    exit_code: ClassVar[int] = EXIT_LEAK


class DetectorUnavailable(PIIError):
    """A detector the caller marked as required could not be loaded."""

    exit_code: ClassVar[int] = EXIT_DETECTOR

    def __init__(self, name: str, *, reason: str, hint: str = "") -> None:
        self.name = name
        self.reason = reason
        self.hint = hint
        message = f"{name} unavailable: {reason}"
        if hint:
            message = f"{message} ({hint})"
        super().__init__(message)


class DetectorUnavailableWarning(UserWarning):
    """A detector is missing and recall is silently reduced."""


class LeakWarning(UserWarning):
    """Verification failed but the caller chose not to raise."""
