"""Exception hierarchy for the privacy gateway.

Every exception here is constructed from counts, types and hashes -- never from
raw document text or mapping values. An exception message is one of the easiest
ways to leak a secret into a log or a terminal, so the constructors below take
structured fields rather than free-form strings built at the call site.
"""

from __future__ import annotations


class GatewayError(Exception):
    """Base class for every error raised by the gateway."""

    exit_code: int = 1


class ConfigError(GatewayError):
    exit_code = 1


class InputTooLargeError(GatewayError):
    exit_code = 2

    def __init__(self, size: int, limit: int) -> None:
        super().__init__(f"input is {size} characters, limit is {limit}")
        self.size = size
        self.limit = limit


class DetectorUnavailableError(GatewayError):
    """A detector that the configured protection level requires has failed."""

    exit_code = 3

    def __init__(self, detector: str, cause: BaseException | None = None, hint: str = "") -> None:
        message = f"detector {detector!r} is unavailable"
        if cause is not None:
            message += f" ({type(cause).__name__})"
        if hint:
            message += f"; {hint}"
        super().__init__(message)
        self.detector = detector
        self.cause = cause


class AggregationInvariantError(GatewayError):
    """A post-condition of entity aggregation was violated.

    Always fatal, in both fail modes: overlapping or misaligned spans are
    precisely the state that produces corrupted output such as
    ``<PER_2>ehal Fahmy``.
    """

    exit_code = 4


class SanitizationLeakError(GatewayError):
    """A mapped value survived into text that was about to be transmitted.

    Not governed by ``fail_mode``: there is no recovering from a transmission.
    """

    exit_code = 5

    def __init__(self, count: int, entity_types: tuple[str, ...], context: str) -> None:
        super().__init__(
            f"{count} sensitive value(s) of type(s) {', '.join(sorted(set(entity_types)))} "
            f"survived sanitization at stage {context!r}"
        )
        self.count = count
        self.entity_types = entity_types
        self.context = context


class PlaceholderInjectionError(GatewayError):
    exit_code = 5

    def __init__(self, count: int) -> None:
        super().__init__(f"input contained {count} gateway-shaped placeholder token(s)")
        self.count = count


class OutputLeakError(GatewayError):
    """The model reproduced a value we believed we had removed."""

    exit_code = 6

    def __init__(self, count: int, entity_types: tuple[str, ...]) -> None:
        super().__init__(
            f"model output contained {count} raw sensitive value(s) "
            f"of type(s) {', '.join(sorted(set(entity_types)))}"
        )
        self.count = count
        self.entity_types = entity_types


class ConversationMismatchError(GatewayError):
    exit_code = 5

    def __init__(self) -> None:
        super().__init__("mapping belongs to a different conversation")


class LLMError(GatewayError):
    exit_code = 7
