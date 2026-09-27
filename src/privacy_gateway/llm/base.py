"""LLM abstraction.

The privacy layer must not know or care which provider is behind this
interface. Detection, aggregation, policy and pseudonymization are all
expressed against sanitized text, so swapping Ollama for anything else changes
one factory function and nothing else.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class LLMResponse:
    text: str
    model: str = ""
    finish_reason: str | None = None
    usage: Mapping[str, int] | None = None
    latency_seconds: float = 0.0
    metadata: Mapping[str, Any] = field(default_factory=dict)


@runtime_checkable
class LLMClient(Protocol):
    name: str
    model: str

    def invoke(
        self,
        prompt: str,
        *,
        system: str | None = None,
        history: Sequence[tuple[str, str]] = (),
    ) -> LLMResponse: ...

    def stream(
        self,
        prompt: str,
        *,
        system: str | None = None,
        history: Sequence[tuple[str, str]] = (),
    ) -> Iterator[str]: ...

    def health(self) -> bool: ...

    def close(self) -> None: ...


def build_llm(config: Any = None, **kwargs: Any) -> LLMClient:
    """Factory keyed on ``config.provider``."""
    provider = str(getattr(config, "provider", "ollama") or "ollama")
    if provider == "ollama":
        from .ollama_client import OllamaClient

        return OllamaClient(
            model=getattr(config, "model", "gpt-oss:120b-cloud"),
            base_url=getattr(config, "base_url", None),
            temperature=getattr(config, "temperature", 0.0),
            timeout_seconds=getattr(config, "timeout_seconds", 120.0),
            **kwargs,
        )
    if provider == "mock":
        from .mock_client import MockLLMClient

        return MockLLMClient(**kwargs)
    if provider == "echo":
        from .mock_client import EchoLLMClient

        return EchoLLMClient(**kwargs)
    raise ValueError(f"unknown LLM provider: {provider!r}")
