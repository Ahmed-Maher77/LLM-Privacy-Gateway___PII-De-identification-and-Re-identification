"""Ollama adapter.

Note that the prompt is scrubbed from any exception this raises. LangChain-style
transport errors routinely echo the request body, and the request body is the
sanitized text -- which, if sanitization has partly failed, is exactly what must
not reach a log or a terminal.
"""

from __future__ import annotations

import time
from collections.abc import Iterator, Sequence
from typing import Any

from ..errors import LLMError
from .base import LLMResponse

DEFAULT_MODEL = "gpt-oss:120b-cloud"


class OllamaClient:
    """Wraps ``langchain_ollama.ChatOllama``."""

    name = "ollama"

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        base_url: str | None = None,
        temperature: float = 0.0,
        timeout_seconds: float = 120.0,
        num_ctx: int | None = None,
    ) -> None:
        self.model = model
        self.base_url = base_url
        self.temperature = temperature
        self.timeout_seconds = timeout_seconds
        self.num_ctx = num_ctx
        self._client: Any = None

    def _ensure(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            from langchain_ollama import ChatOllama
        except ImportError as exc:  # pragma: no cover
            raise LLMError("langchain-ollama is not installed") from exc
        kwargs: dict[str, Any] = {
            "model": self.model,
            "temperature": self.temperature,
        }
        if self.base_url:
            kwargs["base_url"] = self.base_url
        if self.num_ctx:
            kwargs["num_ctx"] = self.num_ctx
        self._client = ChatOllama(**kwargs)
        return self._client

    def invoke(
        self,
        prompt: str,
        *,
        system: str | None = None,
        history: Sequence[tuple[str, str]] = (),
    ) -> LLMResponse:
        client = self._ensure()
        messages: list[tuple[str, str]] = []
        if system:
            messages.append(("system", system))
        messages.extend(history)
        messages.append(("human", prompt))

        started = time.perf_counter()
        try:
            result = client.invoke(messages)
        except Exception as exc:
            # Deliberately does not interpolate the exception text, which may
            # contain the request body.
            raise LLMError(
                f"{type(exc).__name__} while calling model {self.model!r}"
            ) from None
        elapsed = time.perf_counter() - started

        content = getattr(result, "content", result)
        if isinstance(content, list):  # some providers return content blocks
            content = "".join(
                part.get("text", "") if isinstance(part, dict) else str(part) for part in content
            )
        meta = getattr(result, "response_metadata", {}) or {}
        usage = getattr(result, "usage_metadata", None)
        return LLMResponse(
            text=str(content),
            model=self.model,
            finish_reason=meta.get("done_reason"),
            usage=dict(usage) if usage else None,
            latency_seconds=elapsed,
        )

    def stream(
        self,
        prompt: str,
        *,
        system: str | None = None,
        history: Sequence[tuple[str, str]] = (),
    ) -> Iterator[str]:
        client = self._ensure()
        messages: list[tuple[str, str]] = []
        if system:
            messages.append(("system", system))
        messages.extend(history)
        messages.append(("human", prompt))
        try:
            for chunk in client.stream(messages):
                content = getattr(chunk, "content", "")
                if content:
                    yield str(content)
        except Exception as exc:
            raise LLMError(f"{type(exc).__name__} while streaming from {self.model!r}") from None

    def health(self) -> bool:
        try:
            self._ensure()
            return True
        except LLMError:
            return False

    def close(self) -> None:
        self._client = None
