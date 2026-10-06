"""Ollama adapter.

Note that the prompt is scrubbed from any exception this raises. LangChain-style
transport errors routinely echo the request body, and the request body is the
sanitized text -- which, if sanitization has partly failed, is exactly what must
not reach a log or a terminal.
"""

from __future__ import annotations

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
    ) -> None:
        self.model = model
        self.base_url = base_url
        self.temperature = temperature
        self.timeout_seconds = timeout_seconds
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
        self._client = ChatOllama(**kwargs)
        return self._client

    def invoke(self, prompt: str, *, system: str | None = None) -> LLMResponse:
        client = self._ensure()
        messages: list[tuple[str, str]] = []
        if system:
            messages.append(("system", system))
        messages.append(("human", prompt))

        try:
            result = client.invoke(messages)
        except Exception as exc:
            # Deliberately does not interpolate the exception text, which may
            # contain the request body.
            raise LLMError(
                f"{type(exc).__name__} while calling model {self.model!r}"
            ) from None

        content = getattr(result, "content", result)
        if isinstance(content, list):  # some providers return content blocks
            content = "".join(
                part.get("text", "") if isinstance(part, dict) else str(part) for part in content
            )
        return LLMResponse(text=str(content), model=self.model)

    def health(self) -> bool:
        try:
            self._ensure()
            return True
        except LLMError:
            return False
