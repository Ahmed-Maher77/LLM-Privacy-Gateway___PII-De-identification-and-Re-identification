"""Settings, from environment variables.

Hand-rolled rather than pulling in pydantic-settings: ``tomllib`` is stdlib and
``python-dotenv`` is already a dependency, and the dependency surface of a
privacy tool is itself part of its risk.

``Settings.from_env`` is the only place ``os.environ`` is read. Everything else
takes configuration by injection, which is what makes the pipeline testable
without monkeypatching the environment.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Literal

from .detectors.base import DEFAULT_PRIORITIES
from .errors import ConfigError

PREFIX = "GATEWAY_"

Env = Mapping[str, str]
FailMode = Literal["closed", "open"]


def _get(env: Env, key: str) -> str | None:
    return env.get(PREFIX + key)


def _str(env: Env, key: str, default: str) -> str:
    value = _get(env, key)
    return default if value is None else value


def _bool(env: Env, key: str, default: bool) -> bool:
    value = _get(env, key)
    if value is None:
        return default
    lowered = value.strip().casefold()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{PREFIX}{key} must be a boolean, got {value!r}")


def _int(env: Env, key: str, default: int) -> int:
    value = _get(env, key)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ConfigError(f"{PREFIX}{key} must be an integer, got {value!r}") from exc


def _float(env: Env, key: str, default: float) -> float:
    value = _get(env, key)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError as exc:
        raise ConfigError(f"{PREFIX}{key} must be a number, got {value!r}") from exc


def _list(env: Env, key: str, default: Sequence[str]) -> tuple[str, ...]:
    value = _get(env, key)
    if value is None:
        return tuple(default)
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _path(env: Env, key: str, default: Path) -> Path:
    value = _get(env, key)
    return default if value is None else Path(value)


@dataclass(frozen=True, slots=True)
class PreprocessingSettings:
    normalize_newlines: bool = True
    decode_html_entities: bool = True
    strip_zero_width: bool = True
    fold_spaces: bool = True
    fold_quotes: bool = True
    unicode_form: str = "NFC"
    max_input_chars: int = 1_000_000


@dataclass(frozen=True, slots=True)
class DetectorSettings:
    enabled: tuple[str, ...] = ("regex", "registry", "domain", "presidio", "ner")
    required: tuple[str, ...] = ("regex", "registry")
    priorities: Mapping[str, int] = field(default_factory=lambda: dict(DEFAULT_PRIORITIES))
    presidio_spacy_model: str = "en_core_web_lg"
    presidio_score_threshold: float = 0.35
    ner_model: str = "dslim/bert-base-NER"
    ner_device: str = "cpu"
    ner_score_threshold: float = 0.60
    domain_lexicon_path: Path = Path("config/domain_lexicon.toml")


@dataclass(frozen=True, slots=True)
class QwenSettings:
    #: Off by default. Its absence *is* the configured protection level, which
    #: is why a Qwen failure is never fatal unless `required` is set.
    enabled: bool = False
    required: bool = False
    model: str = "qwen2.5:7b-instruct"
    base_url: str | None = None
    timeout_seconds: float = 60.0
    max_chars: int = 4000
    max_retries: int = 1
    temperature: float = 0.0
    max_entities: int = 500
    max_span_ratio: float = 0.10


@dataclass(frozen=True, slots=True)
class ChunkSettings:
    size_chars: int = 4000
    overlap_chars: int = 200
    respect_turns: bool = True


@dataclass(frozen=True, slots=True)
class LLMSettings:
    provider: str = "ollama"
    model: str = "gpt-oss:120b-cloud"
    base_url: str | None = None
    temperature: float = 0.0
    timeout_seconds: float = 120.0
    stream: bool = False
    num_ctx: int | None = None


@dataclass(frozen=True, slots=True)
class ReidentificationSettings:
    placeholder_style: str = "angle"
    placeholder_pad: int = 3
    unknown_action: str = "redact"
    scan_output: bool = True
    scan_drift: bool = True
    on_drift: str = "retry"
    max_drift_retries: int = 1
    #: Documented as UNSAFE. See reidentification/drift.py for why fuzzy
    #: matching turns the gateway into a mapping-dump oracle.
    tolerant_matching: bool = False
    block_on_injection: bool = True


@dataclass(frozen=True, slots=True)
class ObservabilitySettings:
    log_level: str = "INFO"
    log_format: str = "json"
    allow_unsafe_logging: bool = False
    hash_salt: str = ""
    emit_timings: bool = True


@dataclass(frozen=True, slots=True)
class Settings:
    preprocessing: PreprocessingSettings = field(default_factory=PreprocessingSettings)
    detectors: DetectorSettings = field(default_factory=DetectorSettings)
    qwen: QwenSettings = field(default_factory=QwenSettings)
    chunking: ChunkSettings = field(default_factory=ChunkSettings)
    llm: LLMSettings = field(default_factory=LLMSettings)
    reidentification: ReidentificationSettings = field(default_factory=ReidentificationSettings)
    observability: ObservabilitySettings = field(default_factory=ObservabilitySettings)
    policy_path: Path = Path("config/policy.toml")
    allowlist_path: Path = Path("resources/public_entities.txt")
    denylist_path: Path = Path("resources/denylist.txt")
    fail_mode: FailMode = "closed"
    persist_mapping: bool = False
    mapping_dir: Path = Path("artifacts/mappings")
    artifacts_dir: Path = Path("artifacts")

    @property
    def fail_closed(self) -> bool:
        return self.fail_mode == "closed"

    # -- construction ------------------------------------------------------
    @classmethod
    def from_env(cls, env: Env | None = None, *, dotenv: bool = True) -> Settings:
        if env is None:
            if dotenv:
                try:
                    from dotenv import load_dotenv

                    load_dotenv()
                except ImportError:  # pragma: no cover
                    pass
            env = os.environ

        fail_mode = _str(env, "FAIL_MODE", "closed")
        if fail_mode not in ("closed", "open"):
            raise ConfigError(f"{PREFIX}FAIL_MODE must be 'closed' or 'open', got {fail_mode!r}")

        enabled = _list(
            env, "DETECTORS_ENABLED", ("regex", "registry", "domain", "presidio", "ner")
        )
        if not enabled:
            # A gateway with no detectors would pass every document through
            # untouched while reporting success. Refuse to start.
            raise ConfigError(
                f"{PREFIX}DETECTORS_ENABLED is empty; a gateway with no detectors "
                "would forward every document unprotected"
            )

        qwen_enabled = _bool(env, "QWEN_ENABLED", False)
        if qwen_enabled and "qwen" not in enabled:
            enabled = (*enabled, "qwen")

        return cls(
            preprocessing=PreprocessingSettings(
                normalize_newlines=_bool(env, "NORMALIZE_NEWLINES", True),
                decode_html_entities=_bool(env, "DECODE_HTML_ENTITIES", True),
                strip_zero_width=_bool(env, "STRIP_ZERO_WIDTH", True),
                unicode_form=_str(env, "UNICODE_FORM", "NFC"),
                max_input_chars=_int(env, "MAX_INPUT_CHARS", 1_000_000),
            ),
            detectors=DetectorSettings(
                enabled=enabled,
                required=_list(env, "DETECTORS_REQUIRED", ("regex", "registry")),
                presidio_spacy_model=_str(env, "PRESIDIO_SPACY_MODEL", "en_core_web_lg"),
                presidio_score_threshold=_float(env, "PRESIDIO_THRESHOLD", 0.35),
                ner_model=_str(env, "NER_MODEL", "dslim/bert-base-NER"),
                ner_device=_str(env, "NER_DEVICE", "cpu"),
                ner_score_threshold=_float(env, "NER_THRESHOLD", 0.60),
                domain_lexicon_path=_path(
                    env, "DOMAIN_LEXICON", Path("config/domain_lexicon.toml")
                ),
            ),
            qwen=QwenSettings(
                enabled=qwen_enabled,
                required=_bool(env, "QWEN_REQUIRED", False),
                model=_str(env, "QWEN_MODEL", "qwen2.5:7b-instruct"),
                base_url=_get(env, "QWEN_BASE_URL"),
                timeout_seconds=_float(env, "QWEN_TIMEOUT", 60.0),
                max_chars=_int(env, "QWEN_MAX_CHARS", 4000),
                max_retries=_int(env, "QWEN_MAX_RETRIES", 1),
            ),
            chunking=ChunkSettings(
                size_chars=_int(env, "CHUNK_SIZE_CHARS", 4000),
                overlap_chars=_int(env, "CHUNK_OVERLAP_CHARS", 200),
            ),
            llm=LLMSettings(
                provider=_str(env, "LLM_PROVIDER", "ollama"),
                model=_str(env, "OLLAMA_MODEL", "gpt-oss:120b-cloud"),
                base_url=_get(env, "OLLAMA_BASE_URL"),
                temperature=_float(env, "LLM_TEMPERATURE", 0.0),
                timeout_seconds=_float(env, "LLM_TIMEOUT", 120.0),
                stream=_bool(env, "LLM_STREAM", False),
            ),
            reidentification=ReidentificationSettings(
                placeholder_style=_str(env, "PLACEHOLDER_STYLE", "angle"),
                placeholder_pad=_int(env, "PLACEHOLDER_PAD", 3),
                unknown_action=_str(env, "REID_UNKNOWN_ACTION", "redact"),
                scan_output=_bool(env, "SCAN_OUTPUT", True),
                on_drift=_str(env, "ON_DRIFT", "retry"),
                max_drift_retries=_int(env, "MAX_DRIFT_RETRIES", 1),
                tolerant_matching=_bool(env, "REID_TOLERANT", False),
                block_on_injection=_bool(env, "BLOCK_ON_INJECTION", True),
            ),
            observability=ObservabilitySettings(
                log_level=_str(env, "LOG_LEVEL", "INFO"),
                log_format=_str(env, "LOG_FORMAT", "json"),
                allow_unsafe_logging=_bool(env, "ALLOW_UNSAFE_LOGGING", False),
                hash_salt=_str(env, "HASH_SALT", ""),
            ),
            policy_path=_path(env, "POLICY_FILE", Path("config/policy.toml")),
            allowlist_path=_path(env, "ALLOWLIST_FILE", Path("resources/public_entities.txt")),
            denylist_path=_path(env, "DENYLIST_FILE", Path("resources/denylist.txt")),
            fail_mode=fail_mode,  # type: ignore[arg-type]
            persist_mapping=_bool(env, "PERSIST_MAPPING", False),
            mapping_dir=_path(env, "MAPPING_DIR", Path("artifacts/mappings")),
            artifacts_dir=_path(env, "ARTIFACTS_DIR", Path("artifacts")),
        )

    @classmethod
    def for_tests(cls, **overrides: Any) -> Settings:
        """Defaults suited to unit tests: no models, no network."""
        base = cls(
            detectors=DetectorSettings(enabled=("regex",), required=()),
            llm=LLMSettings(provider="mock"),
        )
        return replace(base, **overrides) if overrides else base

    def with_overrides(self, **overrides: Any) -> Settings:
        return replace(self, **overrides)

    def redacted_dict(self) -> dict[str, Any]:
        """Safe to write into a report: no salts, no credentials."""
        return {
            "fail_mode": self.fail_mode,
            "detectors_enabled": list(self.detectors.enabled),
            "detectors_required": list(self.detectors.required),
            "presidio_spacy_model": self.detectors.presidio_spacy_model,
            "ner_model": self.detectors.ner_model,
            "qwen_enabled": self.qwen.enabled,
            "qwen_model": self.qwen.model if self.qwen.enabled else None,
            "llm_provider": self.llm.provider,
            "llm_model": self.llm.model,
            "placeholder_style": self.reidentification.placeholder_style,
            "tolerant_matching": self.reidentification.tolerant_matching,
            "max_input_chars": self.preprocessing.max_input_chars,
            "chunk_size_chars": self.chunking.size_chars,
        }
