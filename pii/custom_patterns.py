"""Organisation-specific patterns loaded from TOML.

Driver's licence, member-ID and employee-code formats differ per organisation,
so they cannot all live in library code. This loads extra rules from an
optional ``pii_patterns.toml`` using stdlib ``tomllib`` -- no new dependency.

The config file is **trusted operator input, not untrusted data**. It executes
no code, but a pathological regex can still hang the process, because Python's
``re`` has no timeout. Treat it with the same care as a firewall rule.
"""

from __future__ import annotations

import os
import re
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType

from .patterns import BUILTIN_RULES, MIN_PATTERN_SCORE, PatternRule

CONFIG_ENV_VAR = "PII_PATTERNS_CONFIG"
CONFIG_FILENAMES = ("pii_patterns.toml", ".pii-patterns.toml")
LABEL_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,31}$")
ALLOWED_FLAGS = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
    "VERBOSE": re.VERBOSE,
}
SUPPORTED_VERSION = 1

_TOP_LEVEL_KEYS = {"version", "settings", "patterns", "exclusions"}
_PATTERN_KEYS = {
    "label",
    "regex",
    "group",
    "score",
    "flags",
    "priority",
    "keywords",
    "context_window",
    "examples",
    "counter_examples",
    "description",
}

# A crude nested-quantifier smoke alarm. Not a guarantee -- catastrophic
# backtracking is undecidable in general -- but it catches the usual shapes.
_REDOS_RE = re.compile(r"\([^)]*[+*][^)]*\)\s*[+*{]")


class PatternConfigError(ValueError):
    """The TOML file is malformed. Raised at load time, never at scan time."""


@dataclass(frozen=True, slots=True)
class CustomPatternConfig:
    rules: tuple[PatternRule, ...] = ()
    min_score: float = MIN_PATTERN_SCORE
    label_priority: Mapping[str, int] = field(default_factory=lambda: MappingProxyType({}))
    id_prefix_stoplist: frozenset[str] = frozenset()
    disabled_labels: frozenset[str] = frozenset()
    replace_builtins: bool = False
    source: Path | None = None

    @property
    def labels(self) -> frozenset[str]:
        return frozenset(rule.label for rule in self.rules)


EMPTY_CONFIG = CustomPatternConfig()


def find_config(
    explicit: str | Path | None = None,
    start: Path | None = None,
) -> Path | None:
    """Resolve the config path: explicit argument, then env var, then search."""
    if explicit is not None:
        path = Path(explicit)
        return path if path.is_file() else None

    from_env = os.environ.get(CONFIG_ENV_VAR)
    if from_env:
        path = Path(from_env)
        return path if path.is_file() else None

    directory = (start or Path.cwd()).resolve()
    for candidate_dir in (directory, *directory.parents):
        for name in CONFIG_FILENAMES:
            candidate = candidate_dir / name
            if candidate.is_file():
                return candidate
    return None


def load_config(path: str | Path | None = None) -> CustomPatternConfig:
    """Load custom rules. A missing file is not an error; a broken one is."""
    resolved = find_config(path)
    if resolved is None:
        return EMPTY_CONFIG
    return _load_cached(resolved, resolved.stat().st_mtime_ns)


@lru_cache(maxsize=8)
def _load_cached(resolved: Path, mtime_ns: int) -> CustomPatternConfig:
    """Cached on (path, mtime) so a long-lived process picks up edits."""
    try:
        with resolved.open("rb") as handle:
            data = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise PatternConfigError(f"{resolved}: invalid TOML: {exc}") from exc

    unknown = set(data) - _TOP_LEVEL_KEYS
    if unknown:
        raise PatternConfigError(f"{resolved}: unknown top-level key(s): {sorted(unknown)}")

    version = data.get("version", SUPPORTED_VERSION)
    if version != SUPPORTED_VERSION:
        raise PatternConfigError(
            f"{resolved}: version {version!r} unsupported; expected {SUPPORTED_VERSION}"
        )

    settings = data.get("settings", {}) or {}
    exclusions = data.get("exclusions", {}) or {}
    tables = data.get("patterns", []) or []

    rules: list[PatternRule] = []
    priorities: dict[str, int] = {}
    for index, table in enumerate(tables):
        rule, priority = _rule_from_table(table, index, resolved)
        rules.append(rule)
        if priority is not None:
            priorities[rule.label] = priority

    return CustomPatternConfig(
        rules=tuple(rules),
        min_score=float(settings.get("min_score", MIN_PATTERN_SCORE)),
        label_priority=MappingProxyType(priorities),
        id_prefix_stoplist=frozenset(
            str(item).casefold() for item in exclusions.get("id_prefixes", [])
        ),
        disabled_labels=frozenset(str(item) for item in exclusions.get("labels", [])),
        replace_builtins=bool(settings.get("replace_builtins", False)),
        source=resolved,
    )


def _rule_from_table(
    table: Mapping[str, object],
    index: int,
    source: Path,
) -> tuple[PatternRule, int | None]:
    where = f"{source}:[[patterns]][{index}]"

    unknown = set(table) - _PATTERN_KEYS
    if unknown:
        raise PatternConfigError(f"{where}: unknown key(s): {sorted(unknown)}")

    label = table.get("label")
    if not isinstance(label, str) or not LABEL_RE.match(label):
        raise PatternConfigError(f"{where}: label must match {LABEL_RE.pattern}, got {label!r}")

    raw = table.get("regex")
    if not isinstance(raw, str) or not raw:
        raise PatternConfigError(f"{where}: 'regex' is required")

    flag_value = 0
    for name in table.get("flags", []) or []:
        if name not in ALLOWED_FLAGS:
            raise PatternConfigError(
                f"{where}: unsupported flag {name!r}; allowed: {sorted(ALLOWED_FLAGS)}"
            )
        flag_value |= ALLOWED_FLAGS[name]

    try:
        compiled = re.compile(raw, flag_value)
    except re.error as exc:
        raise PatternConfigError(f"{where}: regex does not compile: {exc}") from exc

    if _REDOS_RE.search(raw):
        raise PatternConfigError(
            f"{where}: nested unbounded quantifier looks like a backtracking hazard"
        )

    # A zero-width pattern would emit end == start and blow up inside Span.
    if compiled.search("") is not None:
        raise PatternConfigError(f"{where}: regex matches the empty string")

    group = table.get("group", 0)
    if isinstance(group, bool) or not isinstance(group, (int, str)):
        raise PatternConfigError(f"{where}: 'group' must be an int or a group name")
    if isinstance(group, int) and not 0 <= group <= compiled.groups:
        raise PatternConfigError(
            f"{where}: group {group} out of range (pattern has {compiled.groups})"
        )
    if isinstance(group, str) and group not in compiled.groupindex:
        raise PatternConfigError(f"{where}: no group named {group!r}")

    score = float(table.get("score", 1.0))
    if not 0.0 < score <= 1.0:
        raise PatternConfigError(f"{where}: 'score' must be in (0.0, 1.0], got {score}")

    _check_examples(compiled, group, table, where)

    priority = table.get("priority")
    if priority is not None and not isinstance(priority, int):
        raise PatternConfigError(f"{where}: 'priority' must be an integer")

    return PatternRule(label=label, pattern=compiled, group=group, base_score=score), priority


def _check_examples(
    compiled: re.Pattern[str],
    group: int | str,
    table: Mapping[str, object],
    where: str,
) -> None:
    """Assert the declared examples behave as claimed.

    The highest-value validation in the file: it turns a silent typo that
    makes a rule match nothing into a startup failure.
    """
    for sample in table.get("examples", []) or []:
        match = compiled.search(str(sample))
        if match is None or match.span(group)[0] < 0:
            raise PatternConfigError(f"{where}: example {sample!r} does not match")

    for sample in table.get("counter_examples", []) or []:
        if compiled.search(str(sample)) is not None:
            raise PatternConfigError(f"{where}: counter-example {sample!r} unexpectedly matches")


def build_rules(
    config: CustomPatternConfig,
    builtins: Sequence[PatternRule] = BUILTIN_RULES,
) -> tuple[PatternRule, ...]:
    """Merge custom rules with the built-ins, honouring the exclusions."""
    if config.replace_builtins:
        return tuple(config.rules)
    kept = [rule for rule in builtins if rule.label not in config.disabled_labels]
    return tuple([*kept, *config.rules])
