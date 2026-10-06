"""The policy engine: what this deployment actually protects.

Precedence, first match wins, and the winning rule is recorded on the decision
so every outcome is explainable:

1. **denylist** -- always protect, whatever the confidence
2. **allowlist** -- public names, not worth protecting
3. **unknown type** -- protect by default; a detector emitting a label nobody
   configured must not silently leak
4. **below the type's confidence threshold** -- allow when failing open,
   *protect* when failing closed. That asymmetry is the entire point of the
   fail mode.
5. **the type's default action**
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from ..entities.entity import DetectedEntity
from ..errors import ConfigError
from .actions import DEFAULT_RULES, FALLBACK_RULE, TRANSFORMING, Action, EntityRule
from .allowlist import Allowlist

DEFAULT_POLICY_PATH = Path("config/policy.toml")
DEFAULT_ALLOWLIST_PATH = Path("resources/public_entities.txt")
DEFAULT_DENYLIST_PATH = Path("resources/denylist.txt")


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    entity: DetectedEntity
    action: Action
    rule: EntityRule
    rule_id: str
    reason: str = ""

    @property
    def transforms(self) -> bool:
        return self.action in TRANSFORMING

    def __repr__(self) -> str:  # never include the entity's text
        return (
            f"PolicyDecision({self.entity.entity_type} {self.entity.start}:{self.entity.end} "
            f"-> {self.action} via {self.rule_id})"
        )


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    rules: Mapping[str, EntityRule] = field(default_factory=lambda: dict(DEFAULT_RULES))
    unknown_type_action: Action = Action.PSEUDONYMIZE
    below_threshold_action: Action = Action.ALLOW
    below_threshold_action_failclosed: Action = Action.PSEUDONYMIZE

    @classmethod
    def load(cls, path: Path | str = DEFAULT_POLICY_PATH) -> PolicyConfig:
        path = Path(path)
        if not path.exists():
            return cls()
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"policy file is not valid TOML: {path}") from exc
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PolicyConfig:
        rules = dict(DEFAULT_RULES)
        for entity_type, block in (data.get("entity") or {}).items():
            key = entity_type.upper()
            base = rules.get(key, replace(FALLBACK_RULE, entity_type=key))
            try:
                action = Action(str(block.get("action", base.action)))
            except ValueError as exc:
                raise ConfigError(
                    f"[entity.{entity_type}].action is not a known action: "
                    f"{block.get('action')!r}"
                ) from exc
            try:
                rules[key] = EntityRule(
                    entity_type=key,
                    action=action,
                    min_confidence=float(block.get("min_confidence", base.min_confidence)),
                    placeholder_prefix=str(
                        block.get("placeholder_prefix", base.placeholder_prefix)
                    ).upper(),
                    case_sensitive=bool(block.get("case_sensitive", base.case_sensitive)),
                    max_chars=int(block.get("max_chars", base.max_chars)),
                )
            except ValueError as exc:
                raise ConfigError(f"[entity.{entity_type}]: {exc}") from exc

        defaults = data.get("defaults") or {}
        try:
            unknown = Action(str(defaults.get("unknown_type_action", Action.PSEUDONYMIZE)))
            below = Action(str(defaults.get("below_threshold_action", Action.ALLOW)))
        except ValueError as exc:
            raise ConfigError(f"[defaults]: unknown action name ({exc})") from exc

        return cls(
            rules=rules,
            unknown_type_action=unknown,
            below_threshold_action=below,
        )


class PolicyEngine:
    """Maps detected entities onto actions."""

    def __init__(
        self,
        config: PolicyConfig | None = None,
        allowlist: Allowlist | None = None,
        denylist: Allowlist | None = None,
        *,
        fail_closed: bool = True,
    ) -> None:
        self.config = config or PolicyConfig()
        self.allowlist = allowlist or Allowlist()
        self.denylist = denylist or Allowlist()
        self.fail_closed = fail_closed

    @classmethod
    def from_paths(
        cls,
        policy_path: Path | str = DEFAULT_POLICY_PATH,
        allowlist_path: Path | str = DEFAULT_ALLOWLIST_PATH,
        denylist_path: Path | str = DEFAULT_DENYLIST_PATH,
        *,
        fail_closed: bool = True,
    ) -> PolicyEngine:
        return cls(
            PolicyConfig.load(policy_path),
            Allowlist.load(allowlist_path),
            Allowlist.load(denylist_path),
            fail_closed=fail_closed,
        )

    def rule_for(self, entity_type: str) -> EntityRule:
        rule = self.config.rules.get(entity_type)
        if rule is not None:
            return rule
        return replace(FALLBACK_RULE, entity_type=entity_type)

    def decide(self, entity: DetectedEntity) -> PolicyDecision:
        rule = self.rule_for(entity.entity_type)
        value = entity.text.strip()
        known = entity.entity_type in self.config.rules

        if self.denylist.matches(entity.entity_type, value):
            return PolicyDecision(
                entity, Action.PSEUDONYMIZE, rule, "denylist", "explicitly always protected"
            )

        if self.allowlist.matches(entity.entity_type, value):
            return PolicyDecision(
                entity, Action.ALLOW, rule, "allowlist", "public name, identifies no one"
            )

        if not known:
            action = self.config.unknown_type_action
            return PolicyDecision(
                entity,
                action,
                rule,
                f"unknown_type:{entity.entity_type}",
                "type is not configured; defaulting to protect",
            )

        if entity.confidence < rule.min_confidence:
            action = (
                self.config.below_threshold_action_failclosed
                if self.fail_closed
                else self.config.below_threshold_action
            )
            return PolicyDecision(
                entity,
                action,
                rule,
                f"threshold:{entity.entity_type}",
                f"confidence {entity.confidence:.2f} < {rule.min_confidence:.2f}",
            )

        return PolicyDecision(entity, rule.action, rule, f"type_default:{entity.entity_type}")

    def decide_all(self, entities: Sequence[DetectedEntity]) -> tuple[PolicyDecision, ...]:
        return tuple(self.decide(e) for e in entities)
