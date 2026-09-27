"""PII de-identification and re-identification for LLM calls."""

from .custom_patterns import CustomPatternConfig, PatternConfigError, build_rules, load_config
from .detector import DEFAULT_LABELS, DEFAULT_MODEL, DEFAULT_THRESHOLD, GlinerDetector
from .entities import Entity, resolve_aliases
from .errors import (
    DetectorUnavailable,
    LeakDetected,
    PIIError,
    PlaceholderInjection,
    ReviewRequired,
)
from .middleware import (
    AnonymizationResult,
    Detector,
    PIIMiddleware,
    audit,
    dedupe_placeholders,
    validate_output,
)
from .patterns import PatternRule, detect_patterns
from .policy import PROTECTED_TERMS, is_allowlisted, is_protected_term
from .residual import Finding, ResidualPolicy, explain, scan_residual, severity_counts
from .roster import extract_roster, name_variants, propagate_names, propagate_terms, rejoin_split_names
from .spacy_detector import SpacyDetector
from .spans import Span, SpanSet, apply_spans
from .structure import StructureMap, analyze_structure, protect_spans
from .titles import detect_titles
from .vault import PseudonymVault, find_template_literals, format_placeholder, restore

__all__ = [
    "AnonymizationResult",
    "CustomPatternConfig",
    "DEFAULT_LABELS",
    "DEFAULT_MODEL",
    "DEFAULT_THRESHOLD",
    "Detector",
    "Entity",
    "DetectorUnavailable",
    "Finding",
    "GlinerDetector",
    "LeakDetected",
    "PIIError",
    "PIIMiddleware",
    "PatternConfigError",
    "PatternRule",
    "PROTECTED_TERMS",
    "PlaceholderInjection",
    "PseudonymVault",
    "ResidualPolicy",
    "ReviewRequired",
    "SpacyDetector",
    "Span",
    "SpanSet",
    "StructureMap",
    "analyze_structure",
    "apply_spans",
    "audit",
    "build_rules",
    "detect_patterns",
    "detect_titles",
    "dedupe_placeholders",
    "explain",
    "extract_roster",
    "find_template_literals",
    "format_placeholder",
    "is_allowlisted",
    "is_protected_term",
    "load_config",
    "name_variants",
    "propagate_names",
    "propagate_terms",
    "rejoin_split_names",
    "protect_spans",
    "restore",
    "resolve_aliases",
    "scan_residual",
    "severity_counts",
    "validate_output",
]
