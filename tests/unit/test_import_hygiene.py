"""The fast/heavy boundary, enforced rather than assumed.

The core of the gateway must be importable and testable without spaCy, torch,
transformers or Presidio in the process. That is not a style preference: it is
what keeps the unit suite at a few seconds, and it is what lets the pipeline's
correctness be tested independently of any model.

A convention would rot in a week — one convenience re-export in
``detectors/__init__.py`` destroys it. These tests make the boundary something
the build checks, and the last one has real teeth: it runs the unit suite in a
subprocess with the ML frameworks blocked at import time.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "privacy_gateway"
REPO = Path(__file__).resolve().parents[2]

#: Frameworks that must not be pulled in by importing the core.
HEAVY = ("torch", "spacy", "transformers", "presidio_analyzer", "presidio_anonymizer")

#: Modules that make up the model-free core.
CORE_MODULES = [
    "privacy_gateway.config",
    "privacy_gateway.errors",
    "privacy_gateway.gateway",
    "privacy_gateway.entities.entity",
    "privacy_gateway.entities.spans",
    "privacy_gateway.aggregation.aggregator",
    "privacy_gateway.policy.engine",
    "privacy_gateway.pseudonymization.applier",
    "privacy_gateway.pseudonymization.mapping_store",
    "privacy_gateway.reidentification.restorer",
    "privacy_gateway.reidentification.drift",
    "privacy_gateway.reidentification.injection",
    "privacy_gateway.preprocessing.normalizer",
    "privacy_gateway.preprocessing.transcript",
    "privacy_gateway.detectors.base",
    "privacy_gateway.detectors.regex_detector",
    "privacy_gateway.detectors.domain_detector",
    "privacy_gateway.llm.mock_client",
]


def _imported_names(path: Path) -> set[str]:
    """Every module this file imports, relative imports included.

    Relative imports matter most here: ``from .presidio_detector import ...``
    in a package __init__ is exactly the convenience re-export that would
    destroy the boundary, and it is the form a contributor is most likely to
    reach for.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative: `from . import x` or `from .mod import x`
                names.add("." * node.level + (node.module or ""))
            elif node.module:
                names.add(node.module.split(".")[0])
    return names


def test_the_detectors_package_init_is_import_free():
    # A single `from .presidio_detector import PresidioDetector` here would
    # drag spaCy into every import of the package.
    init = SRC / "detectors" / "__init__.py"
    assert _imported_names(init) == set(), "detectors/__init__.py must not import anything"


@pytest.mark.parametrize(
    "package", ["entities", "aggregation", "policy", "pseudonymization", "reidentification", "llm"]
)
def test_package_inits_stay_import_free(package):
    init = SRC / package / "__init__.py"
    if init.exists():
        assert _imported_names(init) == set()


def test_detectors_are_built_through_a_string_keyed_registry():
    # The factory table holds module paths, not imported objects, so the import
    # happens inside build_detector() and only for the detector requested.
    from privacy_gateway.detectors.base import _FACTORIES

    for target in _FACTORIES.values():
        assert ":" in target and target.startswith("privacy_gateway.detectors.")


def test_constructing_a_model_backed_detector_does_not_load_its_model():
    # __init__ stores configuration; warmup() loads weights.
    from privacy_gateway.detectors.presidio_detector import PresidioDetector

    detector = PresidioDetector()
    assert detector._analyzer is None


def test_importing_the_core_pulls_in_no_ml_framework():
    # Run in a subprocess so a sibling test cannot pollute sys.modules.
    code = (
        "import sys\n"
        + "".join(f"import {m}\n" for m in CORE_MODULES)
        + f"bad = [m for m in {HEAVY!r} if m in sys.modules]\n"
        "assert not bad, bad\n"
        "print('clean')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, cwd=REPO, timeout=180
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "clean" in result.stdout


def test_building_a_deterministic_detector_pulls_in_no_ml_framework():
    code = (
        "import sys\n"
        "from privacy_gateway.detectors.base import build_detector\n"
        "build_detector('regex')\n"
        "build_detector('domain')\n"
        f"bad = [m for m in {HEAVY!r} if m in sys.modules]\n"
        "assert not bad, bad\n"
        "print('clean')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, cwd=REPO, timeout=180
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.slow
def test_the_model_free_unit_suite_runs_with_ml_imports_blocked(tmp_path):
    """The guarantee with teeth.

    Installs an import hook that raises for every ML framework, then runs the
    unit suite. If anything in that suite reaches for torch or spaCy, this
    fails -- which is the only way to be sure the boundary is real.
    """
    plugin = tmp_path / "block_ml.py"
    plugin.write_text(
        "import sys\n"
        f"BLOCKED = {HEAVY!r}\n"
        "class Blocker:\n"
        "    def find_module(self, name, path=None):\n"
        "        return self.find_spec(name, path)\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name.split('.')[0] in BLOCKED:\n"
        "            raise ImportError(f'blocked by test: {name}')\n"
        "        return None\n"
        "sys.meta_path.insert(0, Blocker())\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/unit",
            "-q",
            "-p",
            "no:cacheprovider",
            # Exclude this file: it spawns the inner run, so including it would
            # recurse until the timeout.
            "--ignore=tests/unit/test_import_hygiene.py",
            "-m",
            "not requires_models",
            "--timeout=120",
        ],
        capture_output=True,
        text=True,
        cwd=REPO,
        timeout=600,
        env={
            **_clean_env(),
            "PYTHONPATH": str(tmp_path),
            "PYTEST_PLUGINS": "block_ml",
        },
    )
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-2000:]


def _clean_env() -> dict[str, str]:
    import os

    return {k: v for k, v in os.environ.items() if k != "PYTEST_PLUGINS"}
