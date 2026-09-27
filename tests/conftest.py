"""Shared fixtures.

Two rules shape this file:

* Nothing here imports spaCy, torch, transformers or Presidio. The heavy
  detectors are built inside session-scoped fixtures in the suites that need
  them, and availability is probed with ``importlib.util.find_spec`` and a raw
  socket connect so that collection stays cheap when they are deselected.
* Tests that touch a heavy fixture are marked automatically, so nobody has to
  remember to decorate them.
"""

from __future__ import annotations

import importlib.util
import socket
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


# -- paths -------------------------------------------------------------------

@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def test_data_dir() -> Path:
    return REPO_ROOT / "test_data"


@pytest.fixture(scope="session")
def prototype_fixtures_dir() -> Path:
    return REPO_ROOT / "tests" / "regression" / "fixtures" / "prototype_v0"


# -- source documents --------------------------------------------------------

@pytest.fixture(scope="session")
def raw_transcript(test_data_dir):
    """Read a transcript preserving its CRLF line endings."""

    def _read(filename: str) -> str:
        return (test_data_dir / filename).read_bytes().decode("utf-8")

    return _read


@pytest.fixture(scope="session")
def normalized_transcript(raw_transcript):
    from privacy_gateway.preprocessing.normalizer import Normalizer

    normalizer = Normalizer()
    cache: dict[str, object] = {}

    def _norm(filename: str):
        if filename not in cache:
            cache[filename] = normalizer.normalize(raw_transcript(filename))
        return cache[filename]

    return _norm


# -- availability probes (deliberately import nothing heavy) -----------------

def _spec_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _port_open(host: str, port: int, timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def spacy_model_available() -> bool:
    return _spec_available("en_core_web_lg")


@pytest.fixture(scope="session")
def ollama_available() -> bool:
    return _port_open("127.0.0.1", 11434)


# -- marker plumbing ---------------------------------------------------------

_HEAVY_FIXTURES = {
    "presidio_detector",
    "ner_detector",
    "full_gateway",
    "pod_pipeline_result",
    "sme_pipeline_result",
}
_OLLAMA_FIXTURES = {"ollama_client", "live_qwen_detector"}


def pytest_collection_modifyitems(config, items):
    for item in items:
        names = set(getattr(item, "fixturenames", ()))
        if names & _HEAVY_FIXTURES:
            item.add_marker(pytest.mark.requires_models)
            item.add_marker(pytest.mark.slow)
        if names & _OLLAMA_FIXTURES:
            item.add_marker(pytest.mark.requires_ollama)
        if "regression" in str(item.fspath):
            item.add_marker(pytest.mark.regression)
        if "security" in str(item.fspath):
            item.add_marker(pytest.mark.security)
