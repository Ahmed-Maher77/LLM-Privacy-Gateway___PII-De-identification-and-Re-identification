"""Guards that make a fabricated measurement fail the build.

"Do not invent benchmark results" is not a promise anyone can keep by
remembering. These tests encode it: a percentile the sample cannot support is
never emitted, a Qwen figure cannot appear while Qwen is disabled, and an
end-to-end timing cannot appear in a run that made no network call.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
RESULTS = REPO / "benchmarks" / "results"

spec = importlib.util.spec_from_file_location("bench", REPO / "benchmarks" / "bench.py")
bench = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bench)


# -- percentile suppression --------------------------------------------------

def test_p99_is_withheld_below_one_hundred_samples():
    reported, withheld = bench.percentiles([0.1] * 30)
    assert "p99" not in reported
    assert "n=30" in withheld["p99"]


def test_p95_is_withheld_below_twenty_samples():
    reported, withheld = bench.percentiles([0.1] * 10)
    assert "p95" not in reported and "p95" in withheld


def test_p50_is_reported_once_the_sample_supports_it():
    reported, _ = bench.percentiles([0.1] * 10)
    assert "p50" in reported


def test_p99_appears_once_there_are_a_hundred_samples():
    reported, withheld = bench.percentiles([0.1] * 100)
    assert "p99" in reported and "p99" not in withheld


def test_the_summary_records_why_a_percentile_is_missing():
    summary = bench.summarise([0.1] * 30)
    assert "p99" in summary["percentiles_withheld"]


def test_an_empty_sample_reports_not_measured_rather_than_zero():
    summary = bench.summarise([])
    assert summary["n"] == 0
    assert summary["note"] == "not measured"
    assert "median" not in summary


def test_the_summary_reports_spread_not_just_a_midpoint():
    summary = bench.summarise([0.1, 0.2, 0.3, 0.4, 0.5])
    assert {"min", "max", "stdev", "iqr"} <= set(summary)


def test_percentile_floors_are_documented_constants():
    assert bench.PERCENTILE_FLOORS["p99"] >= 100
    assert bench.PERCENTILE_FLOORS["p95"] >= 20


# -- provenance --------------------------------------------------------------

def test_the_hostname_is_hashed_not_published():
    import platform

    info = bench.machine_info()
    assert platform.node() not in json.dumps(info)
    assert len(info["hostname_sha256_8"]) == 8


def test_machine_info_records_thread_count_when_torch_is_present():
    info = bench.machine_info()
    if info.get("torch"):
        assert "torch_num_threads" in info


def test_the_confound_note_names_the_confound():
    note = bench.CONFOUND_NOTE.lower()
    assert "different prompts" in note
    assert "not" in note and "attributable" in note


# -- shipped results ---------------------------------------------------------

def _result_files():
    return sorted(RESULTS.glob("*.json")) if RESULTS.exists() else []


@pytest.mark.parametrize(
    "path", _result_files() or [pytest.param(None, marks=pytest.mark.skip(reason="no results yet"))]
)
def test_every_results_file_carries_provenance(path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    prov = payload["provenance"]
    for key in ("generated_at_utc", "generated_by", "git_commit", "machine", "mode", "runs"):
        assert key in prov


@pytest.mark.parametrize(
    "path", _result_files() or [pytest.param(None, marks=pytest.mark.skip(reason="no results yet"))]
)
def test_qwen_metrics_are_absent_when_qwen_was_disabled(path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    prov = payload["provenance"]
    if not prov.get("qwen_enabled"):
        assert prov.get("qwen_skip_reason")
        assert "qwen" not in prov.get("detectors", [])


@pytest.mark.parametrize(
    "path", _result_files() or [pytest.param(None, marks=pytest.mark.skip(reason="no results yet"))]
)
def test_llm_metrics_are_absent_when_no_model_was_invoked(path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not payload["provenance"].get("llm_invoked"):
        e2e = payload.get("e2e", {})
        assert e2e.get("metrics") is None
        assert payload["provenance"].get("llm_model") is None


@pytest.mark.parametrize(
    "path", _result_files() or [pytest.param(None, marks=pytest.mark.skip(reason="no results yet"))]
)
def test_no_percentile_exceeds_what_its_sample_supports(path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    overhead = payload.get("overhead") or {}
    for document in (overhead.get("documents") or {}).values():
        summary = document["seconds"]
        n = summary["n"]
        for name, floor in bench.PERCENTILE_FLOORS.items():
            if n < floor:
                assert name not in summary, f"{name} emitted from n={n}"


@pytest.mark.parametrize(
    "path", _result_files() or [pytest.param(None, marks=pytest.mark.skip(reason="no results yet"))]
)
def test_input_files_are_hashed_so_a_stale_result_is_detectable(path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    for entry in payload["provenance"]["input_files"]:
        assert entry["sha256"] and entry["chars"] > 0


# -- the evaluation results share the same guarantees ------------------------

EVAL_RESULTS = REPO / "evaluation" / "results"


def _eval_files():
    return sorted(EVAL_RESULTS.glob("*/metrics.json")) if EVAL_RESULTS.exists() else []


@pytest.mark.parametrize(
    "path", _eval_files() or [pytest.param(None, marks=pytest.mark.skip(reason="no results yet"))]
)
def test_a_skipped_config_has_a_reason_and_null_metrics_not_zeros(path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    for config in payload["configs"]:
        if config["status"] != "ok":
            assert config["reason"]
            assert config["metrics"] is None


@pytest.mark.parametrize(
    "path", _eval_files() or [pytest.param(None, marks=pytest.mark.skip(reason="no results yet"))]
)
def test_evaluation_results_state_who_produced_the_labels(path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    note = payload["dataset"]["labeling_note"]
    assert "NOT by a human" in note
    assert payload["dataset"]["inter_annotator_agreement"] is None


@pytest.mark.parametrize(
    "path", _eval_files() or [pytest.param(None, marks=pytest.mark.skip(reason="no results yet"))]
)
def test_qwen_configs_are_skipped_not_scored_when_disabled(path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload["provenance"].get("qwen_enabled"):
        return
    for config in payload["configs"]:
        if "qwen" in config["detectors"]:
            assert config["status"] == "skipped"
