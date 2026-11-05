"""Defect 8 of the Windows integration test: training rewrote a tracked report.

src/train_behavioral_model.py wrote its metrics to models/ - which the ML
container mounts and reads first - and to reports/behavioral_model_metrics.json,
which is committed evidence (TC-21 and the engine's fallback read it). So every
retrain left a diff in a tracked file; the VM checkout had exactly that diff.
The reports/ copy is now written only under URDS_WRITE_REPORTS=1.

Only write_metrics is exercised: training itself builds a corpus and fits a
model, and none of that decides where the file goes.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "src" / "train_behavioral_model.py"


@pytest.fixture(scope="module")
def training():
    spec = importlib.util.spec_from_file_location("urds_train_behavioral_model", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_plain_run_writes_models_and_leaves_the_committed_report_alone(training, tmp_path, monkeypatch):
    monkeypatch.delenv("URDS_WRITE_REPORTS", raising=False)
    models, reports = tmp_path / "models", tmp_path / "reports"
    reports.mkdir()
    committed = reports / "behavioral_model_metrics.json"
    committed.write_text('{"accuracy": 0.884}')

    written = training.write_metrics('{"accuracy": 0.9}', model_dir=models, reports_dir=reports)

    assert written == [models / "behavioral_model_metrics.json"]
    assert (models / "behavioral_model_metrics.json").read_text() == '{"accuracy": 0.9}'
    assert committed.read_text() == '{"accuracy": 0.884}'


@pytest.mark.parametrize("value", ["1", "true", "yes"])
def test_asking_for_it_refreshes_the_committed_report_too(training, tmp_path, monkeypatch, value):
    monkeypatch.setenv("URDS_WRITE_REPORTS", value)
    models, reports = tmp_path / "models", tmp_path / "reports"

    written = training.write_metrics('{"accuracy": 0.9}', model_dir=models, reports_dir=reports)

    assert written == [models / "behavioral_model_metrics.json", reports / "behavioral_model_metrics.json"]
    assert (reports / "behavioral_model_metrics.json").read_text() == '{"accuracy": 0.9}'


def test_the_defaults_are_the_directories_the_engine_reads(training):
    assert training.MODEL_DIR == REPO_ROOT / "models"
    assert training.REPORTS_DIR == REPO_ROOT / "reports"
