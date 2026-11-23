"""The committed demo data is regenerable, and the pipeline tells the documented story."""
import json
import os

import pytest

import generate_synthetic as gen
import pipeline

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYN = os.path.join(ROOT, "data", "synthetic")


def load(name):
    with open(os.path.join(SYN, name), encoding="utf-8") as f:
        return json.load(f)


def test_committed_synthetic_data_matches_the_generator():
    vendors, leaked, stealer = gen.build_world(seed=42)
    raw, truth = gen.split_truth(stealer)
    assert vendors == load("vendors.json")
    assert leaked == load("leaked_credentials.json")
    assert raw == load("stealer_logs.json")
    assert truth == load("ground_truth.json")


def test_offline_dashboard_snapshot_matches_api_report():
    with open(os.path.join(ROOT, "data", "report.json"), encoding="utf-8") as f:
        api_report = json.load(f)
    with open(os.path.join(ROOT, "web", "report_data.js"), encoding="utf-8") as f:
        snapshot = f.read().strip()
    prefix = "window.__REPORT__ = "
    assert snapshot.startswith(prefix) and snapshot.endswith(";")
    assert json.loads(snapshot[len(prefix):-1]) == api_report
    assert api_report["meta"]["source"] == "mock"


def test_failed_snapshot_staging_preserves_previous_report(monkeypatch, tmp_path):
    data_dir = tmp_path / "data"
    web_dir = tmp_path / "web"
    old_report = {"source": "이전"}
    pipeline._write_report_files(old_report, data_dir, web_dir)
    snapshot_path = web_dir / "report_data.js"
    old_snapshot = snapshot_path.read_text(encoding="utf-8")
    write_text = type(snapshot_path).write_text

    def fail_snapshot(path, *args, **kwargs):
        if path.name == snapshot_path.name:
            raise OSError("snapshot write failed")
        return write_text(path, *args, **kwargs)

    monkeypatch.setattr(type(snapshot_path), "write_text", fail_snapshot)
    with pytest.raises(OSError, match="snapshot write failed"):
        pipeline._write_report_files({"source": "신규"}, data_dir, web_dir)

    assert json.loads((data_dir / "report.json").read_text(encoding="utf-8")) == old_report
    assert snapshot_path.read_text(encoding="utf-8") == old_snapshot
    assert sorted(path.name for path in data_dir.iterdir()) == ["report.json"]
    assert sorted(path.name for path in web_dir.iterdir()) == ["report_data.js"]


@pytest.fixture(scope="module")
def report():
    return pipeline.run("mock", write=False)


def test_demo_kpis(report):
    k = report["kpis"]
    assert k["early_warning_lead_days"] == 8
    assert (k["matched_exposed_credentials"], k["total_observed_credentials"]) == (171, 248)
    assert report["ranked_vendors"][0]["name"] == "태성회로"


def test_demo_evaluation_is_reported_honestly(report):
    camp = report["evaluation"]["campaign_detection"]
    assert (camp["ground_truth"], camp["detected"], camp["true_positive"]) == (1, 2, 1)
    assert camp["precision"] == 0.5 and camp["recall"] == 1.0
    assert report["kpis"]["campaign_precision_pct"] == 50


def test_no_signal_vendor_is_not_reported_safe(report):
    row = next(r for r in report["ranked_vendors"] if r["name"] == gen.NO_SIGNAL_VENDOR)
    assert "NO SIGNAL" in row["status"]
