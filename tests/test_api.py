import pytest
from fastapi.testclient import TestClient

from api import server
from api.server import app

client = TestClient(app)


def test_report_and_vendor_endpoints():
    r = client.get("/api/report")
    assert r.status_code == 200
    top = r.json()["ranked_vendors"][0]["vendor_id"]
    assert client.get(f"/api/vendor/{top}").json()["vendor_id"] == top
    assert client.get("/api/vendor/NOPE").status_code == 404


def test_dashboard_is_served():
    assert client.get("/").status_code == 200


@pytest.mark.parametrize("contents", [None, b'{"ranked_vendors":', b"\xff"])
def test_report_read_failure_returns_service_unavailable(monkeypatch, tmp_path, contents):
    report_path = tmp_path / "report.json"
    if contents is not None:
        report_path.write_bytes(contents)
    monkeypatch.setattr(server, "DATA", report_path)

    for url in ("/api/report", "/api/vendor/example", "/api/advisory/example"):
        response = client.get(url)
        assert response.status_code == 503
        assert "python pipeline.py" in response.json()["detail"]
