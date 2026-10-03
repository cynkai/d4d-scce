from fastapi.testclient import TestClient

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
