from __future__ import annotations

from pathlib import Path

from starlette.testclient import TestClient

import web.app as web_app
from privacylens.store import RunStore


def test_health_endpoint() -> None:
    with TestClient(web_app.app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "privacylens"}


def test_upload_scan_creates_masked_run_and_deletes_raw_upload(
    tmp_path: Path, monkeypatch
) -> None:
    run_root = tmp_path / "runs"
    upload_root = tmp_path / "uploads"
    monkeypatch.setattr(web_app, "STORE_ROOT", run_root)
    monkeypatch.setattr(web_app, "UPLOAD_ROOT", upload_root)
    monkeypatch.setattr(web_app, "store", RunStore(run_root))
    content = b"email,phone\nprivate.person@example.com,415-555-0101\n"

    with TestClient(web_app.app) as client:
        response = client.post(
            "/analyze",
            data={"mode": "audit"},
            files={"data_file": ("customers.csv", content, "text/csv")},
            follow_redirects=False,
        )

    assert response.status_code == 303
    manifest = RunStore(run_root).list_runs()[0]
    report_text = (run_root / manifest["run_id"] / "report.json").read_text(encoding="utf-8")
    assert "private.person@example.com" not in report_text
    assert not list(upload_root.glob("*"))


def test_api_scan_is_non_persistent(tmp_path: Path, monkeypatch) -> None:
    run_root = tmp_path / "runs"
    upload_root = tmp_path / "uploads"
    monkeypatch.setattr(web_app, "UPLOAD_ROOT", upload_root)
    monkeypatch.setattr(web_app, "store", RunStore(run_root))

    with TestClient(web_app.app) as client:
        response = client.post(
            "/api/scan",
            files={"data_file": ("data.csv", b"email\none@example.com\n", "text/csv")},
        )

    assert response.status_code == 200
    assert response.json()["category_counts"]["email"] >= 1
    assert not RunStore(run_root).list_runs()
    assert not list(upload_root.glob("*"))
