from __future__ import annotations

from pathlib import Path

import pandas as pd

from privacylens.policy import audit_policy
from privacylens.scanner import scan_frame
from privacylens.store import RunStore


def test_store_persists_masked_evidence_only(tmp_path: Path) -> None:
    raw_email = "private.person@example.com"
    report = scan_frame(pd.DataFrame({"email": [raw_email]}), fingerprint_key="test")
    manifest = RunStore(tmp_path).save(report, audit_policy())
    run_dir = tmp_path / manifest["run_id"]

    assert raw_email not in (run_dir / "report.json").read_text(encoding="utf-8")
    assert raw_email not in (run_dir / "report.html").read_text(encoding="utf-8")
    assert manifest["artifacts"]["report"] == "report.json"
