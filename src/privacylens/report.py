"""Privacy-safe JSON and standalone HTML report rendering."""

from __future__ import annotations

import html
import json
from pathlib import Path

from privacylens.models import SanitizationResult, ScanReport
from privacylens.policy import PrivacyPolicy


def report_payload(
    report: ScanReport,
    *,
    policy: PrivacyPolicy | None = None,
    sanitization: SanitizationResult | None = None,
) -> dict[str, object]:
    """Build a complete report payload without source values."""

    payload: dict[str, object] = {"scan": report.to_dict()}
    if policy is not None:
        payload["policy"] = policy.to_dict()
    if sanitization is not None:
        payload["sanitization"] = sanitization.summary()
    return payload


def write_json_report(payload: dict[str, object], path: str | Path) -> Path:
    """Persist a privacy report as formatted JSON."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return destination


def render_html_report(report: ScanReport) -> str:
    """Render a portable HTML audit report containing masked evidence only."""

    categories = "".join(
        f"<tr><td>{html.escape(category)}</td><td>{count}</td></tr>"
        for category, count in report.category_counts.items()
    ) or '<tr><td colspan="2">No sensitive categories detected.</td></tr>'
    findings = "".join(
        "<tr>"
        f"<td>{item.row_number}</td>"
        f"<td>{html.escape(item.column)}</td>"
        f"<td>{html.escape(item.category)}</td>"
        f"<td>{html.escape(item.severity)}</td>"
        f"<td>{html.escape(item.masked_preview)}</td>"
        f"<td><code>{html.escape(item.fingerprint)}</code></td>"
        "</tr>"
        for item in report.findings[:500]
    ) or '<tr><td colspan="6">No findings.</td></tr>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PrivacyLens report | {html.escape(report.source_name)}</title>
<style>
body{{font-family:system-ui,sans-serif;margin:0;background:#f5f7f8;color:#172027}}main{{max-width:1100px;margin:auto;padding:36px 24px}}
h1{{margin:0}}.meta{{color:#5f6d76}}.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:24px 0}}
.metric{{background:white;border:1px solid #d8e0e4;padding:16px;border-radius:6px}}.metric strong{{display:block;font-size:28px}}
section{{margin-top:30px}}table{{border-collapse:collapse;width:100%;background:white;font-size:13px}}th,td{{padding:9px;border-bottom:1px solid #e2e8eb;text-align:left}}
th{{color:#53636d}}code{{font-size:11px}}.notice{{border-left:4px solid #087f8c;padding:12px 16px;background:#eaf6f7}}
@media(max-width:700px){{.metrics{{grid-template-columns:1fr 1fr}}.table{{overflow:auto}}}}
</style></head><body><main>
<p class="meta">PRIVACYLENS / LOCAL-FIRST AUDIT</p><h1>{html.escape(report.source_name)}</h1>
<p class="meta">Scanned {html.escape(report.scanned_at)}</p>
<div class="metrics"><div class="metric"><span>Risk</span><strong>{report.risk_score}</strong><small>{html.escape(report.risk_level)}</small></div>
<div class="metric"><span>Findings</span><strong>{len(report.findings)}</strong></div><div class="metric"><span>Rows</span><strong>{report.row_count}</strong></div>
<div class="metric"><span>Cells scanned</span><strong>{report.cells_scanned}</strong></div></div>
<p class="notice">This report contains masked previews and run-scoped fingerprints only. Raw detected values are not included.</p>
<section><h2>Category inventory</h2><table><thead><tr><th>Category</th><th>Findings</th></tr></thead><tbody>{categories}</tbody></table></section>
<section><h2>Finding evidence</h2><div class="table"><table><thead><tr><th>Row</th><th>Column</th><th>Category</th><th>Severity</th><th>Preview</th><th>Fingerprint</th></tr></thead><tbody>{findings}</tbody></table></div></section>
</main></body></html>"""


def write_html_report(report: ScanReport, path: str | Path) -> Path:
    """Persist a standalone masked HTML report."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_html_report(report), encoding="utf-8")
    return destination
