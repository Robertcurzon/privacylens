"""Starlette web application for local-first privacy analysis."""

from __future__ import annotations

import os
import secrets
from collections import Counter
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from privacylens.io import load_table
from privacylens.policy import audit_policy, redaction_policy, strict_policy
from privacylens.sanitizer import sanitize_frame
from privacylens.scanner import scan_frame
from privacylens.store import RunStore


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = Path(os.getenv("PRIVACYLENS_DATA_DIR", PROJECT_ROOT / "data/runtime"))
STORE_ROOT = RUNTIME_ROOT / "runs"
UPLOAD_ROOT = RUNTIME_ROOT / "uploads"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
ALLOWED_SUFFIXES = {".csv", ".parquet", ".json", ".jsonl"}

templates = Jinja2Templates(directory=PROJECT_ROOT / "web/templates")
store = RunStore(STORE_ROOT)


def _policy_for_mode(mode: str):
    if mode == "sanitize":
        return redaction_policy()
    if mode == "strict":
        return strict_policy()
    return audit_policy()


def ensure_demo() -> None:
    """Create a masked demonstration report for first-time visitors."""

    if store.list_runs():
        return
    source = PROJECT_ROOT / "data/sample/customer_records.csv"
    frame = load_table(source)
    report = scan_frame(frame, source_name="synthetic_customer_demo.csv", fingerprint_key="demo")
    store.save(report, audit_policy())


def _view_model(run_id: str | None = None) -> dict[str, Any]:
    runs = store.list_runs()
    if not runs:
        return {"runs": [], "selected": None}
    selected_id = run_id or runs[0]["run_id"]
    try:
        selected = store.load(selected_id)
    except FileNotFoundError:
        selected = store.load(runs[0]["run_id"])
    scan = selected["scan"]
    selected["severity_counts"] = dict(
        Counter(item["severity"] for item in scan["findings"])
    )
    selected["top_findings"] = scan["findings"][:100]
    return {"runs": runs, "selected": selected}


async def homepage(request: Request) -> Response:
    """Render the selected privacy run."""

    ensure_demo()
    return templates.TemplateResponse(
        request,
        "index.html",
        _view_model(request.query_params.get("run")),
    )


async def _save_upload(upload: UploadFile) -> Path:
    filename = Path(upload.filename or "upload.csv").name
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(400, f"Unsupported upload type: {suffix}")
    content = await upload.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Uploads are limited to 25 MB in the public demo")
    UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
    destination = UPLOAD_ROOT / f"upload-{secrets.token_hex(6)}{suffix}"
    destination.write_bytes(content)
    return destination


def _run(path: Path, filename: str, mode: str) -> dict[str, Any]:
    frame = load_table(path)
    policy = _policy_for_mode(mode)
    report = scan_frame(
        frame,
        source_name=filename,
        fingerprint_key=os.getenv("PRIVACYLENS_HASH_KEY"),
    )
    result = None
    if mode != "audit":
        result = sanitize_frame(
            frame,
            report,
            policy,
            hash_key=os.getenv("PRIVACYLENS_HASH_KEY"),
        )
    return store.save(report, policy, result)


async def analyze(request: Request) -> Response:
    """Scan an uploaded file and immediately remove the raw upload."""

    form = await request.form()
    upload = form.get("data_file")
    if not isinstance(upload, UploadFile) or not upload.filename:
        raise HTTPException(400, "Choose a data file to scan")
    mode = str(form.get("mode") or "audit")
    if mode not in {"audit", "sanitize", "strict"}:
        raise HTTPException(400, "Unknown privacy mode")
    path = await _save_upload(upload)
    try:
        try:
            manifest = _run(path, Path(upload.filename).name, mode)
        except (RuntimeError, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc
    finally:
        path.unlink(missing_ok=True)
    return RedirectResponse(f"/?run={manifest['run_id']}", status_code=303)


async def api_scan(request: Request) -> Response:
    """Return a masked scan report for a multipart upload."""

    form = await request.form()
    upload = form.get("data_file")
    if not isinstance(upload, UploadFile) or not upload.filename:
        raise HTTPException(400, "data_file is required")
    path = await _save_upload(upload)
    try:
        try:
            frame = load_table(path)
            report = scan_frame(
                frame,
                source_name=Path(upload.filename).name,
                fingerprint_key=os.getenv("PRIVACYLENS_HASH_KEY"),
            )
        except (RuntimeError, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc
    finally:
        path.unlink(missing_ok=True)
    return JSONResponse(report.to_dict())


async def api_runs(request: Request) -> Response:
    """Return saved privacy run manifests."""

    ensure_demo()
    return JSONResponse({"runs": store.list_runs()})


async def api_run(request: Request) -> Response:
    """Return one complete masked report."""

    try:
        return JSONResponse(store.load(request.path_params["run_id"]))
    except FileNotFoundError as exc:
        raise HTTPException(404, "Run not found") from exc


async def download_artifact(request: Request) -> Response:
    """Download a whitelisted report or sanitized output."""

    try:
        path = store.artifact_path(
            request.path_params["run_id"], request.path_params["filename"]
        )
    except FileNotFoundError as exc:
        raise HTTPException(404, "Artifact not found") from exc
    return FileResponse(path, filename=path.name)


async def health(request: Request) -> Response:
    """Return deployment health."""

    return JSONResponse({"status": "ok", "service": "privacylens"})


routes = [
    Route("/", homepage),
    Route("/analyze", analyze, methods=["POST"]),
    Route("/api/scan", api_scan, methods=["POST"]),
    Route("/api/runs", api_runs),
    Route("/api/runs/{run_id:str}", api_run),
    Route("/artifacts/{run_id:str}/{filename:str}", download_artifact),
    Route("/health", health),
    Mount("/static", app=StaticFiles(directory=PROJECT_ROOT / "web/static"), name="static"),
]

app = Starlette(
    debug=os.getenv("PRIVACYLENS_DEBUG", "false").lower() == "true",
    routes=routes,
    middleware=[Middleware(GZipMiddleware, minimum_size=1000)],
)
