"""AutoPiff Dashboard API."""

from __future__ import annotations

import json
import logging
import os
import uuid
from pathlib import Path
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from .corpus import get_corpus_entry, get_corpus_overview
from .models import (
    Analysis,
    AnalysisListResponse,
    CorpusOverview,
    CVECorpusEntry,
    Finding,
    HealthResponse,
)
from .storage import FileStorage, MWDBStorage

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("autopiff.dashboard")

app = FastAPI(
    title="AutoPiff Dashboard API",
    version="0.1.0",
    description="REST API for AutoPiff patch intelligence results",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Storage backend
ANALYSES_DIR = os.environ.get("AUTOPIFF_ANALYSES_DIR", "/data/analyses")
MWDB_API_URL = os.environ.get("MWDB_API_URL", "")
MWDB_API_KEY = os.environ.get("MWDB_API_KEY", "")

file_storage = FileStorage(ANALYSES_DIR)
mwdb_storage = MWDBStorage(MWDB_API_URL, MWDB_API_KEY) if MWDB_API_URL else None

# Corpus validation
CORPUS_DIR = Path(os.environ.get("AUTOPIFF_CORPUS_DIR", "/data/corpus"))
MANIFEST_PATH = Path(os.environ.get("AUTOPIFF_MANIFEST_PATH", "/data/corpus_manifest.json"))


@app.get("/api/health", response_model=HealthResponse)
async def health():
    return HealthResponse()


@app.get("/api/analyses", response_model=AnalysisListResponse)
async def list_analyses(source: str = "file"):
    """List all available analyses."""
    if source == "mwdb" and mwdb_storage:
        items = await mwdb_storage.list_analyses()
    else:
        items = file_storage.list_analyses()
    return AnalysisListResponse(analyses=items, total=len(items))


@app.get("/api/analyses/{analysis_id}", response_model=Analysis)
async def get_analysis(analysis_id: str, source: str = "file"):
    """Get full analysis details."""
    if source == "mwdb" and mwdb_storage:
        analysis = await mwdb_storage.get_analysis(analysis_id)
    else:
        analysis = file_storage.get_analysis(analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis


@app.get("/api/analyses/{analysis_id}/findings", response_model=list[Finding])
async def get_findings(
    analysis_id: str,
    source: str = "file",
    category: Optional[str] = None,
    min_score: float = 0.0,
):
    """Get ranked findings for an analysis, with optional filters."""
    if source == "mwdb" and mwdb_storage:
        analysis = await mwdb_storage.get_analysis(analysis_id)
    else:
        analysis = file_storage.get_analysis(analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")

    findings = analysis.findings
    if category:
        findings = [f for f in findings if f.category.value == category]
    if min_score > 0:
        findings = [f for f in findings if f.final_score >= min_score]
    return findings


@app.post("/api/analyses/upload", response_model=Analysis)
async def upload_analysis(file: UploadFile):
    """Upload a combined analysis JSON artifact."""
    content = await file.read()
    try:
        artifacts = json.loads(content)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    analysis_id = str(uuid.uuid4())[:8]
    analysis = file_storage.save_analysis(analysis_id, artifacts)
    return analysis


# ==========================================================================
# Corpus Validation Endpoints
# ==========================================================================


@app.get("/api/corpus", response_model=CorpusOverview)
async def corpus_overview():
    """Get corpus overview with per-CVE status and aggregate metrics."""
    if not MANIFEST_PATH.exists():
        raise HTTPException(status_code=404, detail="Corpus manifest not found")
    return get_corpus_overview(MANIFEST_PATH, CORPUS_DIR)


@app.get("/api/corpus/{cve_id}", response_model=CVECorpusEntry)
async def corpus_cve(cve_id: str):
    """Get detailed corpus status for a single CVE."""
    if not MANIFEST_PATH.exists():
        raise HTTPException(status_code=404, detail="Corpus manifest not found")
    manifest = json.loads(MANIFEST_PATH.read_text())
    for entry in manifest.get("cves", []):
        if entry["cve_id"] == cve_id:
            return get_corpus_entry(entry, CORPUS_DIR)
    raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found in corpus")


@app.get("/api/corpus/{cve_id}/source")
async def corpus_source(cve_id: str):
    """Return decompiled source files for a CVE (vuln.c + fix.c)."""
    cve_dir = CORPUS_DIR / cve_id
    if not cve_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found on disk")

    vuln_c = cve_dir / "cache" / "vuln.c"
    fix_c = cve_dir / "cache" / "fix.c"

    result: dict = {"cve_id": cve_id, "vuln_source": None, "fix_source": None}
    if vuln_c.exists():
        try:
            result["vuln_source"] = vuln_c.read_text(errors="replace")
        except OSError:
            pass
    if fix_c.exists():
        try:
            result["fix_source"] = fix_c.read_text(errors="replace")
        except OSError:
            pass

    if result["vuln_source"] is None and result["fix_source"] is None:
        raise HTTPException(
            status_code=404,
            detail=f"No decompiled sources found for {cve_id}",
        )
    return result


def _run_download(manifest_path: Path, corpus_dir: Path) -> None:
    """Background task: download corpus binaries."""
    import subprocess
    import sys

    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    cmd = [
        sys.executable,
        str(repo_root / "tests" / "validation" / "run_corpus.py"),
        "--download-only",
        "--corpus-dir", str(corpus_dir),
        "-v",
    ]
    logger.info("Starting corpus download: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode == 0:
        logger.info("Corpus download completed successfully")
    else:
        logger.error("Corpus download failed: %s", result.stderr[-500:] if result.stderr else "no output")


def _run_evaluate(manifest_path: Path, corpus_dir: Path) -> None:
    """Background task: evaluate corpus against rule engine.

    Runs run_corpus.py --evaluate-only --json and saves the aggregate JSON
    result.  Additionally splits the per-CVE results into individual
    ``corpus/{CVE-ID}/cache/eval_result.json`` files so the dashboard
    status reader can pick them up.
    """
    import subprocess
    import sys

    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    cmd = [
        sys.executable,
        str(repo_root / "tests" / "validation" / "run_corpus.py"),
        "--evaluate-only",
        "--corpus-dir", str(corpus_dir),
        "--json",
        "-v",
    ]
    logger.info("Starting corpus evaluation: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)

    if result.returncode in (0, 1):
        # run_corpus.py exits 1 when recall < threshold — still valid output
        logger.info("Corpus evaluation finished (exit %d)", result.returncode)
        try:
            report = json.loads(result.stdout)
            # Save per-CVE eval results so the dashboard can read them
            for cve_data in report.get("cves", []):
                cve_id = cve_data.get("cve_id")
                if not cve_id:
                    continue
                cache_dir = corpus_dir / cve_id / "cache"
                cache_dir.mkdir(parents=True, exist_ok=True)
                eval_path = cache_dir / "eval_result.json"
                eval_path.write_text(json.dumps(cve_data, indent=2))
                logger.info("Saved eval cache: %s", eval_path)
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to parse/save eval results: %s", exc)
    else:
        logger.error(
            "Corpus evaluation failed: %s",
            result.stderr[-500:] if result.stderr else "no output",
        )


@app.post("/api/corpus/download")
async def corpus_download(background_tasks: BackgroundTasks):
    """Trigger corpus binary download as a background task."""
    if not MANIFEST_PATH.exists():
        raise HTTPException(status_code=404, detail="Corpus manifest not found")
    background_tasks.add_task(_run_download, MANIFEST_PATH, CORPUS_DIR)
    return {"status": "started", "message": "Corpus download started in background"}


@app.post("/api/corpus/evaluate")
async def corpus_evaluate(background_tasks: BackgroundTasks):
    """Trigger corpus evaluation as a background task."""
    if not MANIFEST_PATH.exists():
        raise HTTPException(status_code=404, detail="Corpus manifest not found")
    background_tasks.add_task(_run_evaluate, MANIFEST_PATH, CORPUS_DIR)
    return {"status": "started", "message": "Corpus evaluation started in background"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
