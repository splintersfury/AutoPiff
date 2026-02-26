"""AutoPiff Dashboard API."""

from __future__ import annotations

import json
import logging
import os
import secrets
import uuid
from pathlib import Path
from typing import Optional

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from .corpus import get_corpus_entry, get_corpus_overview
from .models import (
    ActivityItem,
    ActivityType,
    AlertEntry,
    AlertsResponse,
    Analysis,
    AnalysisListResponse,
    CorpusOverview,
    CVECorpusEntry,
    DriverSummary,
    Finding,
    HealthResponse,
    PipelineHealth,
    PipelineStage,
    SearchResponse,
    StatsResponse,
    TriageEntry,
    TriageSummary,
    TriageUpdate,
    VariantAlertEntry,
)
from .storage import FileStorage, MWDBStorage
from .triage import TriageStore

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

# Triage store
TRIAGE_PATH = os.environ.get("AUTOPIFF_TRIAGE_PATH", "/data/triage.json")
triage_store = TriageStore(TRIAGE_PATH)

# API key authentication (empty = disabled for local dev)
DASHBOARD_API_KEY = os.environ.get("DASHBOARD_API_KEY", "")


async def require_api_key(authorization: Optional[str] = Header(None)) -> None:
    """Dependency that enforces Bearer-token auth when DASHBOARD_API_KEY is set."""
    if not DASHBOARD_API_KEY:
        return  # auth disabled
    if authorization is None:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header. Expected: Bearer <api-key>",
        )
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header. Expected: Bearer <api-key>",
        )
    if not secrets.compare_digest(token, DASHBOARD_API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")


# Redis connection (for alerts + pipeline health — optional)
KARTON_REDIS_HOST = os.environ.get("KARTON_REDIS_HOST", "")
_redis_client = None


def _get_redis():
    global _redis_client
    if _redis_client is None and KARTON_REDIS_HOST:
        try:
            import redis
            _redis_client = redis.Redis(
                host=KARTON_REDIS_HOST, port=6379, decode_responses=True, socket_timeout=3,
            )
            _redis_client.ping()
        except Exception as e:
            logger.warning("Redis not available: %s", e)
            _redis_client = None
    return _redis_client


# Corpus validation
CORPUS_DIR = Path(os.environ.get("AUTOPIFF_CORPUS_DIR", "/data/corpus"))
MANIFEST_PATH = Path(os.environ.get("AUTOPIFF_MANIFEST_PATH", "/data/corpus_manifest.json"))


@app.get("/api/health", response_model=HealthResponse)
async def health():
    return HealthResponse()


@app.get("/api/analyses", response_model=AnalysisListResponse)
async def list_analyses(
    source: str = "file",
    min_score: float = 0.0,
    noise_risk: Optional[str] = None,
    decision: Optional[str] = None,
    arch: Optional[str] = None,
):
    """List all available analyses with optional filters."""
    if source == "mwdb" and mwdb_storage:
        items = await mwdb_storage.list_analyses()
    else:
        items = file_storage.list_analyses()
    if min_score > 0:
        items = [a for a in items if a.top_score >= min_score]
    if noise_risk:
        items = [a for a in items if a.noise_risk and a.noise_risk.value == noise_risk]
    if decision:
        items = [a for a in items if a.decision and a.decision.value == decision]
    if arch:
        items = [a for a in items if a.arch.value == arch]
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
async def upload_analysis(file: UploadFile, _auth: None = Depends(require_api_key)):
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
# Drivers (per-driver grouping)
# ==========================================================================


@app.get("/api/drivers", response_model=list[DriverSummary])
async def list_drivers():
    """Group analyses by driver and return driver-level summaries."""
    return file_storage.get_drivers()


@app.get("/api/drivers/{driver_name}", response_model=AnalysisListResponse)
async def get_driver_analyses(driver_name: str):
    """Get all analyses for a specific driver."""
    items = file_storage.get_driver_analyses(driver_name)
    if not items:
        raise HTTPException(status_code=404, detail=f"Driver '{driver_name}' not found")
    return AnalysisListResponse(analyses=items, total=len(items))


# ==========================================================================
# Alerts (from Redis)
# ==========================================================================


@app.get("/api/alerts", response_model=AlertsResponse)
async def get_alerts(limit: int = 50):
    """Fetch recent alerts and variant alerts from Redis."""
    rdb = _get_redis()
    if not rdb:
        return AlertsResponse()

    alerts = []
    try:
        raw_alerts = rdb.zrevrange("autopiff:alerts:recent", 0, limit - 1, withscores=True)
        for entry_json, ts in raw_alerts:
            data = json.loads(entry_json)
            surface = data.get("surface_area", "")
            if isinstance(surface, list):
                surface = ", ".join(surface)
            alerts.append(AlertEntry(
                score=data.get("score", 0),
                function=data.get("function", ""),
                rule_id=data.get("rule_id", ""),
                category=data.get("category", ""),
                surface_area=surface,
                driver_new=data.get("driver_new", ""),
                why_matters=data.get("why_matters", ""),
                timestamp=ts,
            ))
    except Exception as e:
        logger.warning("Failed to read alerts: %s", e)

    variants = []
    try:
        raw_variants = rdb.zrevrange("autopiff:alerts:variants", 0, limit - 1, withscores=True)
        for entry_json, ts in raw_variants:
            data = json.loads(entry_json)
            variants.append(VariantAlertEntry(
                source_driver=data.get("source_driver", ""),
                source_function=data.get("source_function", ""),
                bug_class=data.get("bug_class", ""),
                variant_driver=data.get("variant_driver", ""),
                variant_function=data.get("variant_function", ""),
                similarity=data.get("similarity", 0),
                confidence=data.get("confidence", 0),
                reasoning=data.get("reasoning", ""),
                timestamp=ts,
            ))
    except Exception as e:
        logger.warning("Failed to read variant alerts: %s", e)

    return AlertsResponse(alerts=alerts, variants=variants)


# ==========================================================================
# Search
# ==========================================================================


@app.get("/api/search", response_model=SearchResponse)
async def search(q: str = "", limit: int = 50):
    """Search across drivers, analyses, and findings."""
    if not q or len(q) < 2:
        return SearchResponse(query=q)
    results = file_storage.search(q, limit=limit)
    return SearchResponse(query=q, results=results, total=len(results))


# ==========================================================================
# Stats & Trends
# ==========================================================================


@app.get("/api/stats", response_model=StatsResponse)
async def get_stats():
    """Get trend data, score distribution, and category breakdown."""
    return file_storage.get_stats()


# ==========================================================================
# Pipeline Health
# ==========================================================================


_EXPECTED_STAGES = [
    ("Patch Differ (1-4)", "karton.autopiff.patch-differ"),
    ("Reachability (5)", "karton.autopiff.reachability"),
    ("Ranking (6)", "karton.autopiff.ranking"),
    ("Report (7)", "karton.autopiff.report"),
    ("Alerter", "karton.autopiff.alerter"),
    ("Driver Triage", "karton.driveratlas.triage"),
    ("KernelSense", "karton.autopiff.kernelsense"),
    ("Driver Monitor", "karton.autopiff.driver-monitor"),
]


@app.get("/api/pipeline", response_model=PipelineHealth)
async def pipeline_health():
    """Get pipeline stage health from Karton Redis."""
    rdb = _get_redis()
    if not rdb:
        return PipelineHealth(
            stages=[PipelineStage(name=n, identity=i, status="unknown") for n, i in _EXPECTED_STAGES],
        )

    stages = []
    active = 0
    try:
        # Karton stores online consumers in a hash
        online_consumers = set()
        for key in rdb.scan_iter("karton.consumer-*"):
            try:
                info = rdb.hgetall(key)
                identity = info.get("identity", "")
                if identity:
                    online_consumers.add(identity)
            except Exception:
                continue

        for name, identity in _EXPECTED_STAGES:
            is_online = identity in online_consumers
            if is_online:
                active += 1
            stages.append(PipelineStage(
                name=name,
                identity=identity,
                status="online" if is_online else "offline",
            ))
    except Exception as e:
        logger.warning("Failed to read pipeline state: %s", e)
        stages = [PipelineStage(name=n, identity=i, status="unknown") for n, i in _EXPECTED_STAGES]

    return PipelineHealth(stages=stages, active_consumers=active, redis_connected=True)


# ==========================================================================
# Activity Feed
# ==========================================================================


@app.get("/api/activity", response_model=list[ActivityItem])
async def activity_feed(limit: int = 30):
    """Return a chronological activity feed of recent events."""
    items: list[ActivityItem] = []

    # 1. Recent analyses -> activity items
    analyses = file_storage.list_analyses()
    for a in analyses:
        # New analysis event
        items.append(ActivityItem(
            type=ActivityType.new_analysis,
            timestamp=a.created_at.isoformat() if hasattr(a.created_at, "isoformat") else str(a.created_at),
            title=f"New analysis: {a.driver_name or a.id}",
            detail=(
                f"{a.total_findings} finding{'s' if a.total_findings != 1 else ''}"
                f"{f', {a.reachable_findings} reachable' if a.reachable_findings else ''}"
                f" — top score {a.top_score:.1f}"
            ),
            link=f"/analysis/{a.id}",
            score=a.top_score,
        ))

        # High-score findings as separate events (score >= 8)
        if a.top_score >= 8.0:
            items.append(ActivityItem(
                type=ActivityType.high_score_finding,
                timestamp=a.created_at.isoformat() if hasattr(a.created_at, "isoformat") else str(a.created_at),
                title=f"High-scoring finding in {a.driver_name or a.id}",
                detail=f"Score {a.top_score:.1f} — {a.reachable_findings} reachable via IOCTL/IRP",
                link=f"/analysis/{a.id}",
                score=a.top_score,
            ))

    # 2. Recent triage updates
    for entry in triage_store.recent_updates(limit=20):
        items.append(ActivityItem(
            type=ActivityType.triage_update,
            timestamp=entry.updated_at.isoformat() if hasattr(entry.updated_at, "isoformat") else str(entry.updated_at),
            title=f"Triaged: {entry.function} -> {entry.state.value}",
            detail=entry.note or "",
            link=f"/analysis/{entry.analysis_id}",
        ))

    # Sort by timestamp descending
    items.sort(key=lambda x: x.timestamp, reverse=True)
    return items[:limit]


# ==========================================================================
# Triage Workflow
# ==========================================================================


@app.get("/api/triage/summary", response_model=TriageSummary)
async def triage_summary():
    """Get aggregate triage state counts across all findings."""
    return triage_store.summary()


@app.get("/api/triage/{analysis_id}", response_model=dict[str, TriageEntry])
async def get_triage_states(analysis_id: str):
    """Get all triage states for an analysis."""
    return triage_store.get_for_analysis(analysis_id)


@app.get("/api/triage/{analysis_id}/{function}", response_model=TriageEntry)
async def get_triage_state(analysis_id: str, function: str):
    """Get triage state for a specific finding."""
    return triage_store.get(analysis_id, function)


@app.put("/api/triage/{analysis_id}/{function}", response_model=TriageEntry)
async def set_triage_state(analysis_id: str, function: str, body: TriageUpdate, _auth: None = Depends(require_api_key)):
    """Update triage state for a specific finding."""
    return triage_store.set(analysis_id, function, body.state, body.note)


# ==========================================================================
# Corpus Validation Endpoints
# ==========================================================================


@app.get("/api/corpus", response_model=CorpusOverview)
async def corpus_overview():
    """Get corpus overview with per-CVE status and aggregate metrics."""
    if not MANIFEST_PATH.exists():
        return CorpusOverview()
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
        except OSError as e:
            logger.warning(f"Failed to read {vuln_c}: {e}")
    if fix_c.exists():
        try:
            result["fix_source"] = fix_c.read_text(errors="replace")
        except OSError as e:
            logger.warning(f"Failed to read {fix_c}: {e}")

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
async def corpus_download(background_tasks: BackgroundTasks, _auth: None = Depends(require_api_key)):
    """Trigger corpus binary download as a background task."""
    if not MANIFEST_PATH.exists():
        raise HTTPException(status_code=404, detail="Corpus manifest not found")
    background_tasks.add_task(_run_download, MANIFEST_PATH, CORPUS_DIR)
    return {"status": "started", "message": "Corpus download started in background"}


@app.post("/api/corpus/evaluate")
async def corpus_evaluate(background_tasks: BackgroundTasks, _auth: None = Depends(require_api_key)):
    """Trigger corpus evaluation as a background task."""
    if not MANIFEST_PATH.exists():
        raise HTTPException(status_code=404, detail="Corpus manifest not found")
    background_tasks.add_task(_run_evaluate, MANIFEST_PATH, CORPUS_DIR)
    return {"status": "started", "message": "Corpus evaluation started in background"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
