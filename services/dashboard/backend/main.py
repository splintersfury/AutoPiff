"""AutoPiff Dashboard API."""

from __future__ import annotations

import logging
import os
import uuid
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from .models import (
    Analysis,
    AnalysisListResponse,
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
    import json

    content = await file.read()
    try:
        artifacts = json.loads(content)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    analysis_id = str(uuid.uuid4())[:8]
    analysis = file_storage.save_analysis(analysis_id, artifacts)
    return analysis


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
