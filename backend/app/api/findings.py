"""Findings API: list and fetch findings for an assessment."""
from dataclasses import asdict

from fastapi import APIRouter, HTTPException, Request

from app.api.assessments import get_store

router = APIRouter(prefix="/api/assessments/{assessment_id}/findings", tags=["findings"])


def _require(request: Request, assessment_id: str):
    rec = get_store(request).get(assessment_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return rec


@router.get("")
def list_findings(assessment_id: str, request: Request, category: str | None = None,
                  severity: str | None = None):
    rec = _require(request, assessment_id)
    items = [asdict(f) for f in rec.findings]
    if category:
        items = [f for f in items if f["category"] == category]
    if severity:
        items = [f for f in items if f["severity"].lower() == severity.lower()]
    return items


@router.get("/{finding_id}")
def get_finding(assessment_id: str, finding_id: str, request: Request):
    rec = _require(request, assessment_id)
    match = next((f for f in rec.findings if f.id == finding_id), None)
    if not match:
        raise HTTPException(status_code=404, detail="Finding not found")
    return asdict(match)
