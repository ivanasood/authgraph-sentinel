"""Reports API: the rendered report (JSON + Markdown) and re-test scenarios."""
from dataclasses import asdict

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse

from app.api.assessments import get_store
from app.config import LAB
from app.reports.generator import render_markdown

router = APIRouter(prefix="/api/assessments/{assessment_id}", tags=["reports"])


def _require(request: Request, assessment_id: str):
    rec = get_store(request).get(assessment_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return rec


@router.get("/report.json")
def report_json(assessment_id: str, request: Request):
    rec = _require(request, assessment_id)
    return [asdict(f) for f in rec.findings]


@router.get("/report.md", response_class=PlainTextResponse)
def report_md(assessment_id: str, request: Request):
    rec = _require(request, assessment_id)
    return render_markdown(rec.findings, LAB)


@router.get("/retests")
def retests(assessment_id: str, request: Request):
    rec = _require(request, assessment_id)
    return {"count": len(rec.retests), "scenarios": rec.retests}
