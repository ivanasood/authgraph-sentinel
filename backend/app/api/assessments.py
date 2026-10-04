"""Assessments API: run an assessment and list results.

State is held in an in-memory store (AssessmentStore) for the MVP; a persistent
store (SQLite/Postgres) is a later hardening step. An assessment runs
synchronously inside the request - it takes a few seconds because it performs
the full discover -> detect -> verify pipeline against the target.
"""
import datetime
import uuid
from dataclasses import dataclass, field

from fastapi import APIRouter, HTTPException, Request

from app.config import LAB
from app.engine.http_client import ScopeError
from app.models.finding import Finding
from app.reports.generator import run_assessment, severity_summary

router = APIRouter(prefix="/api/assessments", tags=["assessments"])


@dataclass
class AssessmentRecord:
    id: str
    created: str
    target_name: str
    target_url: str
    status: str                         # complete | error
    summary: dict
    findings: list = field(default_factory=list)   # list[Finding]
    graph: dict = field(default_factory=dict)       # node-link snapshot
    retests: list = field(default_factory=list)


class AssessmentStore:
    def __init__(self):
        self._items: dict[str, AssessmentRecord] = {}

    def add(self, rec: AssessmentRecord):
        self._items[rec.id] = rec

    def get(self, assessment_id: str):
        return self._items.get(assessment_id)

    def list(self):
        return sorted(self._items.values(), key=lambda r: r.created, reverse=True)


def get_store(request: Request) -> AssessmentStore:
    return request.app.state.store


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def summary_view(rec: AssessmentRecord) -> dict:
    return {
        "id": rec.id,
        "created": rec.created,
        "target": {"name": rec.target_name, "url": rec.target_url},
        "status": rec.status,
        "finding_count": len(rec.findings),
        "severity": rec.summary,
    }


@router.post("")
def create_assessment(request: Request):
    store = get_store(request)
    try:
        graph, findings = run_assessment(LAB)
    except ScopeError as exc:
        raise HTTPException(status_code=400, detail=f"Scope guard blocked the run: {exc}")
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Target unreachable or assessment failed: {exc}. "
                   f"Is the lab running at {LAB.base_url}?",
        )
    rec = AssessmentRecord(
        id=uuid.uuid4().hex[:12], created=_now(),
        target_name=LAB.name, target_url=LAB.base_url, status="complete",
        summary=severity_summary(findings), findings=findings,
        graph=graph.to_dict(), retests=[f.retest for f in findings if f.retest],
    )
    store.add(rec)
    return summary_view(rec)


@router.get("")
def list_assessments(request: Request):
    return [summary_view(r) for r in get_store(request).list()]


@router.get("/{assessment_id}")
def get_assessment(assessment_id: str, request: Request):
    rec = get_store(request).get(assessment_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return summary_view(rec)
