"""Graph API: the authorization graph snapshot for an assessment (node-link JSON)."""
from fastapi import APIRouter, HTTPException, Request

from app.api.assessments import get_store

router = APIRouter(prefix="/api/assessments/{assessment_id}/graph", tags=["graph"])


@router.get("")
def get_graph(assessment_id: str, request: Request):
    rec = get_store(request).get(assessment_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return rec.graph
