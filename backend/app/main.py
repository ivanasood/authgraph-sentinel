"""AuthGraph Sentinel API.

Run (on a DIFFERENT port than the lab, which uses 8000):
    uvicorn app.main:app --reload --port 8001

The API drives the engine, which in turn talks to the target lab at
LAB.base_url (http://127.0.0.1:8000). Both servers must be running.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.assessments import AssessmentStore
from app.api.assessments import router as assessments_router
from app.api.findings import router as findings_router
from app.api.graph import router as graph_router
from app.api.reports import router as reports_router

app = FastAPI(title="AuthGraph Sentinel API", version="0.1.0")

# dev frontend origins (Phase 7 React app)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173",
                   "http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.state.store = AssessmentStore()

app.include_router(assessments_router)
app.include_router(findings_router)
app.include_router(graph_router)
app.include_router(reports_router)


@app.get("/")
def root():
    return {"service": "AuthGraph Sentinel API", "version": "0.1.0", "docs": "/docs"}
