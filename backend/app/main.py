"""AuthGraph Sentinel API."""

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.assessments import AssessmentStore
from app.api.assessments import router as assessments_router
from app.api.findings import router as findings_router
from app.api.graph import router as graph_router
from app.api.reports import router as reports_router


app = FastAPI(
    title="AuthGraph Sentinel API",
    version="0.1.0",
)


_default_origins = ",".join(
    [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
)

cors_origins = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", _default_origins).split(",")
    if origin.strip()
]


app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
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
    return {
        "service": "AuthGraph Sentinel API",
        "version": "0.1.0",
        "docs": "/docs",
    }
