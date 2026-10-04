# AuthGraph Sentinel

An evidence-first, authorized security-assessment tool for access-control flaws.
It discovers an application's endpoints, builds an **authorization graph** of who
owns and who requests each resource, and **proves** access-control issues by
reproducing them against a local lab - never calling something a finding until a
deterministic test confirms it.

It ships with `World Monitor`, an intentionally vulnerable target to assess, and a
dashboard to read the results.

> **Authorized use only.** The bundled lab is deliberately insecure and is for
> testing against itself. Point the engine only at systems you are authorized to
> assess. The scope guard enforces an allowlist so the engine cannot reach any host
> you have not configured.

## What it finds

- **BOLA / IDOR** - reading or modifying another user's resources by ID
- **Broken RBAC** - reaching privileged functions as a lower role
- **Privilege escalation** - a low-privilege user becoming admin
- **Weak sessions** - forgeable / unsigned / non-expiring tokens
- **Excessive data exposure** - secrets returned in API responses

Each finding carries a CVSS v3.1 score, confidence (suspected/verified), business
impact, remediation, redacted evidence, and a replayable re-test scenario.

## Quick start (Docker, one command)

```bash
docker compose up --build
```

- Dashboard - http://localhost:5173
- API docs - http://localhost:8001/docs
- Lab (target) - http://localhost:8000/docs

Open the dashboard and click **Run assessment**. See `docs/demo.md` for a tour.

## Manual setup (three terminals)

```bash
# Terminal 1 - target lab
cd sentinel-lab && python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --port 8000

# Terminal 2 - engine + API
cd backend && python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8001

# Terminal 3 - dashboard
cd frontend && npm install && npm run dev   # http://localhost:5173
```

The command-line pipeline also runs standalone:

```bash
cd backend && source .venv/bin/activate
python -m app.reports.generator    # writes report.md / report.json / retest_scenarios.json
```

## Project structure

```
authgraph-sentinel/
├── sentinel-lab/      intentionally-vulnerable target (World Monitor)
├── backend/           engine + API
│   └── app/
│       ├── engine/    discovery, auth analysis, graph, detectors, scope guard
│       ├── models/    graph, user, finding
│       ├── risk/      CVSS
│       ├── reports/   report generator
│       └── api/       REST endpoints
├── frontend/          React + TypeScript dashboard
├── docs/              architecture, methodology, demo
└── docker-compose.yml
```

## How it works

Discover -> analyze sessions -> build the authorization graph -> judge access ->
**prove** by reproduction -> score -> report. Suspected issues come from graph
inference; only reproduced tests become verified findings. Destructive tests are
bracketed by a lab reset so they are deterministic and leave no residue.

See `docs/architecture.md` for the design and `docs/methodology.md` for the
evidence-first approach, the policy assumption, scoring, and known limitations.

## Requirements

- Docker (for the one-command path), or
- Python 3.11+ and Node 18+ (for manual setup)

## Disclaimer

For authorized security testing and education only. You are responsible for having
permission to assess any target you point this tool at.
