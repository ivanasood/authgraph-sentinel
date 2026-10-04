"""Shared verification scaffolding for the detectors.

Detectors turn a *suspected* violation into a *verified* finding by actually
performing the access against the authorized lab and checking the result.
Destructive tests are bracketed by reset_lab() so they are deterministic and
leave the lab clean. All evidence is redacted before it is stored.
"""
import datetime
import json
from dataclasses import asdict, dataclass, field

from app.config import AssessmentConfig
from app.engine.http_client import ScopedClient

SENSITIVE_KEYS = {"password_hash", "api_key", "token", "password"}


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def redact(obj):
    """Recursively mask secret values so evidence can be stored/shown safely."""
    if isinstance(obj, dict):
        return {k: ("<redacted>" if k in SENSITIVE_KEYS else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    return obj


def login(client: ScopedClient, config: AssessmentConfig, role: str):
    cred = next((c for c in config.credentials if c.role == role), None)
    if not cred:
        return None
    r = client.post(config.login_path,
                    json={"username": cred.username, "password": cred.password})
    return r.json().get("token") if r.status_code == 200 else None


def reset_lab(client: ScopedClient) -> bool:
    """Restore known lab state (lab-only hook). Returns True on success."""
    try:
        return client.post("/api/_lab/reset").status_code == 200
    except Exception:
        return False


@dataclass
class VerifiedFinding:
    id: str
    category: str                 # BOLA | BROKEN_RBAC | PRIV_ESC
    title: str
    actor_role: str
    endpoint: str
    status: str                   # verified | not_reproduced
    rationale: str
    destructive: bool = False
    evidence: list = field(default_factory=list)
    retest: dict = field(default_factory=dict)


def save_scenarios(findings, path: str) -> int:
    """Persist verified findings' reproductions as replayable re-test scenarios."""
    scenarios = [f.retest for f in findings if f.status == "verified" and f.retest]
    with open(path, "w") as fh:
        json.dump({"generated": datetime.datetime.utcnow().isoformat() + "Z",
                   "scenarios": scenarios}, fh, indent=2)
    return len(scenarios)


def print_findings(findings, title: str) -> None:
    verified = sum(1 for f in findings if f.status == "verified")
    print(f"=== {title} ===  ({verified}/{len(findings)} verified)\n")
    for f in findings:
        tag = "  [destructive - lab reset]" if f.destructive else ""
        print(f"[{f.status.upper():14}] {f.category:11} {f.endpoint}{tag}")
        print(f"   {f.title}")
        print(f"   {f.rationale}\n")
