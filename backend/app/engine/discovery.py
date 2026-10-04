"""Discovery engine.

Approach: spec-driven + authenticated probing.
  1. Ingest the target's OpenAPI spec and enumerate every endpoint.
  2. Log in as each configured role to obtain sessions.
  3. Probe which endpoints each role can reach.

SAFETY: probing is read-only. Only idempotent methods (GET) are fired, so
discovery never mutates lab state. Mutating endpoints (POST/PATCH/DELETE)
are inventoried and flagged but left for deterministic active testing in a
later phase, where state is reseeded and cleaned up.

Discovery produces EVIDENCE, not findings. "viewer can reach an admin route"
is a signal to investigate; it is not declared a vulnerability until the
authorization graph (what should be permitted) and a reproduced test confirm it.
"""
from dataclasses import dataclass, field

from app.config import LAB, AssessmentConfig
from app.engine.http_client import ScopedClient

SAFE_METHODS = {"GET"}


@dataclass
class Endpoint:
    method: str
    path: str
    path_params: list[str]
    operation_id: str | None
    summary: str | None
    requires_body: bool


@dataclass
class ProbeResult:
    role: str
    method: str
    path: str
    concrete_path: str
    status_code: int
    outcome: str          # allowed | denied | not_found | error


@dataclass
class DiscoveryReport:
    base_url: str
    endpoints: list[Endpoint]
    tokens: dict[str, str] = field(default_factory=dict)
    access_map: list[ProbeResult] = field(default_factory=list)


# --- steps -------------------------------------------------------------------
def fetch_spec(client: ScopedClient, config: AssessmentConfig) -> dict:
    resp = client.get(config.openapi_path)
    resp.raise_for_status()
    return resp.json()


def parse_endpoints(spec: dict) -> list[Endpoint]:
    http_methods = {"get", "post", "put", "patch", "delete", "options", "head"}
    endpoints: list[Endpoint] = []
    for path, operations in spec.get("paths", {}).items():
        if path.startswith("/api/_lab"):      # test hooks are not target surface
            continue
        for method, op in operations.items():
            if method.lower() not in http_methods:
                continue
            params = op.get("parameters", []) or []
            path_params = [p["name"] for p in params if p.get("in") == "path"]
            endpoints.append(Endpoint(
                method=method.upper(),
                path=path,
                path_params=path_params,
                operation_id=op.get("operationId"),
                summary=op.get("summary"),
                requires_body="requestBody" in op,
            ))
    return endpoints


def login_all(client: ScopedClient, config: AssessmentConfig) -> dict[str, str]:
    tokens: dict[str, str] = {}
    for cred in config.credentials:
        resp = client.post(config.login_path,
                            json={"username": cred.username, "password": cred.password})
        if resp.status_code == 200:
            tokens[cred.role] = resp.json().get("token")
    return tokens


def _concrete(path: str, path_params: list[str], samples: dict) -> str:
    out = path
    for name in path_params:
        out = out.replace("{%s}" % name, str(samples.get(name, 1)))
    return out


def _classify(status: int) -> str:
    if 200 <= status < 300:
        return "allowed"
    if status in (401, 403):
        return "denied"
    if status == 404:
        return "not_found"
    return "error"


def probe_access(client: ScopedClient, endpoints: list[Endpoint],
                 tokens: dict[str, str], samples: dict) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    for ep in endpoints:
        if ep.method not in SAFE_METHODS:
            continue
        concrete = _concrete(ep.path, ep.path_params, samples)
        for role, token in tokens.items():
            resp = client.get(concrete, headers={"Authorization": f"Bearer {token}"})
            results.append(ProbeResult(
                role=role, method=ep.method, path=ep.path,
                concrete_path=concrete, status_code=resp.status_code,
                outcome=_classify(resp.status_code),
            ))
    return results


def run_discovery(config: AssessmentConfig = LAB, samples: dict | None = None) -> DiscoveryReport:
    samples = samples or {"report_id": 1, "user_id": 1}
    with ScopedClient(config) as client:
        spec = fetch_spec(client, config)
        endpoints = parse_endpoints(spec)
        tokens = login_all(client, config)
        access_map = probe_access(client, endpoints, tokens, samples)
    return DiscoveryReport(config.base_url, endpoints, tokens, access_map)


# --- presentation ------------------------------------------------------------
def render_matrix(report: DiscoveryReport) -> str:
    roles = list(report.tokens.keys())
    get_eps = sorted({(r.path) for r in report.access_map})
    header = f"{'GET endpoint':40}" + "".join(f"{r:9}" for r in roles)
    lines = [header, "-" * len(header)]
    for path in get_eps:
        row = f"{path:40}"
        hint = ""
        for role in roles:
            pr = next((r for r in report.access_map
                       if r.path == path and r.role == role), None)
            cell = pr.outcome if pr else "-"
            row += f"{cell:9}"
            if pr and pr.outcome == "allowed" and "/admin" in path and role != "admin":
                hint = "  <- non-admin reached admin route"
        lines.append(row + hint)
    return "\n".join(lines)


if __name__ == "__main__":
    rep = run_discovery()
    print(f"Target: {rep.base_url}")
    print(f"Discovered {len(rep.endpoints)} endpoints:\n")
    for ep in rep.endpoints:
        tag = " [body]" if ep.requires_body else ""
        defer = "" if ep.method in SAFE_METHODS else "  (mutating - deferred to active testing)"
        print(f"  {ep.method:7}{ep.path}{tag}{defer}")

    print("\nSessions (redacted):")
    for role, token in rep.tokens.items():
        print(f"  {role:8} {token[:6]}...  ({len(token)} chars)")

    print("\nPer-role access map  [legend: allowed / denied / not_found]")
    print("(GET probes only; read-only. <- marks a hint worth investigating, not a finding)\n")
    print(render_matrix(rep))
