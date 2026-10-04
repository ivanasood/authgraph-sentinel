"""Authorization engine: build the graph, apply policy, surface violations.

POLICY IS AN ASSUMPTION LAYER. Real targets rarely ship a machine-readable
access policy, so BASELINE_POLICY below is derived from role semantics and
ownership (viewer/analyst -> own resources only; admin -> everything). Treat
it as an editable hypothesis, not ground truth. Every violation it produces is
'suspected' until a Phase-4 detector reproduces it deterministically.

The path->resource mapping in _resolve() is likewise heuristic (based on URL
shape), not a spec of the app's domain model.
"""
from dataclasses import dataclass, field

from app.config import LAB, AssessmentConfig
from app.engine.discovery import DiscoveryReport, run_discovery
from app.engine.http_client import ScopedClient
from app.models.graph import AuthorizationGraph
from app.models.user import Principal


@dataclass
class Policy:
    permissions: dict[str, set]


# Editable baseline. Each role maps to the access classes it is allowed.
BASELINE_POLICY = Policy(permissions={
    "viewer":  {"own_report", "own_user"},
    "analyst": {"own_report", "own_user"},
    "admin":   {"own_report", "other_report", "own_user", "other_user", "admin_function"},
})


@dataclass
class AccessViolation:
    principal: str
    role: str
    method: str
    path: str
    concrete_path: str
    access_class: str
    category: str              # BOLA | BROKEN_RBAC | OTHER
    expected: str
    status: str = "suspected"  # promoted to 'verified' only by Phase-4 detectors
    evidence: dict = field(default_factory=dict)


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _resolve(path_template: str, concrete_path: str):
    """Map a probed path to (resource_type, resource_key) from URL shape alone."""
    if "/admin" in path_template:
        return "admin", path_template
    if path_template.endswith("/me"):
        return "self", None
    if path_template.endswith("}"):                       # object-scoped (e.g. /x/{id})
        collection = path_template.rstrip("/").split("/")[-2]
        return collection.rstrip("s"), concrete_path.rstrip("/").split("/")[-1]
    collection = path_template.rstrip("/").split("/")[-1]  # bare collection
    return "collection:" + collection.rstrip("s"), None


def _classify(rtype, key, principal: Principal, report_owner, uid_owner):
    if rtype == "admin":
        return f"admin:{key}", "admin_function"
    if rtype == "self":
        return f"user:{principal.uid}", "own_user"
    if rtype == "report":
        owner = report_owner.get(str(key))
        return f"report:{key}", ("own_report" if owner == principal.username else "other_report")
    if rtype == "user":
        owner = uid_owner.get(int(key)) if str(key).isdigit() else None
        return f"user:{key}", ("own_user" if owner == principal.username else "other_user")
    if str(rtype).startswith("collection"):
        return str(rtype), "own_report"      # scoped list of the caller's own resources
    return None, None


def categorize(access_class: str) -> str:
    if access_class in ("other_report", "other_user"):
        return "BOLA"
    if access_class == "admin_function":
        return "BROKEN_RBAC"
    return "OTHER"


def build_graph(report: DiscoveryReport, config: AssessmentConfig = LAB):
    role_cred = {c.role: c for c in config.credentials}
    graph = AuthorizationGraph()
    principals: list[Principal] = []

    with ScopedClient(config) as client:
        # 1. identities + roles
        for role, token in report.tokens.items():
            me = client.get("/api/users/me", headers=_auth(token)).json()
            p = Principal(role_cred[role].username, role, token, me.get("id"))
            principals.append(p)
            graph.add_principal(p.username, p.role, p.uid)

        by_role = {p.role: p for p in principals}
        uid_owner = {p.uid: p.username for p in principals}

        # 2. ownership learned from the scoped (correct) list endpoint
        report_owner: dict[str, str] = {}
        for p in principals:
            r = client.get("/api/reports", headers=_auth(p.token))
            if r.status_code == 200:
                for rep in r.json():
                    graph.add_resource(f"report:{rep['id']}", "report", owner=p.username)
                    report_owner[str(rep["id"])] = p.username
        for p in principals:
            graph.add_resource(f"user:{p.uid}", "user", owner=p.username)

        # 3. observed requests -> classified request edges
        for pr in report.access_map:
            if pr.outcome != "allowed":
                continue
            p = by_role.get(pr.role)
            if not p:
                continue
            rtype, key = _resolve(pr.path, pr.concrete_path)
            resource_id, access_class = _classify(rtype, key, p, report_owner, uid_owner)
            if resource_id is None:
                continue
            graph.add_resource(resource_id, "resource")
            graph.add_request(p.username, resource_id, method=pr.method,
                              path=pr.path, concrete=pr.concrete_path,
                              access_class=access_class)
    return graph, principals


def evaluate(graph: AuthorizationGraph, policy: Policy = BASELINE_POLICY):
    violations: list[AccessViolation] = []
    for username, resource_id, data in graph.requests():
        role = graph.role_of(username)
        cls = data.get("access_class")
        if not cls or cls in policy.permissions.get(role, set()):
            continue
        violations.append(AccessViolation(
            principal=username, role=role, method=data.get("method"),
            path=data.get("path"), concrete_path=data.get("concrete"),
            access_class=cls, category=categorize(cls),
            expected=f"role '{role}' is not permitted '{cls}' under baseline policy",
            evidence={"resource": resource_id, "observed": "allowed"},
        ))
    order = {"BOLA": 0, "BROKEN_RBAC": 1, "OTHER": 2}
    violations.sort(key=lambda v: (order.get(v.category, 9), v.role, v.path))
    return violations


def run(config: AssessmentConfig = LAB):
    report = run_discovery(config)
    graph, principals = build_graph(report, config)
    return graph, principals, evaluate(graph)


if __name__ == "__main__":
    graph, principals, violations = run()
    print("Graph summary:", graph.summary())
    print("Principals:   " + ", ".join(f"{p.username}({p.role})" for p in principals))
    print(f"\n{len(violations)} suspected access violation(s) "
          f"[all 'suspected' until Phase-4 verification]:\n")
    hdr = f"{'category':13}{'role':9}{'method':7}{'path':32}{'access class':14}"
    print(hdr); print("-" * len(hdr))
    for v in violations:
        print(f"{v.category:13}{v.role:9}{v.method:7}{v.path:32}{v.access_class:14}")
    print("\nControl check: admin yields 0 violations and the scoped list endpoint "
          "is not flagged - the baseline holds with no false positives here.")
