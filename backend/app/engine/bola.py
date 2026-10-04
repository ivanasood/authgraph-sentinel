"""BOLA / IDOR detector.

Proves object-level authorization failures by having a low-privilege user
operate on resources owned by someone else, then confirming the other user's
data was returned (or their resource was mutated). Promotes suspected -> verified.
"""
from app.config import LAB, AssessmentConfig
from app.engine import verification as V
from app.engine.authorization import run as run_authz
from app.engine.http_client import ScopedClient
from app.engine.verification import VerifiedFinding


def _ownership(graph):
    report_owner, uid_owner = {}, {}
    for node, data in graph.g.nodes(data=True):
        if data.get("kind") == "resource" and data.get("owner"):
            if node.startswith("report:"):
                report_owner[node.split(":", 1)[1]] = data["owner"]
            elif node.startswith("user:"):
                uid_owner[node.split(":", 1)[1]] = data["owner"]
    return report_owner, uid_owner


def run_bola(config: AssessmentConfig = LAB, shared=None):
    graph, principals, _ = shared or run_authz(config)
    report_owner, uid_owner = _ownership(graph)
    by_role = {p.role: p for p in principals}
    findings: list[VerifiedFinding] = []

    with ScopedClient(config) as client:
        # 1. Cross-user report read (non-destructive)
        attacker = by_role["viewer"]
        target = next((r for r, o in report_owner.items() if o != attacker.username), None)
        if target:
            token = V.login(client, config, attacker.role)
            resp = client.get(f"/api/reports/{target}", headers=V.auth(token))
            body = resp.json() if resp.status_code == 200 else {}
            ok = resp.status_code == 200 and body.get("owner_id") != attacker.uid
            findings.append(VerifiedFinding(
                id="BOLA-REPORT-READ", category="BOLA",
                title="Viewer reads another user's report by ID (IDOR)",
                actor_role=attacker.role, endpoint="GET /api/reports/{report_id}",
                status="verified" if ok else "not_reproduced",
                rationale=f"{attacker.username} ({attacker.role}) retrieved report "
                          f"{target}, owned by {report_owner[target]}.",
                evidence=[{"step": "cross-user GET",
                           "request": {"as_role": attacker.role, "method": "GET",
                                       "path": f"/api/reports/{target}"},
                           "response": {"status": resp.status_code, "body": V.redact(body)}}],
                retest={"name": "BOLA-REPORT-READ", "category": "BOLA",
                        "steps": [{"as_role": attacker.role, "method": "GET",
                                   "path": f"/api/reports/{target}", "expect_status": 200,
                                   "expect": "body.owner_id != actor uid"}]},
            ))

        # 2. Cross-user user-record read + excessive exposure (non-destructive)
        attacker = by_role["analyst"]
        tuid = next((u for u, o in uid_owner.items() if o != attacker.username), None)
        if tuid:
            token = V.login(client, config, attacker.role)
            resp = client.get(f"/api/users/{tuid}", headers=V.auth(token))
            body = resp.json() if resp.status_code == 200 else {}
            leaked = sorted(k for k in body if k in V.SENSITIVE_KEYS)
            ok = resp.status_code == 200 and body.get("username") != attacker.username
            findings.append(VerifiedFinding(
                id="BOLA-USER-READ", category="BOLA",
                title="Analyst reads another user's record, including secret fields",
                actor_role=attacker.role, endpoint="GET /api/users/{user_id}",
                status="verified" if ok else "not_reproduced",
                rationale=f"{attacker.username} retrieved user {tuid} "
                          f"({uid_owner[tuid]}); leaked fields: {leaked or 'none'}.",
                evidence=[{"step": "cross-user GET",
                           "request": {"as_role": attacker.role, "method": "GET",
                                       "path": f"/api/users/{tuid}"},
                           "response": {"status": resp.status_code, "body": V.redact(body)}}],
                retest={"name": "BOLA-USER-READ", "category": "BOLA",
                        "steps": [{"as_role": attacker.role, "method": "GET",
                                   "path": f"/api/users/{tuid}", "expect_status": 200,
                                   "expect": "body.username != actor"}]},
            ))

        # 3. Cross-user report delete (DESTRUCTIVE -> reset bracket)
        attacker = by_role["viewer"]
        if target:
            V.reset_lab(client)
            token = V.login(client, config, attacker.role)
            before = client.get(f"/api/reports/{target}", headers=V.auth(token)).status_code
            dele = client.delete(f"/api/reports/{target}", headers=V.auth(token))
            after = client.get(f"/api/reports/{target}", headers=V.auth(token)).status_code
            ok = dele.status_code == 200 and before == 200 and after == 404
            findings.append(VerifiedFinding(
                id="BOLA-REPORT-DELETE", category="BOLA",
                title="Viewer deletes another user's report (IDOR + no function-level auth)",
                actor_role=attacker.role, endpoint="DELETE /api/reports/{report_id}",
                status="verified" if ok else "not_reproduced", destructive=True,
                rationale=f"{attacker.username} deleted report {target} "
                          f"(owner {report_owner.get(target)}); GET after delete = {after}. "
                          f"Lab state restored.",
                evidence=[{"step": "delete",
                           "request": {"as_role": attacker.role, "method": "DELETE",
                                       "path": f"/api/reports/{target}"},
                           "response": {"status": dele.status_code}},
                          {"step": "confirm-gone",
                           "request": {"method": "GET", "path": f"/api/reports/{target}"},
                           "response": {"status": after}}],
                retest={"name": "BOLA-REPORT-DELETE", "category": "BOLA", "destructive": True,
                        "steps": [{"as_role": attacker.role, "method": "DELETE",
                                   "path": f"/api/reports/{target}", "expect_status": 200},
                                  {"as_role": attacker.role, "method": "GET",
                                   "path": f"/api/reports/{target}", "expect_status": 404}],
                        "cleanup": [{"action": "reset_lab"}]},
            ))
            V.reset_lab(client)

    return findings


if __name__ == "__main__":
    results = run_bola()
    V.print_findings(results, "BOLA / IDOR detector")
    n = V.save_scenarios(results, "retest_scenarios_bola.json")
    print(f"Saved {n} re-test scenario(s) -> retest_scenarios_bola.json")
