"""Canonical Finding model.

A Finding ties a verified result to its risk picture: CVSS score + severity,
business impact, remediation, redacted evidence, and a re-test scenario. It is
built from a detector's VerifiedFinding or an auth-analyzer observation.
"""
from dataclasses import dataclass, field

from app.risk.cvss import rate

# CVSS v3.1 base vectors per finding class (see cvss.py for the math).
_CVSS = {
    "WEAK_SESSION":       "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",  # forge any identity, no creds
    "PRIV_ESC":           "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",  # low-priv -> admin
    "BOLA_READ":          "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",  # read another user's data
    "BOLA_WRITE":         "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",  # modify/delete another's data
    "BROKEN_RBAC":        "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",  # reach privileged function
    "EXCESSIVE_EXPOSURE": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",  # secrets in responses
}

_IMPACT = {
    "BOLA": "A low-privilege authenticated user can read or modify resources belonging to "
            "other users, breaking user isolation and exposing confidential data.",
    "BROKEN_RBAC": "A user can invoke privileged functions reserved for higher roles, "
                   "bypassing the role model that protects administrative capability and data.",
    "PRIV_ESC": "A low-privilege user can elevate to administrator, gaining full control over "
                "users, roles, and data - effectively total compromise of the access model.",
    "WEAK_SESSION": "Session tokens can be forged without credentials, letting anyone impersonate "
                    "any user (including an administrator) and bypass authentication entirely.",
    "EXCESSIVE_EXPOSURE": "API responses include secret fields (password hashes, API keys) that "
                          "enable credential theft and lateral movement.",
}

_REMEDIATION = {
    "BOLA": "Enforce object-level authorization on every resource access: verify the requester "
            "owns or is explicitly granted the object before returning or mutating it. Never rely "
            "on unguessable IDs as a control.",
    "BROKEN_RBAC": "Enforce function-level authorization server-side on every privileged endpoint; "
                   "deny by default and check the caller's role rather than trusting the UI.",
    "PRIV_ESC": "Never bind client input to privileged fields: use an explicit allowlist of "
                "updatable attributes and require a separately authorized, audited path for role "
                "changes.",
    "WEAK_SESSION": "Issue signed, expiring tokens (JWT with a strong server secret, or server-side "
                    "sessions); verify signature and expiry on every request and never trust "
                    "client-supplied identity or role.",
    "EXCESSIVE_EXPOSURE": "Return only the minimal fields each caller needs; never serialize "
                          "password hashes, API keys, or other secrets.",
}


@dataclass
class Finding:
    id: str
    title: str
    category: str
    confidence: str            # verified | suspected
    cvss_vector: str
    cvss_score: float
    severity: str
    actor_role: str | None
    endpoint: str | None
    business_impact: str
    remediation: str
    evidence: list = field(default_factory=list)
    retest: dict | None = None

    @staticmethod
    def _cvss_key(category: str, endpoint: str | None) -> str:
        if category == "BOLA":
            method = (endpoint or "").split(" ", 1)[0].upper()
            return "BOLA_WRITE" if method in ("DELETE", "PATCH", "POST", "PUT") else "BOLA_READ"
        return category

    @classmethod
    def from_verified(cls, vf) -> "Finding":
        r = rate(_CVSS[cls._cvss_key(vf.category, vf.endpoint)])
        return cls(
            id=vf.id, title=vf.title, category=vf.category, confidence=vf.status,
            cvss_vector=r["vector"], cvss_score=r["score"], severity=r["severity"],
            actor_role=vf.actor_role, endpoint=vf.endpoint,
            business_impact=_IMPACT.get(vf.category, ""),
            remediation=_REMEDIATION.get(vf.category, ""),
            evidence=vf.evidence, retest=vf.retest or None,
        )

    @classmethod
    def from_session(cls, obs, endpoint: str = "POST /api/auth/login") -> "Finding":
        r = rate(_CVSS["WEAK_SESSION"])
        return cls(
            id=obs.id, title=obs.title, category="WEAK_SESSION", confidence=obs.status,
            cvss_vector=r["vector"], cvss_score=r["score"], severity=r["severity"],
            actor_role=None, endpoint=endpoint,
            business_impact=_IMPACT["WEAK_SESSION"], remediation=_REMEDIATION["WEAK_SESSION"],
            evidence=[obs.evidence], retest=None,
        )

    @classmethod
    def exposure(cls, evidence: list) -> "Finding":
        r = rate(_CVSS["EXCESSIVE_EXPOSURE"])
        return cls(
            id="EXPOSURE-USER-SECRETS",
            title="API responses expose secret fields (password hashes, API keys)",
            category="EXCESSIVE_EXPOSURE", confidence="verified",
            cvss_vector=r["vector"], cvss_score=r["score"], severity=r["severity"],
            actor_role=None, endpoint="GET /api/users/{user_id}, GET /api/users/me",
            business_impact=_IMPACT["EXCESSIVE_EXPOSURE"],
            remediation=_REMEDIATION["EXCESSIVE_EXPOSURE"],
            evidence=evidence, retest=None,
        )
