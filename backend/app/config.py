"""Assessment configuration.

The `allowed_hosts` list is the authorization boundary for the whole engine.
Every HTTP request made by Sentinel is routed through ScopedClient, which
refuses any host not on this list. Nothing Sentinel does can reach a target
you have not explicitly authorized here.
"""
import os
from dataclasses import dataclass, field


@dataclass
class RoleCredential:
    role: str
    username: str
    password: str


@dataclass
class AssessmentConfig:
    name: str
    base_url: str                        # scheme://host:port of the target
    allowed_hosts: list[str]             # HARD allowlist (host:port). The scope guard.
    openapi_path: str = "/openapi.json"
    login_path: str = "/api/auth/login"
    credentials: list[RoleCredential] = field(default_factory=list)


# Default target: the local World Monitor Lab only.
# Overridable via env so the same image works under Docker (lab:8000) and
# locally (127.0.0.1:8000) without code changes.
_BASE_URL = os.getenv("TARGET_BASE_URL", "http://127.0.0.1:8000")
_ALLOWED = os.getenv("TARGET_ALLOWED_HOSTS", "127.0.0.1:8000,localhost:8000")

LAB = AssessmentConfig(
    name=os.getenv("TARGET_NAME", "World Monitor Lab"),
    base_url=_BASE_URL,
    allowed_hosts=[h.strip() for h in _ALLOWED.split(",") if h.strip()],
    credentials=[
        RoleCredential("admin", "alice", "alice123"),
        RoleCredential("analyst", "bob", "bob123"),
        RoleCredential("viewer", "carol", "carol123"),
    ],
)
