"""Principal: an acting identity in an assessment (a user + its role + session)."""
from dataclasses import dataclass


@dataclass
class Principal:
    username: str
    role: str
    token: str | None = None
    uid: int | None = None

    def redacted(self) -> dict:
        tok = (self.token[:6] + "...") if self.token else None
        return {"username": self.username, "role": self.role,
                "uid": self.uid, "token": tok}
