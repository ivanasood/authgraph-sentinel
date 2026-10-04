"""World Monitor Lab - authentication layer.

NOTE: This layer is DELIBERATELY WEAK so AuthGraph Sentinel has concrete,
reproducible findings. Do not copy this into real software.
"""
import base64
import hashlib
import json

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import User


def weak_hash(password: str) -> str:
    # [VULN: insecure password storage] unsalted SHA-256
    return hashlib.sha256(password.encode()).hexdigest()


def issue_token(user: User) -> str:
    # [VULN: weak session] unsigned + non-expiring token. Anyone can forge one
    # by base64-encoding {"uid": <any>, "role": "admin"}.
    payload = {"uid": user.id, "role": user.role}
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()


def decode_token(token: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(token.encode()).decode())


def get_current_user(
    authorization: str = Header(None), db: Session = Depends(get_db)
) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1]
    try:
        # [VULN: weak session] token is trusted with no signature verification.
        claims = decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.id == claims.get("uid")).first()
    if not user:
        raise HTTPException(status_code=401, detail="Unknown user")
    return user
