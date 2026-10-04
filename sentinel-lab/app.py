"""World Monitor Lab - intentionally vulnerable test target for AuthGraph Sentinel.

Run (auto-seeds on first start):
    uvicorn app:app --reload --port 8000

Force a clean reseed:
    python app.py

Ground-truth vulnerabilities (what Sentinel should independently discover):
    1. BOLA/IDOR        GET/DELETE /api/reports/{id}     - no ownership check
    2. BOLA + exposure  GET /api/users/{id}              - any user reads any user + secrets
    3. Broken RBAC      GET /api/admin/users             - no role check
    4. Priv-esc (RBAC)  POST /api/admin/users/{id}/role  - no role check
    5. Priv-esc (mass)  PATCH /api/users/me              - accepts arbitrary fields incl. role
    6. Excessive expo   /api/users/me, /api/users/{id}   - returns password_hash + api_key
    7. Weak session     auth.py                          - unsigned, forgeable, non-expiring token
"""
from fastapi import Body, Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from auth import get_current_user, issue_token, weak_hash
from database import Base, SessionLocal, engine, get_db
from models import Report, User

app = FastAPI(
    title="World Monitor Lab",
    version="0.1.0",
    description="INTENTIONALLY VULNERABLE target for AuthGraph Sentinel. Never expose publicly.",
)


# --- serializers -------------------------------------------------------------
def serialize_user(u: User, full: bool = True) -> dict:
    data = {"id": u.id, "username": u.username, "email": u.email,
            "full_name": u.full_name, "role": u.role}
    if full:
        # [VULN: excessive data exposure] secrets leak to any caller
        data["password_hash"] = u.password_hash
        data["api_key"] = u.api_key
    return data


def serialize_report(r: Report) -> dict:
    return {"id": r.id, "title": r.title, "content": r.content,
            "classification": r.classification, "owner_id": r.owner_id}


# --- auth --------------------------------------------------------------------
@app.post("/api/auth/login")
def login(payload: dict = Body(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.get("username")).first()
    if not user or user.password_hash != weak_hash(payload.get("password", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": issue_token(user), "role": user.role}


# --- users -------------------------------------------------------------------
@app.get("/api/users/me")
def me(current: User = Depends(get_current_user)):
    return serialize_user(current, full=True)  # [VULN: excessive data exposure]


@app.patch("/api/users/me")
def update_me(payload: dict = Body(...), current: User = Depends(get_current_user),
              db: Session = Depends(get_db)):
    # [VULN: mass assignment -> privilege escalation] any attribute incl. role is set
    for key, value in payload.items():
        if hasattr(current, key):
            setattr(current, key, value)
    db.commit(); db.refresh(current)
    return serialize_user(current, full=True)


@app.get("/api/users/{user_id}")
def get_user(user_id: int, current: User = Depends(get_current_user),
             db: Session = Depends(get_db)):
    # [VULN: BOLA + excessive exposure] any authenticated user reads any user
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Not found")
    return serialize_user(u, full=True)


# --- reports -----------------------------------------------------------------
@app.get("/api/reports")
def list_reports(current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # CONTROL (intentionally correct): scoped to the caller. Sentinel should NOT flag this.
    rows = db.query(Report).filter(Report.owner_id == current.id).all()
    return [serialize_report(r) for r in rows]


@app.get("/api/reports/{report_id}")
def get_report(report_id: int, current: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    # [VULN: BOLA/IDOR] no ownership check; sequential ids are guessable
    r = db.query(Report).filter(Report.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Not found")
    return serialize_report(r)


@app.delete("/api/reports/{report_id}")
def delete_report(report_id: int, current: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    # [VULN: BOLA + broken function-level auth] no ownership/role check
    r = db.query(Report).filter(Report.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(r); db.commit()
    return {"deleted": report_id}


# --- admin (role checks intentionally missing) -------------------------------
@app.get("/api/admin/users")
def admin_list_users(current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # [VULN: broken RBAC] should require role == "admin"; never checked
    return [serialize_user(u, full=True) for u in db.query(User).all()]


@app.post("/api/admin/users/{user_id}/role")
def admin_set_role(user_id: int, payload: dict = Body(...),
                   current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # [VULN: broken RBAC -> privilege escalation] non-admins can change any role
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Not found")
    u.role = payload.get("role", u.role); db.commit()
    return serialize_user(u, full=True)


# --- lab-only test hook (NOT part of the assessed surface) -------------------
@app.post("/api/_lab/reset")
def lab_reset():
    """Restore known seed state. Used by the engine to make destructive tests
    deterministic and to leave the lab clean afterwards. Lab-only, not a target."""
    seed(drop=True)
    return {"reset": True}


# --- seeding -----------------------------------------------------------------
def seed(drop: bool = False):
    if drop:
        Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    if db.query(User).first():
        db.close()
        return
    users = [
        User(username="alice", email="alice@worldmonitor.local", full_name="Alice Admin",
             role="admin", password_hash=weak_hash("alice123"), api_key="wm_live_alice_0001"),
        User(username="bob", email="bob@worldmonitor.local", full_name="Bob Analyst",
             role="analyst", password_hash=weak_hash("bob123"), api_key="wm_live_bob_0002"),
        User(username="carol", email="carol@worldmonitor.local", full_name="Carol Viewer",
             role="viewer", password_hash=weak_hash("carol123"), api_key="wm_live_carol_0003"),
    ]
    db.add_all(users); db.commit()
    for u in users:
        db.refresh(u)
    db.add_all([
        Report(title="Q3 Ops Summary", content="Internal ops numbers",
               classification="internal", owner_id=users[1].id),           # owned by bob
        Report(title="Exec Confidential Brief", content="Board-only material",
               classification="confidential", owner_id=users[0].id),       # owned by alice
        Report(title="Carol's Draft", content="Viewer draft notes",
               classification="internal", owner_id=users[2].id),           # owned by carol
    ])
    db.commit(); db.close()


seed()  # auto-seed on import if empty


if __name__ == "__main__":
    seed(drop=True)
    print("World Monitor Lab reseeded. Start with: uvicorn app:app --reload --port 8000")
