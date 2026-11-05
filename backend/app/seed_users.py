"""Demo users (DEMO-ONLY credentials, sandbox use only)."""
from __future__ import annotations

from sqlalchemy import select

from .core.db import session_scope
from .core.security import hash_password
from .models import User

DEMO_PASSWORD = "mallya-demo-2026"  # demo-only; printed on the sign-in page; never use outside the sandbox
DEMO_USERS = [
    ("admin@meridian.demo", "Asha Admin", "ADMIN"),
    ("analyst@meridian.demo", "Sam Analyst", "SECURITY_ANALYST"),
    ("engineer@meridian.demo", "Ira Engineer", "IMPLEMENTATION_ENGINEER"),
    ("viewer@meridian.demo", "Vik Viewer", "VIEWER"),
]


def main() -> None:
    with session_scope() as db:
        for email, name, role in DEMO_USERS:
            if not db.execute(select(User).where(User.email == email)).scalar_one_or_none():
                db.add(User(email=email, name=name, role=role, password_hash=hash_password(DEMO_PASSWORD), is_demo=True))
    print("demo users ready")


if __name__ == "__main__":
    main()
