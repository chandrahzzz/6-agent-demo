from __future__ import annotations

from alembic import context

from app.core.db import engine
from app.models import Base

target_metadata = Base.metadata


def run() -> None:
    with engine().connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


run()
