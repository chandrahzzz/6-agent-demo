from __future__ import annotations

import asyncio
import contextlib
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import internal
from .api.v1 import actions, auth, drills, incidents, overview
from .core import errors
from .core.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
# Access logs contain only method + path (no bodies, no query values of note); keep them quiet.
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)


async def _nginx_poller() -> None:
    """Pull CDN access logs every few seconds so the access_events table stays current."""
    from .investigation import ingest
    while True:
        with contextlib.suppress(Exception):
            await asyncio.to_thread(ingest.pull_nginx)
        await asyncio.sleep(3)


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    task = asyncio.create_task(_nginx_poller())
    yield
    task.cancel()


app = FastAPI(title="MALLYA API", version="0.1.0", lifespan=lifespan,
              description="Autonomous data privacy engineer — concept prototype (SANDBOX).")
errors.install(app)
app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in settings().cors_origins.split(",")],
                   allow_credentials=True, allow_methods=["GET", "POST", "PUT", "DELETE"], allow_headers=["content-type"])

for r in (auth.router, incidents.router, drills.router, actions.router, overview.router):
    app.include_router(r, prefix="/api/v1")
app.include_router(overview.public, prefix="/api/v1")
app.include_router(internal.router)
