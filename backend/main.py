"""
SOC Threat Matrix - FastAPI Application Entrypoint
==================================================
Assembles the modular OSINT streamer, SQLite authentication API, WebSocket router,
and static frontend file server.
"""

import asyncio
import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# Ensure local backend modules resolve whether launched from `backend/` or project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import FRONTEND_PATH
from database import init_db
from routes.auth import router as auth_router
from routes.websocket import router as ws_router
from services.osint_collector import osint_worker


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    task = asyncio.create_task(osint_worker())
    yield
    task.cancel()


app = FastAPI(title="SOC Threat Matrix OSINT Server", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API and WebSocket routers
app.include_router(auth_router)
app.include_router(ws_router)

# Mount static frontend application
if os.path.exists(FRONTEND_PATH):
    app.mount("/", StaticFiles(directory=FRONTEND_PATH, html=True), name="frontend")
