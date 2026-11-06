"""
WebSocket Connection & Session Manager
======================================
Manages active WebSocket client connections, per-client authentication binding,
and per-user custom indicator pool caching.
"""

import json
from typing import Dict, Optional
from fastapi import WebSocket

from config import logger
from database import get_user_by_raw_token


class ConnectionManager:
    def __init__(self):
        # Maps WebSocket -> {"user_id": Optional[int]}
        self.clients: Dict[WebSocket, Dict] = {}
        # Cache of geolocated custom pools per user_id: {user_id: {"pool": [...], "ts": float, "hash": str}}
        self.user_custom_pools: Dict[int, Dict] = {}

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.clients[websocket] = {"user_id": None}
        logger.info(f"Client connected. Active listeners: {len(self.clients)}")

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.clients:
            del self.clients[websocket]
            logger.info(f"Client disconnected. Active listeners: {len(self.clients)}")

    def set_client_auth(self, websocket: WebSocket, token: Optional[str]) -> None:
        if websocket not in self.clients:
            return
        user = get_user_by_raw_token(token) if token else None
        self.clients[websocket] = {"user_id": user["id"] if user else None}
        if user:
            logger.info(f"Authenticated WebSocket session for operator '{user['username']}'.")
        else:
            logger.info("WebSocket session running as unauthenticated guest (default feeds active).")

    def invalidate_user_cache(self, user_id: int) -> None:
        if user_id in self.user_custom_pools:
            del self.user_custom_pools[user_id]

    async def send_to_client(self, ws: WebSocket, message: dict) -> None:
        try:
            await ws.send_text(json.dumps(message))
        except Exception:
            self.disconnect(ws)


manager = ConnectionManager()
