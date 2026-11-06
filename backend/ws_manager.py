"""
WebSocket Connection & Mode Manager
===================================
Manages active WebSocket client connections, per-client feed routing ('live' vs 'custom'),
and per-user custom indicator pool caching.
"""

import json
from typing import Dict, Optional
from fastapi import WebSocket

from config import logger
from database import get_user_by_raw_token


class ConnectionManager:
    def __init__(self):
        # Maps WebSocket -> {"mode": "live" | "custom", "user_id": Optional[int]}
        self.clients: Dict[WebSocket, Dict] = {}
        # Cache of geolocated custom pools per user_id: {user_id: {"pool": [...], "ts": float, "hash": str}}
        self.user_custom_pools: Dict[int, Dict] = {}

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.clients[websocket] = {"mode": "live", "user_id": None}
        logger.info(f"Client connected. Active listeners: {len(self.clients)}")

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.clients:
            del self.clients[websocket]
            logger.info(f"Client disconnected. Active listeners: {len(self.clients)}")

    def set_client_mode(self, websocket: WebSocket, mode: str, token: Optional[str]) -> None:
        if websocket not in self.clients:
            return
        user = get_user_by_raw_token(token) if token else None
        if mode == "custom" and user:
            self.clients[websocket] = {"mode": "custom", "user_id": user["id"]}
            logger.info(f"User '{user['username']}' switched WebSocket to CUSTOM INTEL mode.")
        else:
            self.clients[websocket] = {"mode": "live", "user_id": user["id"] if user else None}
            logger.info("Client switched WebSocket to LIVE INTEL mode.")

    def invalidate_user_cache(self, user_id: int) -> None:
        if user_id in self.user_custom_pools:
            del self.user_custom_pools[user_id]

    async def broadcast_live(self, message: dict) -> None:
        """Sends live OSINT events ONLY to clients currently in 'live' mode."""
        payload = json.dumps(message)
        for ws, meta in list(self.clients.items()):
            if meta.get("mode") == "live":
                try:
                    await ws.send_text(payload)
                except Exception:
                    self.disconnect(ws)

    async def send_to_client(self, ws: WebSocket, message: dict) -> None:
        try:
            await ws.send_text(json.dumps(message))
        except Exception:
            self.disconnect(ws)


manager = ConnectionManager()
