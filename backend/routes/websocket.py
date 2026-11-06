"""
WebSocket Telemetry Route
=========================
Handles real-time WebSocket client connections and dynamic mode switching
between 'live' public OSINT feeds and 'custom' user-configured feeds.
"""

import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ws_manager import manager

router = APIRouter(tags=["websocket"])


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            raw_msg = await websocket.receive_text()
            try:
                msg = json.loads(raw_msg)
                if msg.get("action") in ("auth", "set_mode"):
                    manager.set_client_auth(
                        websocket,
                        token=msg.get("token"),
                    )
            except Exception:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)
