"""
WebSocket — real-time updates para o frontend
Broadcasts: new_incident, alert_ingested, action_executed, incident_updated
"""
import json
from typing import Dict, Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from app.core.security import decode_token

router = APIRouter()

# Connection manager
class ConnectionManager:
    def __init__(self):
        # org_id -> set of websockets
        self.connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, org_id: str):
        await websocket.accept()
        if org_id not in self.connections:
            self.connections[org_id] = set()
        self.connections[org_id].add(websocket)

    def disconnect(self, websocket: WebSocket, org_id: str):
        if org_id in self.connections:
            self.connections[org_id].discard(websocket)

    async def broadcast_to_org(self, org_id: str, message: dict):
        if org_id not in self.connections:
            return
        dead = set()
        for ws in self.connections[org_id]:
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                dead.add(ws)
        for ws in dead:
            self.connections[org_id].discard(ws)


manager = ConnectionManager()


@router.websocket("/incidents")
async def websocket_incidents(websocket: WebSocket, token: str = Query(...)):
    try:
        payload = decode_token(token)
        org_id = payload.get("org")
    except Exception:
        await websocket.close(code=4001)
        return

    await manager.connect(websocket, org_id)
    try:
        while True:
            # Keep-alive ping
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket, org_id)


async def broadcast_event(org_id: str, event_type: str, data: dict):
    """Chamado pelos workers para notificar o frontend."""
    await manager.broadcast_to_org(org_id, {"type": event_type, "data": data})
