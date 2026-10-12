import asyncio
import json
from typing import Set, Dict, Any
from fastapi import WebSocket
from app.core.logging import logger


class ConnectionManager:
    """Manages WebSocket connections and real-time event broadcasting."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)
        logger.info(f"[WEBSOCKET] Client connected. Total active: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(f"[WEBSOCKET] Client disconnected. Total active: {len(self.active_connections)}")

    async def broadcast(self, message_type: str, data: Dict[str, Any]):
        """Broadcast structured event to all active clients."""
        payload = json.dumps({
            "type": message_type,
            "data": data
        })
        async with self._lock:
            dead_connections = []
            for connection in self.active_connections:
                try:
                    await connection.send_text(payload)
                except Exception:
                    dead_connections.append(connection)

            for dead in dead_connections:
                self.active_connections.remove(dead)

    def broadcast_sync(self, message_type: str, data: Dict[str, Any]):
        """Synchronous wrapper to broadcast from worker threads or sniffer callbacks."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(self.broadcast(message_type, data), loop)
        except Exception as e:
            logger.debug(f"[WEBSOCKET] Failed to broadcast sync: {e}")


ws_manager = ConnectionManager()
