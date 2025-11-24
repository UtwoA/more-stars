from fastapi import WebSocket
from typing import Dict, List

clients: Dict[int, List[WebSocket]] = {}  # user_id: websockets

async def connect_ws(user_id: int, ws: WebSocket):
    await ws.accept()
    if user_id not in clients:
        clients[user_id] = []
    clients[user_id].append(ws)

async def disconnect_ws(user_id: int, ws: WebSocket):
    if user_id in clients and ws in clients[user_id]:
        clients[user_id].remove(ws)

async def notify_frontend(order_id: int, status: str):
    """
    Отправка уведомления всем подключенным фронтам
    """
    # В реальности нужно хранить user_id или связывать order_id -> user_id
    for user_sockets in clients.values():
        for ws in user_sockets:
            await ws.send_json({"order_id": order_id, "status": status})
