import asyncio

from .config import ADMIN_CHAT_IDS
from bot import send_admin_message


async def notify_admin(text: str) -> None:
    if not ADMIN_CHAT_IDS:
        return

    tasks = []
    for cid in ADMIN_CHAT_IDS:
        try:
            tasks.append(send_admin_message(chat_id=int(cid), text=text))
        except (TypeError, ValueError):
            continue

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

