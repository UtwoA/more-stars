import logging
import os
from typing import Any

import httpx

logger = logging.getLogger("telegram_stars")

BOT_TOKEN = os.getenv("BOT_TOKEN")
TELEGRAM_STARS_PROVIDER_TOKEN = os.getenv("TELEGRAM_STARS_PROVIDER_TOKEN", "")


async def create_stars_invoice_link(*, title: str, description: str, payload: str, amount_stars: int) -> str:
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN is not set")
    if amount_stars <= 0:
        raise ValueError("amount_stars must be positive")

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/createInvoiceLink"
    body: dict[str, Any] = {
        "title": title,
        "description": description,
        "payload": payload,
        "currency": "XTR",
        "prices": [
            {
                "label": title,
                "amount": int(amount_stars),
            }
        ],
    }
    if TELEGRAM_STARS_PROVIDER_TOKEN:
        body["provider_token"] = TELEGRAM_STARS_PROVIDER_TOKEN

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(url, json=body)
        if r.status_code >= 400:
            logger.error("[STARS] createInvoiceLink failed: %s", r.text)
            r.raise_for_status()
        data = r.json()
        if not data.get("ok"):
            raise RuntimeError(f"Telegram API error: {data}")
        return data.get("result")
