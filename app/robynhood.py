import uuid
import os
import logging
import httpx
from dotenv import load_dotenv

from .models import Order
from .database import SessionLocal


dotenv_path = "/var/www/crypto_mvp/more-stars-backend/.env"
load_dotenv(dotenv_path=dotenv_path)

logger = logging.getLogger("robynhood")

ROBYNHOOD_API_URL = os.getenv("ROBYNHOOD_TEST_API_URL", "https://robynhood.parssms.info/api/purchase")
ROBYNHOOD_API_TOKEN = os.getenv("ROBYNHOOD_API_TOKEN")


import re

import re

async def send_purchase_to_robynhood(order):
    idempotency_key = str(uuid.uuid4())

    # Определяем тип продукта
    if "stars" in order.product.lower() or "⭐" in order.product:
        product_type = "stars"
        quantity = int(re.sub(r"\D", "", order.product))  # извлекаем число
    elif "premium" in order.product.lower():
        product_type = "premium"
        quantity = int(re.sub(r"\D", "", order.product))
    elif "ads" in order.product.lower():
        product_type = "ads"
        quantity = int(re.sub(r"\D", "", order.product))
    else:
        raise ValueError(f"Unknown product type: {order.product}")

    payload = {
        "product_type": product_type,
        "recipient": order.recipient,
        "idempotency_key": idempotency_key
    }

    # ставим число в нужное поле
    if product_type == "stars":
        payload["quantity"] = str(quantity)
    elif product_type == "premium":
        payload["months"] = str(quantity)
    elif product_type == "ads":
        payload["amount"] = str(quantity)

    headers = {
        "X-API-Key": ROBYNHOOD_API_TOKEN,
        "Content-Type": "application/json"
    }

    logger.info(f"[ROBYNHOOD] Sending: {payload}")

    async with httpx.AsyncClient() as client:
        r = await client.post(ROBYNHOOD_API_URL, json=payload, headers=headers, timeout=15)
        resp = r.json()
        logger.info(f"[ROBYNHOOD] Response: {resp}")

    # сохраняем idempotency_key
    db = SessionLocal()
    db_order = db.query(Order).filter(Order.order_id == order.order_id).first()
    if db_order:
        db_order.idempotency_key = idempotency_key
        db.commit()
    db.close()

    return resp


