import uuid
import os
import logging
import httpx
import secrets
import re
from dotenv import load_dotenv
from fastapi import FastAPI, Request

from .models import Order
from .database import SessionLocal

dotenv_path = "/var/www/crypto_mvp/more-stars-backend/.env"
load_dotenv(dotenv_path=dotenv_path)

logger = logging.getLogger("robynhood")

ROBYNHOOD_API_URL = os.getenv("ROBYNHOOD_TEST_API_URL", "https://robynhood.parssms.info/api/purchase")
ROBYNHOOD_API_TOKEN = os.getenv("ROBYNHOOD_API_TOKEN")



async def send_purchase_to_robynhood(order):
    idempotency_key = str(uuid.uuid4())
    webhook_token = secrets.token_urlsafe(16)

    # Определяем тип продукта
    if "stars" in order.product.lower() or "⭐" in order.product:
        product_type = "stars"
        try:
            quantity = int(re.sub(r"\D", "", order.product))
        except ValueError:
            logger.error(f"Invalid product format: {order.product}")
            raise
    elif "premium" in order.product.lower():
        product_type = "premium"
        quantity = int(re.sub(r"\D", "", order.product))
    elif "ads" in order.product.lower():
        product_type = "ads"
        quantity = int(re.sub(r"\D", "", order.product))
    else:
        raise ValueError(f"Unknown product type: {order.product}")

    # Формируем recipient с токеном
    recipient_with_token = f"{order.recipient}|{webhook_token}"

    payload = {
        "product_type": product_type,
        "recipient": recipient_with_token,
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
        try:
            resp = r.json()
        except ValueError:
            logger.error(f"[ROBYNHOOD] Invalid JSON response: {r.text}")
            resp = {"error": "Invalid JSON"}
        if r.status_code != 201:
            logger.warning(f"[ROBYNHOOD] Status code {r.status_code}, response: {resp}")

    # сохраняем idempotency_key и webhook_token
    db = SessionLocal()
    db_order = db.query(Order).filter(Order.order_id == order.order_id).first()
    if db_order:
        db_order.idempotency_key = idempotency_key
        db_order.webhook_token = webhook_token
        db.commit()
    db.close()

    return resp
