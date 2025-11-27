import uuid
import os
import logging
import httpx
from dotenv import load_dotenv

from .database import SessionLocal

load_dotenv()

logger = logging.getLogger("robynhood")

ROBYNHOOD_API_URL = os.getenv("ROBYNHOOD_TEST_API_URL", "https://robynhood.parssms.info/api/test/purchase")
ROBYNHOOD_API_TOKEN = os.getenv("ROBYNHOOD_TEST_API_TOKEN")


async def send_purchase_to_robynhood(order):
    """
    Отправка заказа на Robynhood после успешной оплаты
    """
    idempotency_key = str(uuid.uuid4())

    payload = {
        "product_type": order.product,
        "recipient": order.recipient,
        "idempotency_key": idempotency_key
    }

    # динамика товара
    if order.product == "stars":
        payload["quantity"] = 50

    elif order.product == "premium":
        payload["months"] = 3

    elif order.product == "ads":
        payload["amount"] = 1

    headers = {
        "Authorization": f"Bearer {ROBYNHOOD_API_TOKEN}",
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
