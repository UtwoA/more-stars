import uuid
import os
import logging
import httpx
from dotenv import load_dotenv

from .models import Order
from .database import SessionLocal

load_dotenv()

logger = logging.getLogger("robynhood")

ROBYNHOOD_API_URL = os.getenv("ROBYNHOOD_API_URL", "https://robynhood.parssms.info/api/purchase")
ROBYNHOOD_API_TOKEN = os.getenv("ROBYNHOOD_API_TOKEN")


def _build_payload(order: Order, idempotency_key: str) -> dict:
    payload = {
        "product_type": order.product_type,
        "recipient": order.recipient,
        "idempotency_key": idempotency_key
    }

    if order.product_type == "stars":
        payload["quantity"] = str(order.quantity)
    elif order.product_type == "premium":
        payload["months"] = str(order.months)
    elif order.product_type == "ads":
        payload["amount"] = str(order.amount)

    return payload


async def send_purchase_to_robynhood(order: Order) -> dict:
    if not ROBYNHOOD_API_TOKEN:
        raise RuntimeError("ROBYNHOOD_API_TOKEN is not set")

    idempotency_key = str(uuid.uuid4())
    payload = _build_payload(order, idempotency_key)

    headers = {
        "X-API-Key": ROBYNHOOD_API_TOKEN,
        "Content-Type": "application/json"
    }

    logger.info(f"[ROBYNHOOD] Sending: {payload}")

    async with httpx.AsyncClient() as client:
        r = await client.post(ROBYNHOOD_API_URL, json=payload, headers=headers, timeout=15)
        r.raise_for_status()
        resp = r.json()
        logger.info(f"[ROBYNHOOD] Response: {resp}")

    db = SessionLocal()
    db_order = db.query(Order).filter(Order.order_id == order.order_id).first()
    if db_order:
        db_order.idempotency_key = idempotency_key
        db_order.robynhood_transaction_id = resp.get("transaction_id")
        db_order.robynhood_status = resp.get("status")
        db.commit()
    db.close()

    return resp


