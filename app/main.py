import asyncio
import hashlib
import hmac
import json
import uuid
import os
import logging
from datetime import timedelta
from fastapi import FastAPI, Request, Form, Query, Header, HTTPException
from pydantic import BaseModel
from zoneinfo import ZoneInfo
import httpx


from dotenv import load_dotenv

from .crypto_pay import verify_signature, API_TOKEN
from .database import SessionLocal, Base, engine
from .models import Order
from .utils import now_msk
from .crypto import convert_to_rub, convert_rub_to_crypto
from bot import send_user_message
from .robynhood import send_purchase_to_robynhood
from fastapi.responses import PlainTextResponse
import uuid
from datetime import datetime

from .robokassa_service import generate_payment_link, verify_result_signature



# ------------------------------------------------------
# INIT
# ------------------------------------------------------
dotenv_path = "/var/www/crypto_mvp/more-stars-backend/.env"
load_dotenv(dotenv_path=dotenv_path)

CRYPTOBOT_TOKEN = os.getenv("CRYPTOBOT_TOKEN")
CRYPTO_PAY_API_URL = "https://testnet-pay.crypt.bot/api/createInvoice"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

app = FastAPI()
Base.metadata.create_all(bind=engine)

MSK = ZoneInfo("Europe/Moscow")


# ------------------------------------------------------
# MODELS
# ------------------------------------------------------

class OrderCreate(BaseModel):
    user_id: str
    recipient: str
    product: str
    amount: float
    currency: str  # TON / USDT


# ------------------------------------------------------
# CRYPTO CREATE INVOICE
# ------------------------------------------------------

async def create_crypto_invoice(amount: float, currency: str, order_id: str, recipient: str):
    payload = {
        "currency_type": "crypto",
        "asset": currency.upper(),
        "amount": amount,
        "description": f"Покупка {recipient}",
        "payload": order_id,
        "allow_comments": False,
        "allow_anonymous": False
    }

    headers = {
        "Crypto-Pay-API-Token": CRYPTOBOT_TOKEN,
        "Content-Type": "application/json"
    }

    async with httpx.AsyncClient() as client:
        r = await client.post(CRYPTO_PAY_API_URL, json=payload, headers=headers, timeout=15)
        return r.json()


# ------------------------------------------------------
# CREATE ORDER
# ------------------------------------------------------
@app.post("/create_order")
async def create_order(order: OrderCreate):

    # рубли нам приходят с фронта
    amount_rub = order.amount

    # рубли → крипта (USDT или TON)
    amount_crypto = await convert_rub_to_crypto(order.amount, order.currency)

    db = SessionLocal()
    order_id = str(uuid.uuid4())

    db_order = Order(
        order_id=order_id,
        user_id=order.user_id,
        recipient=order.recipient if order.recipient != "@unknown" else "self",
        product=order.product,
        amount_rub=amount_rub,
        currency=order.currency,
        status="created",
        type_of_payment="crypto",
        timestamp=now_msk(),
        expires_at=now_msk() + timedelta(minutes=10)
    )

    db.add(db_order)
    db.commit()
    db.refresh(db_order)

    # создаём инвойс с количеством криптовалюты, а НЕ рублями
    invoice = await create_crypto_invoice(
        amount_crypto,
        order.currency,
        order_id,
        db_order.recipient
    )

    db.close()

    return {
        "order_id": order_id,
        "amount_rub": amount_rub,
        "crypto_invoice": invoice
    }



# ------------------------------------------------------
# WEBHOOK CRYPTO
# ------------------------------------------------------

@app.post("/webhook/crypto")
async def crypto_webhook(
    request: Request,
    crypto_pay_api_signature: str = Header(None)
):
    if not crypto_pay_api_signature:
        raise HTTPException(status_code=400, detail="Missing crypto-pay-api-signature header")

    raw_body = await request.body()

    print("RAW BODY STRING:")
    print(raw_body.decode("utf-8", errors="replace"))
    print("HEADER SIGNATURE:", crypto_pay_api_signature)

    if not verify_signature(raw_body, crypto_pay_api_signature):
        raise HTTPException(status_code=403, detail="Invalid signature")

    data = await request.json()
    logger.info(f"WEBHOOK CRYPTO DATA: {json.dumps(data)}")

    order_id = data.get("order_id") or data.get("payload", {}).get("payload")
    if not order_id:
        return {"status": "error", "message": "No order_id found"}

    db = SessionLocal()
    try:
        order = db.query(Order).filter(Order.order_id == order_id).first()
        if not order:
            return {"status": "error", "message": "Order not found"}

        status = data.get("status") or data.get("payload", {}).get("status")
        if status == "paid" and order.status != "paid":
            order.status = "paid"
            db.commit()

            asyncio.create_task(send_user_message(chat_id=int(order.user_id), product_name=order.product))
            asyncio.create_task(send_purchase_to_robynhood(order))
    finally:
        db.close()

    return {"status": "ok"}

# ------------------------------------------------------
# ORDER STATUS
# ------------------------------------------------------

def check_order_expired(order, db):
    if order.status == "created" and order.expires_at < now_msk():
        order.status = "failed"
        db.commit()
    return order


@app.get("/order_status")
async def order_status(order_id: str = Query(...)):
    db = SessionLocal()
    order = db.query(Order).filter(Order.order_id == order_id).first()


    if not order:
        db.close()
        return {"error": "Order not found"}

    check_order_expired(order, db)
    result = {"order_id": order.order_id, "status": order.status}

    db.close()
    return result


@app.get("/last_order_status")
async def last_order_status(user_id: str = Query(...)):
    db = SessionLocal()
    order = (
        db.query(Order)
        .filter(Order.user_id == user_id)
        .order_by(Order.timestamp.desc())
        .first()
    )

    if order:
        result = {
            "order_id": order.order_id,
            "status": order.status,
            "product": order.product,
            "show_success_page": False,
            "show_failure_page": False
        }

        if order.status == "paid" and order.success_page_shown == 0:
            result["show_success_page"] = True
            order.success_page_shown = 1
            db.commit()

        elif order.status == "failed" and order.failure_page_shown == 0:
            result["show_failure_page"] = True
            order.failure_page_shown = 1
            db.commit()

        check_order_expired(order, db)
        db.close()
        return result

    db.close()
    return {"status": "none"}


# ------------------------------------------------------
# ORDER HISTORY
# ------------------------------------------------------

@app.get("/order_history")
async def order_history(user_id: str = Query(...), limit: int = 10):
    db = SessionLocal()
    orders = (
        db.query(Order)
        .filter(Order.user_id == user_id)
        .order_by(Order.timestamp.desc())
        .limit(limit)
        .all()
    )
    db.close()

    return {
        "orders": [
            {
                "order_id": o.order_id,
                "product": o.product,
                "amount_rub": o.amount_rub,
                "currency": o.currency,
                "status": o.status,
                "timestamp": o.timestamp.astimezone(MSK).isoformat()
            }
            for o in orders
        ]
    }

# ---------------------
# WEBHOOK: ROBYNHOOD
# ---------------------

@app.post("/webhook/robynhood")
async def robynhood_webhook(request: Request):
    data = await request.json()
    logger.info(f"[ROBYNHOOD WEBHOOK] {data}")
    idempotency_key = data.get("idempotency_key")
    status = data.get("status")

    if not idempotency_key:
        logger.error("[ROBYNHOOD] No idempotency_key in webhook")
        return {"status": "error"}

    db = SessionLocal()

    order = db.query(Order).filter(Order.idempotency_key == idempotency_key).first()
    if not order:
        logger.error(f"[ROBYNHOOD] Order not found for idempotency_key={idempotency_key}")
        db.close()
        return {"status": "error", "message": "Order not found"}

    if status == "paid":
        order.status = "paid"
        db.commit()
        logger.info(f"[ROBYNHOOD] Order {order.order_id} marked PAID")

        asyncio.create_task(
            send_user_message(
                chat_id=int(order.user_id),
                product_name=order.product
            )
        )

    elif status == "failed":
        order.status = "failed"
        db.commit()
        logger.info(f"[ROBYNHOOD] Order {order.order_id} marked FAILED")

    db.close()
    return {"status": "ok"}


app = FastAPI()

@app.post("/create_order_robokassa")
async def create_order_robokassa(order: OrderCreate):
    db = SessionLocal()
    order_id = str(uuid.uuid4())

    db_order = Order(
        order_id=order_id,
        user_id=order.user_id,
        recipient=order.recipient if order.recipient != "@unknown" else "self",
        product=order.product,
        amount_rub=order.amount,
        currency="RUB",
        status="created",
        type_of_payment="robokassa",
        timestamp=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=10)
    )

    db.add(db_order)
    db.commit()
    db.refresh(db_order)

    payment_url = generate_payment_link(db_order)

    db.close()

    return {
        "invoice_id": order_id,
        "amount": db_order.amount_rub,
        "payment_url": payment_url
    }

@app.post("/webhook/robokassa")
async def robokassa_webhook(
        OutSum: str = Query(...),
        InvId: str = Query(...),
        SignatureValue: str = Query(...)
):
    if not verify_result_signature(OutSum, InvId, SignatureValue):
        raise HTTPException(status_code=403, detail="Invalid signature")

    db = SessionLocal()
    order = db.query(Order).filter(Order.order_id == InvId).first()
    if not order:
        db.close()
        return PlainTextResponse(content=f"Order not found: {InvId}", status_code=404)

    if order.status != "paid":
        order.status = "paid"
        db.commit()

        asyncio.create_task(send_user_message(chat_id=int(order.user_id), product_name=order.product))
        asyncio.create_task(send_purchase_to_robynhood(order))

    db.close()
    return PlainTextResponse(content=f"OK{InvId}", status_code=200)

@app.get("/robokassa/success")
async def robokassa_success():
    return "<html><body><script>window.location.href='/'</script></body></html>"

@app.get("/robokassa/fail")
async def robokassa_fail():
    return "<html><body><script>window.location.href='/'</script></body></html>"

