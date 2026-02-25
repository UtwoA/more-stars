import json
import logging
import os
import uuid
from datetime import timedelta

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Query, Header, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, root_validator
from sqlalchemy import text
from zoneinfo import ZoneInfo

from .crypto_pay import verify_signature
from .crypto import convert_rub_to_crypto
from .database import SessionLocal, Base, engine
from .models import Order
from .utils import now_msk
from .robokassa_service import verify_result_signature
from .fragment import send_purchase_to_fragment
from bot import send_user_message


load_dotenv()

CRYPTO_PAY_API_URL = os.getenv("CRYPTO_PAY_API_URL", "https://testnet-pay.crypt.bot/api/createInvoice")
CRYPTOBOT_TOKEN = os.getenv("CRYPTOBOT_TOKEN")
CRYPTO_PAY_GET_INVOICES_URL = f"{CRYPTO_PAY_API_URL.rsplit('/', 1)[0]}/getInvoices"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

app = FastAPI()
Base.metadata.create_all(bind=engine)
with engine.begin() as conn:
    conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS fragment_transaction_id VARCHAR"))
    conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS fragment_status VARCHAR"))

MSK = ZoneInfo("Europe/Moscow")


class OrderCreateBase(BaseModel):
    user_id: str
    recipient: str
    product_type: str
    quantity: int | None = None
    months: int | None = None
    amount: float | None = None
    amount_rub: float

    @root_validator(skip_on_failure=True)
    def validate_product_fields(cls, values):
        product_type = (values.get("product_type") or "").lower()
        values["product_type"] = product_type

        quantity = values.get("quantity")
        months = values.get("months")
        amount = values.get("amount")

        if product_type == "stars":
            if not quantity:
                raise ValueError("quantity is required for stars")
        elif product_type == "premium":
            if not months:
                raise ValueError("months is required for premium")
        elif product_type == "ads":
            if amount is None:
                raise ValueError("amount is required for ads")
        else:
            raise ValueError("product_type must be one of: stars, premium, ads")

        return values


class CryptoOrderCreate(OrderCreateBase):
    currency: str  # TON / USDT


class RobokassaOrderCreate(OrderCreateBase):
    pass


class FragmentOrderCreate(OrderCreateBase):
    pass


def _product_label(order: Order) -> str:
    if order.product_type == "stars":
        return f"Stars x{order.quantity}"
    if order.product_type == "premium":
        return f"Premium {order.months} month(s)"
    if order.product_type == "ads":
        return f"Ads amount {order.amount}"
    return order.product_type


def _extract_order_id(data: dict) -> str | None:
    if isinstance(data.get("payload"), str):
        return data.get("payload")
    if isinstance(data.get("payload"), dict):
        return data.get("payload", {}).get("payload") or data.get("payload", {}).get("order_id")
    return data.get("order_id")


async def _create_crypto_invoice(amount: float, currency: str, order_id: str, recipient: str) -> dict:
    if not CRYPTOBOT_TOKEN:
        raise RuntimeError("CRYPTOBOT_TOKEN is not set")

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
        r.raise_for_status()
        return r.json()


async def _sync_crypto_order_status(order: Order, db) -> None:
    # Fallback: if webhook is not received, sync invoice status directly from Crypto Pay API.
    if order.payment_provider != "crypto" or order.status in ("paid", "failed"):
        return
    if not order.payment_invoice_id or not CRYPTOBOT_TOKEN:
        return

    headers = {"Crypto-Pay-API-Token": CRYPTOBOT_TOKEN}
    params = {"invoice_ids": str(order.payment_invoice_id)}

    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(CRYPTO_PAY_GET_INVOICES_URL, params=params, headers=headers, timeout=15)
            r.raise_for_status()
            payload = r.json()
    except Exception:
        logger.exception("[CRYPTO] Failed to sync invoice status for order %s", order.order_id)
        return

    items = payload.get("result", {}).get("items") or []
    if not items:
        return

    status = items[0].get("status")
    if status == "paid":
        order.status = "paid"
        db.commit()
        try:
            await send_purchase_to_fragment(order)
            await send_user_message(chat_id=int(order.user_id), product_name=_product_label(order))
        except Exception:
            logger.exception("[FRAGMENT] Failed to send purchase")
            order.status = "failed"
            db.commit()
    elif status in ("expired", "failed"):
        order.status = "failed"
        db.commit()


def _create_order(db, order_in: OrderCreateBase, provider: str, currency: str | None = None) -> Order:
    order_id = str(uuid.uuid4())

    db_order = Order(
        order_id=order_id,
        user_id=order_in.user_id,
        recipient=order_in.recipient if order_in.recipient != "@unknown" else "self",
        product_type=order_in.product_type,
        quantity=order_in.quantity,
        months=order_in.months,
        amount=order_in.amount,
        amount_rub=order_in.amount_rub,
        currency=currency or "RUB",
        status="created",
        payment_provider=provider,
        timestamp=now_msk(),
        expires_at=now_msk() + timedelta(minutes=10)
    )

    db.add(db_order)
    db.commit()
    db.refresh(db_order)
    return db_order


def _check_order_expired(order: Order, db):
    if order.status == "created" and order.expires_at < now_msk():
        order.status = "failed"
        db.commit()
    return order


@app.post("/orders/crypto")
async def create_order_crypto(order: CryptoOrderCreate):
    if order.product_type != "stars":
        raise HTTPException(status_code=400, detail="Only Stars are supported right now")
    amount_crypto = await convert_rub_to_crypto(order.amount_rub, order.currency)

    db = SessionLocal()
    try:
        db_order = _create_order(db, order, provider="crypto", currency=order.currency)

        invoice = await _create_crypto_invoice(
            amount_crypto,
            order.currency,
            db_order.order_id,
            db_order.recipient
        )

        db_order.payment_invoice_id = str(invoice.get("result", {}).get("invoice_id") or "")
        db.commit()

        return {
            "order_id": db_order.order_id,
            "amount_rub": db_order.amount_rub,
            "amount_crypto": amount_crypto,
            "currency": order.currency,
            "crypto_invoice": invoice
        }
    finally:
        db.close()


@app.post("/orders/robokassa")
async def create_order_robokassa(order: RobokassaOrderCreate):
    raise HTTPException(status_code=503, detail="SBP/Robokassa payment is temporarily unavailable")


@app.post("/orders/fragment")
async def create_order_fragment(order: FragmentOrderCreate):
    db = SessionLocal()
    try:
        db_order = _create_order(db, order, provider="fragment", currency="TON")
        try:
            resp = await send_purchase_to_fragment(db_order)
        except Exception:
            logger.exception("[FRAGMENT] Failed to send purchase")
            db_order.status = "failed"
            db.commit()
            return {"order_id": db_order.order_id, "status": "failed"}

        if resp.get("status") == "success":
            db_order.status = "paid"
        else:
            db_order.status = "failed"
        db.commit()

        return {"order_id": db_order.order_id, "status": db_order.status}
    finally:
        db.close()


@app.post("/webhook/crypto")
async def crypto_webhook(request: Request, crypto_pay_api_signature: str = Header(None)):
    if not crypto_pay_api_signature:
        raise HTTPException(status_code=400, detail="Missing crypto-pay-api-signature header")

    raw_body = await request.body()
    if not verify_signature(raw_body, crypto_pay_api_signature):
        raise HTTPException(status_code=403, detail="Invalid signature")

    data = await request.json()
    logger.info(f"WEBHOOK CRYPTO DATA: {json.dumps(data)}")

    order_id = _extract_order_id(data)
    if not order_id:
        return {"status": "error", "message": "No order_id found"}

    status = data.get("status") or data.get("payload", {}).get("status")

    db = SessionLocal()
    try:
        order = db.query(Order).filter(Order.order_id == order_id).first()
        if not order:
            return {"status": "error", "message": "Order not found"}

        if status == "paid" and order.status != "paid":
            order.status = "paid"
            db.commit()

            try:
                await send_purchase_to_fragment(order)
                await send_user_message(chat_id=int(order.user_id), product_name=_product_label(order))
            except Exception:
                logger.exception("[FRAGMENT] Failed to send purchase")
                order.status = "failed"
                db.commit()
    finally:
        db.close()

    return {"status": "ok"}


@app.post("/webhook/robokassa")
async def robokassa_webhook(
        OutSum: str = Query(...),
        InvId: str = Query(...),
        SignatureValue: str = Query(...)
):
    if not verify_result_signature(OutSum, InvId, SignatureValue):
        raise HTTPException(status_code=403, detail="Invalid signature")

    db = SessionLocal()
    try:
        order = db.query(Order).filter(Order.order_id == InvId).first()
        if not order:
            return PlainTextResponse(content=f"Order not found: {InvId}", status_code=404)

        if order.status != "paid":
            order.status = "paid"
            db.commit()

            try:
                await send_purchase_to_fragment(order)
                await send_user_message(chat_id=int(order.user_id), product_name=_product_label(order))
            except Exception:
                logger.exception("[FRAGMENT] Failed to send purchase")
                order.status = "failed"
                db.commit()

        return PlainTextResponse(content=f"OK{InvId}", status_code=200)
    finally:
        db.close()


@app.get("/orders/{order_id}")
async def order_status(order_id: str):
    db = SessionLocal()
    try:
        order = db.query(Order).filter(Order.order_id == order_id).first()
        if not order:
            return {"error": "Order not found"}

        await _sync_crypto_order_status(order, db)
        _check_order_expired(order, db)
        return {"order_id": order.order_id, "status": order.status}
    finally:
        db.close()


@app.get("/orders/last")
async def last_order_status(user_id: str = Query(...)):
    db = SessionLocal()
    try:
        order = (
            db.query(Order)
            .filter(Order.user_id == user_id)
            .order_by(Order.timestamp.desc())
            .first()
        )

        if not order:
            return {"status": "none"}

        await _sync_crypto_order_status(order, db)
        result = {
            "order_id": order.order_id,
            "status": order.status,
            "product_type": order.product_type,
            "quantity": order.quantity,
            "months": order.months,
            "amount": order.amount,
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

        _check_order_expired(order, db)
        return result
    finally:
        db.close()


@app.get("/orders/history")
async def order_history(user_id: str = Query(...), limit: int = 10):
    db = SessionLocal()
    try:
        orders = (
            db.query(Order)
            .filter(Order.user_id == user_id)
            .order_by(Order.timestamp.desc())
            .limit(limit)
            .all()
        )

        # Keep history statuses fresh even if webhook is delayed/missed.
        for order in orders:
            await _sync_crypto_order_status(order, db)
            _check_order_expired(order, db)

        orders = (
            db.query(Order)
            .filter(Order.user_id == user_id)
            .order_by(Order.timestamp.desc())
            .limit(limit)
            .all()
        )

        return {
            "orders": [
                {
                    "order_id": o.order_id,
                    "recipient": o.recipient,
                    "product_type": o.product_type,
                    "quantity": o.quantity,
                    "months": o.months,
                    "amount": o.amount,
                    "amount_rub": o.amount_rub,
                    "currency": o.currency,
                    "status": o.status,
                    "timestamp": o.timestamp.astimezone(MSK).isoformat()
                }
                for o in orders
            ]
        }
    finally:
        db.close()


@app.get("/robokassa/success")
async def robokassa_success():
    return "<html><body><script>window.location.href='/'</script></body></html>"


@app.get("/robokassa/fail")
async def robokassa_fail():
    return "<html><body><script>window.location.href='/'</script></body></html>"
