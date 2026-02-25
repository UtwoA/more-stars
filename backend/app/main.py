import asyncio
import hashlib
import hmac
import json
import logging
import os
import uuid
from datetime import timedelta, datetime, time
from urllib.parse import parse_qsl, unquote_plus

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
from bot import send_user_message, send_admin_message, build_admin_dispatcher, bot


load_dotenv()

CRYPTO_PAY_API_URL = os.getenv("CRYPTO_PAY_API_URL", "https://testnet-pay.crypt.bot/api/createInvoice")
CRYPTOBOT_TOKEN = os.getenv("CRYPTOBOT_TOKEN")
CRYPTO_PAY_GET_INVOICES_URL = f"{CRYPTO_PAY_API_URL.rsplit('/', 1)[0]}/getInvoices"
PLATEGA_BASE_URL = os.getenv("PLATEGA_BASE_URL", "https://app.platega.io")
PLATEGA_MERCHANT_ID = os.getenv("PLATEGA_MERCHANT_ID")
PLATEGA_SECRET = os.getenv("PLATEGA_SECRET")
PLATEGA_PAYMENT_METHOD = int(os.getenv("PLATEGA_PAYMENT_METHOD", "2"))
PLATEGA_RETURN_URL = os.getenv("PLATEGA_RETURN_URL")
PLATEGA_FAIL_URL = os.getenv("PLATEGA_FAIL_URL")
PLATEGA_WEBHOOK_SIGNING_SECRET = os.getenv("PLATEGA_WEBHOOK_SIGNING_SECRET")
PLATEGA_WEBHOOK_IP_ALLOWLIST = {
    ip.strip() for ip in (os.getenv("PLATEGA_WEBHOOK_IP_ALLOWLIST") or "").split(",") if ip.strip()
}
PLATEGA_WEBHOOK_TOKEN = os.getenv("PLATEGA_WEBHOOK_TOKEN")
BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID")
MINI_APP_URL = os.getenv("MINI_APP_URL")

API_AUTH_KEY = os.getenv("API_AUTH_KEY")
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "30"))
ALLOW_UNVERIFIED_INITDATA = os.getenv("ALLOW_UNVERIFIED_INITDATA", "false").lower() in ("1", "true", "yes")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

app = FastAPI()
Base.metadata.create_all(bind=engine)
with engine.begin() as conn:
    conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS fragment_transaction_id VARCHAR"))
    conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS fragment_status VARCHAR"))
    conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS fragment_in_progress BOOLEAN"))
    conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS fragment_attempts INTEGER"))
    conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS fragment_last_error VARCHAR"))
    conn.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS payment_transactions (
                id SERIAL PRIMARY KEY,
                order_id VARCHAR NOT NULL,
                provider VARCHAR NOT NULL,
                provider_txn_id VARCHAR,
                status VARCHAR,
                amount FLOAT,
                currency VARCHAR,
                raw_response TEXT,
                created_at TIMESTAMPTZ DEFAULT now()
            )
            """
        )
    )

MSK = ZoneInfo("Europe/Moscow")
_last_app_up: bool | None = None


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
        recipient = (values.get("recipient") or "").strip()

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

        if recipient not in ("self", "@unknown"):
            if not recipient.startswith("@"):
                raise ValueError("recipient must start with @")
            handle = recipient[1:]
            if not handle or len(handle) < 5 or len(handle) > 32:
                raise ValueError("recipient username length is invalid")
            if not handle.replace("_", "").isalnum():
                raise ValueError("recipient username contains invalid characters")

        user_id = values.get("user_id")
        if not user_id or not str(user_id).isdigit():
            raise ValueError("user_id must be numeric")

        return values


class CryptoOrderCreate(OrderCreateBase):
    currency: str  # TON / USDT


class RobokassaOrderCreate(OrderCreateBase):
    pass


class PlategaOrderCreate(OrderCreateBase):
    payment_method: int | None = None


def _product_label(order: Order) -> str:
    if order.product_type == "stars":
        return f"Stars x{order.quantity}"
    if order.product_type == "premium":
        return f"Premium {order.months} month(s)"
    if order.product_type == "ads":
        return f"Ads amount {order.amount}"
    return order.product_type


def _constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def _verify_telegram_init_data(init_data: str) -> bool:
    if not BOT_TOKEN:
        return False
    secret_key = hashlib.sha256(BOT_TOKEN.encode()).digest()

    # Path 1: decoded pairs (standard approach)
    parsed = dict(parse_qsl(init_data, keep_blank_values=True))
    hash_value = parsed.pop("hash", "")
    if hash_value:
        data_check = "\n".join(f"{k}={parsed[k]}" for k in sorted(parsed))
        h = hmac.new(secret_key, data_check.encode(), hashlib.sha256).hexdigest()
        if _constant_time_eq(h, hash_value):
            return True

    # Path 2: raw pairs with explicit unquote_plus on values
    raw_pairs = []
    raw_hash = ""
    for pair in init_data.split("&"):
        if not pair:
            continue
        k, _, v = pair.partition("=")
        if k == "hash":
            raw_hash = v
            continue
        raw_pairs.append((k, unquote_plus(v)))
    if not raw_hash:
        return False
    raw_check = "\n".join(f"{k}={v}" for k, v in sorted(raw_pairs))
    h2 = hmac.new(secret_key, raw_check.encode(), hashlib.sha256).hexdigest()
    return _constant_time_eq(h2, raw_hash)


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class _RateLimiter:
    def __init__(self, limit_per_min: int):
        self.limit = limit_per_min
        self.buckets: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = asyncio.get_event_loop().time()
        window_start = now - 60
        bucket = self.buckets.get(key, [])
        bucket = [t for t in bucket if t >= window_start]
        if len(bucket) >= self.limit:
            self.buckets[key] = bucket
            return False
        bucket.append(now)
        self.buckets[key] = bucket
        return True


_rate_limiter = _RateLimiter(RATE_LIMIT_PER_MIN)


@app.middleware("http")
async def auth_and_rate_limit(request: Request, call_next):
    path = request.url.path
    if path.startswith("/webhook/"):
        return await call_next(request)

    if path.startswith("/orders/"):
        if not _rate_limiter.allow(_client_ip(request)):
            return PlainTextResponse("Too Many Requests", status_code=429)

        api_key = request.headers.get("x-api-key")
        if API_AUTH_KEY and api_key and _constant_time_eq(api_key, API_AUTH_KEY):
            return await call_next(request)

        init_data = request.headers.get("x-telegram-init-data")
        if init_data:
            if _verify_telegram_init_data(init_data):
                return await call_next(request)
            if ALLOW_UNVERIFIED_INITDATA:
                logger.warning("[AUTH] Allowing unverified initData for %s", path)
                return await call_next(request)

        return PlainTextResponse("Unauthorized", status_code=401)

    return await call_next(request)


async def _safe_send_user_message(order: Order) -> None:
    try:
        chat_id = int(order.user_id)
    except (TypeError, ValueError):
        logger.warning("[BOT] Invalid user_id for chat_id: %s", order.user_id)
        return
    await send_user_message(chat_id=chat_id, product_name=_product_label(order))


async def _notify_admin(text: str) -> None:
    if not ADMIN_CHAT_ID:
        return
    try:
        await send_admin_message(chat_id=int(ADMIN_CHAT_ID), text=text)
    except Exception:
        logger.exception("[ADMIN] Failed to send admin message")


async def _send_daily_report() -> None:
    if not ADMIN_CHAT_ID:
        return
    from .admin_reports import build_admin_report
    text = await build_admin_report()
    await _notify_admin(text)


async def _daily_report_loop() -> None:
    while True:
        now = now_msk()
        tomorrow = now.date() + timedelta(days=1)
        next_midnight = datetime.combine(tomorrow, time(0, 0), tzinfo=MSK)
        sleep_seconds = (next_midnight - now).total_seconds()
        await asyncio.sleep(max(1, sleep_seconds))
        await _send_daily_report()


async def _check_mini_app() -> None:
    global _last_app_up
    if not MINI_APP_URL:
        return
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(MINI_APP_URL, timeout=15)
        is_up = r.status_code < 400
    except Exception:
        is_up = False

    if _last_app_up is None:
        _last_app_up = is_up
        return

    if is_up != _last_app_up:
        status = "UP ✅" if is_up else "DOWN ❌"
        await _notify_admin(f"🔔 Mini app status changed: {status}\nurl={MINI_APP_URL}")
        _last_app_up = is_up


async def _availability_loop() -> None:
    while True:
        await _check_mini_app()
        await asyncio.sleep(30 * 60)


@app.on_event("startup")
async def _startup_tasks():
    asyncio.create_task(_daily_report_loop())
    asyncio.create_task(_availability_loop())
    if ADMIN_CHAT_ID:
        dp = build_admin_dispatcher(ADMIN_CHAT_ID)
        asyncio.create_task(dp.start_polling(bot))


async def _fulfill_order_if_needed(order: Order, db) -> None:
    if order.product_type != "stars":
        return
    if (order.fragment_status or "").lower() == "success":
        return

    claim = db.execute(
        text(
            """
            UPDATE orders
            SET fragment_in_progress = TRUE,
                fragment_attempts = COALESCE(fragment_attempts, 0) + 1
            WHERE order_id = :order_id
              AND (fragment_in_progress IS NULL OR fragment_in_progress = FALSE)
              AND (fragment_status IS NULL OR fragment_status != 'success')
            """
        ),
        {"order_id": order.order_id},
    )
    db.commit()
    if claim.rowcount == 0:
        return

    last_error = None
    for delay in (0, 2, 5):
        if delay:
            await asyncio.sleep(delay)
        try:
            resp = await send_purchase_to_fragment(order)
            if resp.get("status") == "success":
                last_error = None
                break
            last_error = RuntimeError("Fragment returned non-success status")
        except Exception as exc:
            last_error = exc
            logger.exception("[FRAGMENT] Failed to send purchase")

    if last_error:
        order.status = "failed"
        order.fragment_last_error = str(last_error)
        order.fragment_in_progress = False
        db.commit()
        await _notify_admin(
            f"❗ Fragment purchase failed\n"
            f"order_id={order.order_id}\n"
            f"user_id={order.user_id}\n"
            f"error={order.fragment_last_error}"
        )
        return

    try:
        await _safe_send_user_message(order)
    except Exception:
        logger.exception("[BOT] Failed to send user message")
    await _notify_admin(
        f"✅ Purchase completed\n"
        f"order_id={order.order_id}\n"
        f"user_id={order.user_id}\n"
        f"product={_product_label(order)}"
    )
    order.fragment_in_progress = False
    db.commit()


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


async def _create_platega_payment(amount_rub: float, order_id: str) -> dict:
    return await _create_platega_payment_with_method(amount_rub, order_id, PLATEGA_PAYMENT_METHOD)


async def _create_platega_payment_with_method(amount_rub: float, order_id: str, payment_method: int) -> dict:
    if not PLATEGA_MERCHANT_ID or not PLATEGA_SECRET:
        raise RuntimeError("PLATEGA_MERCHANT_ID or PLATEGA_SECRET is not set")

    payload = {
        "paymentMethod": payment_method,
        "paymentDetails": {"amount": amount_rub, "currency": "RUB"},
        "description": f"Order {order_id}",
        "payload": order_id
    }
    if PLATEGA_RETURN_URL:
        payload["return"] = PLATEGA_RETURN_URL
    if PLATEGA_FAIL_URL:
        payload["failedUrl"] = PLATEGA_FAIL_URL

    headers = {
        "X-MerchantId": PLATEGA_MERCHANT_ID,
        "X-Secret": PLATEGA_SECRET,
        "Content-Type": "application/json"
    }

    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{PLATEGA_BASE_URL}/transaction/process",
            json=payload,
            headers=headers,
            timeout=20
        )
        if r.status_code >= 400:
            logger.error("[PLATEGA] Create payment failed: %s %s", r.status_code, r.text)
            r.raise_for_status()
        resp = r.json()

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO payment_transactions
                (order_id, provider, provider_txn_id, status, amount, currency, raw_response)
                VALUES (:order_id, :provider, :provider_txn_id, :status, :amount, :currency, :raw_response)
                """
            ),
            {
                "order_id": order_id,
                "provider": "platega",
                "provider_txn_id": resp.get("transactionId"),
                "status": resp.get("status"),
                "amount": amount_rub,
                "currency": "RUB",
                "raw_response": json.dumps(resp),
            },
        )

    return resp


async def _get_platega_status(transaction_id: str, order_id: str | None = None) -> dict:
    if not PLATEGA_MERCHANT_ID or not PLATEGA_SECRET:
        raise RuntimeError("PLATEGA_MERCHANT_ID or PLATEGA_SECRET is not set")

    headers = {
        "X-MerchantId": PLATEGA_MERCHANT_ID,
        "X-Secret": PLATEGA_SECRET,
        "Content-Type": "application/json"
    }

    async with httpx.AsyncClient() as client:
        r = await client.get(
            f"{PLATEGA_BASE_URL}/transaction/{transaction_id}",
            headers=headers,
            timeout=20
        )
        r.raise_for_status()
        resp = r.json()

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO payment_transactions
                (order_id, provider, provider_txn_id, status, raw_response)
                VALUES (:order_id, :provider, :provider_txn_id, :status, :raw_response)
                """
            ),
            {
                "order_id": order_id or "",
                "provider": "platega_status",
                "provider_txn_id": transaction_id,
                "status": resp.get("status"),
                "raw_response": json.dumps(resp),
            },
        )

    return resp


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
        await _fulfill_order_if_needed(order, db)
    elif status in ("expired", "failed"):
        order.status = "failed"
        db.commit()


async def _sync_platega_order_status(order: Order, db) -> None:
    if order.payment_provider != "platega" or order.status == "paid":
        return
    if not order.payment_invoice_id:
        return

    try:
        payload = await _get_platega_status(order.payment_invoice_id, order.order_id)
    except Exception:
        logger.exception("[PLATEGA] Failed to sync payment status for order %s", order.order_id)
        return

    status = (payload.get("status") or "").upper()
    if status == "CONFIRMED":
        order.status = "paid"
        db.commit()
        await _fulfill_order_if_needed(order, db)
    elif status in ("CANCELED", "CHARGEBACKED"):
        order.status = "failed"
        order.fragment_last_error = f"platega_status={status}"
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


@app.post("/orders/platega")
async def create_order_platega(order: PlategaOrderCreate):
    if order.product_type != "stars":
        raise HTTPException(status_code=400, detail="Only Stars are supported right now")

    payment_method = order.payment_method or PLATEGA_PAYMENT_METHOD
    if payment_method not in (2, 11):
        raise HTTPException(status_code=400, detail="Unsupported payment method")

    db = SessionLocal()
    try:
        db_order = _create_order(db, order, provider="platega", currency="RUB")
        try:
            payment = await _create_platega_payment_with_method(
                db_order.amount_rub,
                db_order.order_id,
                payment_method
            )
        except httpx.HTTPStatusError as exc:
            detail = "Platega error"
            if exc.response is not None:
                detail = exc.response.text
            logger.error("[PLATEGA] Create payment failed: %s", detail)
            await _notify_admin(
                f"⚠️ Platega create failed\n"
                f"order_id={db_order.order_id}\n"
                f"user_id={db_order.user_id}\n"
                f"detail={detail}"
            )
            raise HTTPException(status_code=502, detail=detail)
        except httpx.ReadTimeout:
            logger.error("[PLATEGA] Create payment timed out")
            await _notify_admin(
                f"⚠️ Platega timeout\n"
                f"order_id={db_order.order_id}\n"
                f"user_id={db_order.user_id}"
            )
            raise HTTPException(status_code=504, detail="Platega timeout")

        transaction_id = payment.get("transactionId")
        if not transaction_id:
            raise RuntimeError("Platega did not return transactionId")

        db_order.payment_invoice_id = transaction_id
        db_order.payment_url = payment.get("redirect")
        db.commit()

        return {
            "order_id": db_order.order_id,
            "status": db_order.status,
            "redirect": db_order.payment_url,
            "platega": payment
        }
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
            await _fulfill_order_if_needed(order, db)
    finally:
        db.close()

    return {"status": "ok"}


@app.post("/webhook/platega/{token}")
async def platega_webhook(
    token: str,
    request: Request,
    x_signature: str | None = Header(default=None, alias="X-Signature"),
):
    if not PLATEGA_WEBHOOK_TOKEN:
        raise HTTPException(status_code=500, detail="PLATEGA_WEBHOOK_TOKEN is not configured")
    if not _constant_time_eq(token, PLATEGA_WEBHOOK_TOKEN):
        raise HTTPException(status_code=404, detail="Not found")
    merchant_id = request.headers.get("X-MerchantId")
    secret = request.headers.get("X-Secret")
    if not merchant_id or not secret:
        raise HTTPException(status_code=400, detail="Missing X-MerchantId or X-Secret")
    if merchant_id != PLATEGA_MERCHANT_ID or not _constant_time_eq(secret, PLATEGA_SECRET or ""):
        raise HTTPException(status_code=403, detail="Invalid credentials")

    body = await request.body()
    if PLATEGA_WEBHOOK_SIGNING_SECRET:
        calc = hmac.new(PLATEGA_WEBHOOK_SIGNING_SECRET.encode(), body, hashlib.sha256).hexdigest()
        if not x_signature or not _constant_time_eq(calc, x_signature):
            raise HTTPException(status_code=403, detail="Invalid signature")
    if PLATEGA_WEBHOOK_IP_ALLOWLIST:
        ip = _client_ip(request)
        if ip not in PLATEGA_WEBHOOK_IP_ALLOWLIST:
            raise HTTPException(status_code=403, detail="IP not allowed")

    data = json.loads(body.decode("utf-8") or "{}")
    logger.info("WEBHOOK PLATEGA DATA: %s", json.dumps(data))

    transaction_id = data.get("id")
    status = (data.get("status") or "").upper()
    if not transaction_id:
        return {"status": "error", "message": "No transaction id"}

    db = SessionLocal()
    try:
        order = db.query(Order).filter(Order.payment_invoice_id == transaction_id).first()
        if not order:
            return {"status": "error", "message": "Order not found"}

        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO payment_transactions
                    (order_id, provider, provider_txn_id, status, raw_response)
                    VALUES (:order_id, :provider, :provider_txn_id, :status, :raw_response)
                    """
                ),
                {
                    "order_id": order.order_id,
                    "provider": "platega_webhook",
                    "provider_txn_id": transaction_id,
                    "status": status,
                    "raw_response": json.dumps(data),
                },
            )

        if status == "CONFIRMED" and order.status != "paid":
            order.status = "paid"
            db.commit()
            await _fulfill_order_if_needed(order, db)
        elif status in ("CANCELED", "CHARGEBACKED"):
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
            await _fulfill_order_if_needed(order, db)

        return PlainTextResponse(content=f"OK{InvId}", status_code=200)
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
        await _sync_platega_order_status(order, db)
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
            await _sync_platega_order_status(order, db)
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


@app.get("/orders/{order_id}")
async def order_status(order_id: str):
    db = SessionLocal()
    try:
        order = db.query(Order).filter(Order.order_id == order_id).first()
        if not order:
            return {"error": "Order not found"}

        await _sync_crypto_order_status(order, db)
        await _sync_platega_order_status(order, db)
        _check_order_expired(order, db)
        return {"order_id": order.order_id, "status": order.status}
    finally:
        db.close()


@app.get("/robokassa/success")
async def robokassa_success():
    return "<html><body><script>window.location.href='/'</script></body></html>"


@app.get("/robokassa/fail")
async def robokassa_fail():
    return "<html><body><script>window.location.href='/'</script></body></html>"
