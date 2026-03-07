import asyncio
import hashlib
import hmac
import json
from decimal import Decimal, ROUND_HALF_UP
import logging
import os
import secrets
import uuid
from datetime import timedelta, datetime, time
from urllib.parse import parse_qsl, unquote_plus

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Query, Header, HTTPException
from fastapi.responses import PlainTextResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, root_validator
from sqlalchemy import text
from zoneinfo import ZoneInfo

from .crypto_pay import verify_signature
from .crypto import convert_rub_to_crypto, convert_to_rub, get_usdtrub_rate
from .database import SessionLocal, Base, engine
from .models import Order, User, PromoCode, PromoRedemption, PromoReservation, ReferralEarning, PaymentTransaction, BonusGrant, BonusClaim, BonusClaimRedemption, AdminSetting
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
ADMIN_CHAT_IDS = {
    item.strip() for item in (os.getenv("ADMIN_CHAT_ID") or "").split(",") if item.strip()
}
MINI_APP_URL = os.getenv("MINI_APP_URL")
REFERRAL_PERCENT = int(os.getenv("REFERRAL_PERCENT", "5"))
BONUS_MIN_STARS = int(os.getenv("BONUS_MIN_STARS", "50"))
ADMIN_REPORT_TIME = os.getenv("ADMIN_REPORT_TIME", "00:00")
STAR_COST_USD_PER_100 = float(os.getenv("STAR_COST_USD_PER_100", "1.5"))

API_AUTH_KEY = os.getenv("API_AUTH_KEY")
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "30"))
ALLOW_UNVERIFIED_INITDATA = os.getenv("ALLOW_UNVERIFIED_INITDATA", "false").lower() in ("1", "true", "yes")
ADMIN_OTP_TTL_MIN = int(os.getenv("ADMIN_OTP_TTL_MIN", "5"))
ADMIN_OTP_SECRET = os.getenv("ADMIN_OTP_SECRET") or API_AUTH_KEY or "change-me"

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
    conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS promo_code VARCHAR"))
    conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS promo_percent INTEGER"))
    conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS promo_redeemed BOOLEAN"))
    conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS amount_rub_original FLOAT"))
    conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS bonus_stars_applied INTEGER DEFAULT 0"))
    conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS bonus_grant_id INTEGER"))
    conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_method VARCHAR"))
    conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS user_username VARCHAR"))
    conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS audit_sent BOOLEAN DEFAULT FALSE"))
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR"))
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR"))
    conn.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS admin_settings (
                key VARCHAR PRIMARY KEY,
                value VARCHAR NOT NULL,
                updated_at TIMESTAMPTZ DEFAULT now()
            )
            """
        )
    )
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
    conn.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id VARCHAR PRIMARY KEY,
                referrer_id VARCHAR,
                referral_balance_stars INTEGER DEFAULT 0,
                created_at TIMESTAMPTZ DEFAULT now()
            )
            """
        )
    )
    conn.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS bonus_grants (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR NOT NULL,
                stars INTEGER NOT NULL,
                status VARCHAR DEFAULT 'active',
                source VARCHAR,
                expires_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ DEFAULT now(),
                consumed_at TIMESTAMPTZ,
                consumed_order_id VARCHAR
            )
            """
        )
    )
    conn.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS bonus_claims (
                id SERIAL PRIMARY KEY,
                token VARCHAR UNIQUE,
                stars INTEGER NOT NULL,
                status VARCHAR DEFAULT 'active',
                source VARCHAR,
                max_uses INTEGER DEFAULT 1,
                uses INTEGER DEFAULT 0,
                expires_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ DEFAULT now(),
                claimed_user_id VARCHAR,
                claimed_at TIMESTAMPTZ
            )
            """
        )
    )
    conn.execute(text("ALTER TABLE bonus_claims ADD COLUMN IF NOT EXISTS max_uses INTEGER DEFAULT 1"))
    conn.execute(text("ALTER TABLE bonus_claims ADD COLUMN IF NOT EXISTS uses INTEGER DEFAULT 0"))
    conn.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS bonus_claim_redemptions (
                id SERIAL PRIMARY KEY,
                claim_id INTEGER NOT NULL,
                user_id VARCHAR NOT NULL,
                created_at TIMESTAMPTZ DEFAULT now()
            )
            """
        )
    )
    conn.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS promo_codes (
                code VARCHAR PRIMARY KEY,
                percent INTEGER NOT NULL,
                max_uses INTEGER,
                uses INTEGER DEFAULT 0,
                active BOOLEAN DEFAULT TRUE,
                expires_at TIMESTAMPTZ
            )
            """
        )
    )
    conn.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS promo_redemptions (
                id SERIAL PRIMARY KEY,
                code VARCHAR,
                user_id VARCHAR,
                order_id VARCHAR,
                percent INTEGER,
                created_at TIMESTAMPTZ DEFAULT now()
            )
            """
        )
    )
    conn.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS promo_reservations (
                id SERIAL PRIMARY KEY,
                code VARCHAR,
                user_id VARCHAR,
                percent INTEGER,
                order_id VARCHAR,
                expires_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ DEFAULT now()
            )
            """
        )
    )
    conn.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS referral_earnings (
                id SERIAL PRIMARY KEY,
                referrer_id VARCHAR,
                referred_user_id VARCHAR,
                order_id VARCHAR,
                stars INTEGER,
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
    promo_code: str | None = None


class RobokassaOrderCreate(OrderCreateBase):
    pass


class PlategaOrderCreate(OrderCreateBase):
    payment_method: int | None = None
    promo_code: str | None = None


def _product_label(order: Order) -> str:
    if order.product_type == "stars":
        bonus = int(order.bonus_stars_applied or 0)
        if bonus > 0:
            return f"Stars x{order.quantity} (+{bonus} bonus)"
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
    parsed = dict(parse_qsl(init_data, keep_blank_values=True))
    hash_value = parsed.pop("hash", "")
    if not hash_value:
        return False

    data_check = "\n".join(f"{k}={parsed[k]}" for k in sorted(parsed))

    def _verify_with_secret(secret_key: bytes) -> bool:
        h = hmac.new(secret_key, data_check.encode(), hashlib.sha256).hexdigest()
        return _constant_time_eq(h, hash_value)

    webapp_secret = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    if _verify_with_secret(webapp_secret):
        return True

    legacy_secret = hashlib.sha256(BOT_TOKEN.encode()).digest()
    return _verify_with_secret(legacy_secret)


def _extract_user_fields(init_data: str | None) -> tuple[str | None, str | None, str | None]:
    if not init_data:
        return None, None, None
    try:
        parsed = dict(parse_qsl(init_data, keep_blank_values=True))
        user_raw = parsed.get("user")
        if not user_raw:
            return None, None, None
        user = json.loads(unquote_plus(user_raw))
        username = (user.get("username") or "").strip() or None
        first = (user.get("first_name") or "").strip()
        last = (user.get("last_name") or "").strip()
        full = " ".join(part for part in [first, last] if part).strip() or None
        display = f"@{username}" if username else full
        return username, full, display
    except Exception:
        return None, None, None


def _touch_user_from_initdata(db, user_id: str, init_data: str | None) -> str | None:
    username, full_name, display = _extract_user_fields(init_data)
    if not username and not full_name:
        return display
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        user = User(user_id=user_id)
        db.add(user)
    if username:
        user.username = username
    if full_name:
        user.full_name = full_name
    db.commit()
    return display


def _get_setting(db, key: str, default: str) -> str:
    row = db.query(AdminSetting).filter(AdminSetting.key == key).first()
    if row and row.value is not None:
        return row.value
    return default


def _get_setting_float(db, key: str, default: float) -> float:
    raw = _get_setting(db, key, str(default))
    try:
        return float(raw)
    except ValueError:
        return default


def _get_setting_int(db, key: str, default: int) -> int:
    raw = _get_setting(db, key, str(default))
    try:
        return int(raw)
    except ValueError:
        return default


def _get_report_time(db) -> time:
    raw = _get_setting(db, "ADMIN_REPORT_TIME", ADMIN_REPORT_TIME)
    try:
        parts = raw.split(":")
        if len(parts) != 2:
            raise ValueError("invalid")
        hour = int(parts[0])
        minute = int(parts[1])
        return time(hour=hour, minute=minute)
    except Exception:
        return time(0, 0)


def _round_money(value: float | None) -> float | None:
    if value is None:
        return None
    return float(Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))

    def _verify_with_secret(secret_key: bytes) -> bool:
        parsed = dict(parse_qsl(init_data, keep_blank_values=True))
        hash_value = parsed.pop("hash", "")
        if hash_value:
            data_check = "\n".join(f"{k}={parsed[k]}" for k in sorted(parsed))
            h = hmac.new(secret_key, data_check.encode(), hashlib.sha256).hexdigest()
            if _constant_time_eq(h, hash_value):
                return True

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

    # WebApp validation (correct for initData)
    webapp_secret = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    if _verify_with_secret(webapp_secret):
        return True

    # Fallback for legacy login-widget style (safety)
    legacy_secret = hashlib.sha256(BOT_TOKEN.encode()).digest()
    return _verify_with_secret(legacy_secret)


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

_admin_otp_code: str | None = None
_admin_otp_expires_at: datetime | None = None
_admin_sessions: dict[str, datetime] = {}


@app.middleware("http")
async def auth_and_rate_limit(request: Request, call_next):
    path = request.url.path
    if path.startswith("/promo/validate"):
        return await call_next(request)
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

        logger.warning(
            "[AUTH] Unauthorized %s ip=%s init_len=%s ua=%s",
            path,
            _client_ip(request),
            len(init_data or ""),
            request.headers.get("user-agent", "")
        )
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
    if not ADMIN_CHAT_IDS:
        return
    try:
        for admin_id in ADMIN_CHAT_IDS:
            await send_admin_message(chat_id=int(admin_id), text=text)
    except Exception:
        logger.exception("[ADMIN] Failed to send admin message")


def _format_payment_method(order: Order) -> str:
    if order.payment_provider == "platega":
        if order.payment_method == "sbp":
            return "SBP"
        if order.payment_method == "card":
            return "Card"
        return "Platega"
    if order.payment_provider == "crypto":
        return "CryptoBot"
    return order.payment_provider or "unknown"


def _format_audit_line(order: Order) -> str:
    bonus = int(order.bonus_stars_applied or 0)
    qty = int(order.quantity or 0)
    total = qty + bonus
    when = order.timestamp.astimezone(MSK).strftime("%Y-%m-%d %H:%M")
    if order.user_username:
        user = f"{order.user_username} (id {order.user_id})"
    else:
        user = f"id {order.user_id}"
    pay = _format_payment_method(order)
    return (
        f"⭐ {total} ({qty}+{bonus}) | {user} | {pay} | {when}\n"
        f"order: {order.order_id}"
    )


def _format_audit_line_with_user(order: Order, display_name: str | None) -> str:
    bonus = int(order.bonus_stars_applied or 0)
    qty = int(order.quantity or 0)
    total = qty + bonus
    when = order.timestamp.astimezone(MSK).strftime("%Y-%m-%d %H:%M")
    if display_name:
        user = f"{display_name} (id {order.user_id})"
    elif order.user_username:
        user = f"{order.user_username} (id {order.user_id})"
    else:
        user = f"id {order.user_id}"
    pay = _format_payment_method(order)
    return (
        f"⭐ {total} ({qty}+{bonus}) | {user} | {pay} | {when}\n"
        f"order: {order.order_id}"
    )


def _admin_session_valid(token: str | None) -> bool:
    if not token:
        return False
    expires_at = _admin_sessions.get(token)
    if not expires_at:
        return False
    if expires_at <= now_msk():
        _admin_sessions.pop(token, None)
        return False
    return True


def _admin_set_session() -> str:
    token = secrets.token_urlsafe(24)
    _admin_sessions[token] = now_msk() + timedelta(hours=12)
    return token


async def _admin_send_otp() -> None:
    global _admin_otp_code, _admin_otp_expires_at
    _admin_otp_code = f"{secrets.randbelow(1000000):06d}"
    _admin_otp_expires_at = now_msk() + timedelta(minutes=ADMIN_OTP_TTL_MIN)
    await _notify_admin(
        "🔐 Admin login code\n"
        f"Code: {_admin_otp_code}\n"
        f"Valid: {ADMIN_OTP_TTL_MIN} min"
    )


async def _send_audit_if_needed(order: Order, db) -> None:
    if order.audit_sent:
        return
    if order.product_type != "stars" or order.status != "paid":
        return
    display = None
    if not order.user_username:
        user = db.query(User).filter(User.user_id == order.user_id).first()
        if user:
            display = f"@{user.username}" if user.username else user.full_name
    base_line = _format_audit_line_with_user(order, display)
    revenue_line = ""
    try:
        total_stars = int(order.quantity or 0) + int(order.bonus_stars_applied or 0)
        usdtrub = await get_usdtrub_rate()
        cost_usd = total_stars * (STAR_COST_USD_PER_100 / 100.0)
        cost_rub = cost_usd * usdtrub
        revenue = _round_money(order.amount_rub) or 0
        cost_rub = _round_money(cost_rub) or 0
        profit = _round_money(revenue - cost_rub) or 0
        per_star = _round_money(cost_rub / total_stars) if total_stars else 0
        revenue_line = (
            f"\n💰 Выручка: {revenue} ₽"
            f"\n📦 Себестоимость: {cost_rub} ₽"
            f"\n📊 Себестоимость/звезда: {per_star} ₽"
            f"\n📈 Прибыль: {profit} ₽"
            f"\n💱 Курс USDTRUB: {_round_money(usdtrub)} ₽"
        )
    except Exception:
        logger.exception("[AUDIT] Failed to compute revenue")
    text = "✅ Покупка звёзд\n" + base_line + revenue_line
    await _notify_admin(text)
    order.audit_sent = True
    db.commit()


async def _send_daily_report() -> None:
    if not ADMIN_CHAT_IDS:
        return
    from .admin_reports import build_admin_report
    text = await build_admin_report()
    await _notify_admin(text)


async def _daily_report_loop() -> None:
    while True:
        now = now_msk()
        db = SessionLocal()
        try:
            report_time = _get_report_time(db)
        finally:
            db.close()
        target = datetime.combine(now.date(), report_time, tzinfo=MSK)
        if target <= now:
            target = target + timedelta(days=1)
        sleep_seconds = (target - now).total_seconds()
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
    if ADMIN_CHAT_IDS:
        dp = build_admin_dispatcher(ADMIN_CHAT_IDS)
        asyncio.create_task(dp.start_polling(bot))


async def _fulfill_order_if_needed(order: Order, db) -> None:
    if order.product_type != "stars":
        return
    if (order.fragment_status or "").lower() == "success":
        return

    if (order.bonus_stars_applied or 0) == 0 and (order.quantity or 0) >= BONUS_MIN_STARS:
        _reserve_bonus_for_order(order, db)

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
        _release_bonus_reservation(order, db)
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
    order.fragment_in_progress = False
    db.commit()
    _consume_bonus(order, db)
    await _send_audit_if_needed(order, db)

    if order.promo_code and not order.promo_redeemed:
        promo = _load_promo(order.promo_code, db)
        if promo:
            promo.uses = (promo.uses or 0) + 1
            redemption = PromoRedemption(
                code=promo.code,
                user_id=order.user_id,
                order_id=order.order_id,
                percent=promo.percent
            )
            order.promo_redeemed = True
            db.add(redemption)
            db.query(PromoReservation).filter(
                PromoReservation.code == promo.code,
                PromoReservation.user_id == order.user_id
            ).delete()
            db.commit()

    user = db.query(User).filter(User.user_id == order.user_id).first()
    if user and user.referrer_id and order.quantity:
        percent = _get_setting_int(db, "REFERRAL_PERCENT", REFERRAL_PERCENT)
        bonus = int(order.quantity * percent / 100)
        if bonus > 0:
            user.referral_balance_stars = (user.referral_balance_stars or 0) + bonus
            earning = ReferralEarning(
                referrer_id=user.referrer_id,
                referred_user_id=order.user_id,
                order_id=order.order_id,
                stars=bonus
            )
            db.add(earning)
            db.commit()


def _extract_order_id(data: dict) -> str | None:
    if isinstance(data.get("payload"), str):
        return data.get("payload")
    if isinstance(data.get("payload"), dict):
        return data.get("payload", {}).get("payload") or data.get("payload", {}).get("order_id")
    return data.get("order_id")


def _stars_base_price(quantity: int) -> float:
    db = SessionLocal()
    try:
        rate_1 = _get_setting_float(db, "STARS_RATE_1", 1.39)
        rate_2 = _get_setting_float(db, "STARS_RATE_2", 1.37)
        rate_3 = _get_setting_float(db, "STARS_RATE_3", 1.35)
    finally:
        db.close()
    if quantity <= 1000:
        return quantity * rate_1
    if quantity <= 5000:
        return quantity * rate_2
    return quantity * rate_3


def _load_promo(code: str, db) -> PromoCode | None:
    promo = db.query(PromoCode).filter(PromoCode.code == code.upper()).first()
    if not promo:
        return None
    if not promo.active:
        return None
    if promo.expires_at and promo.expires_at < now_msk():
        return None
    if promo.max_uses is not None and promo.uses >= promo.max_uses:
        return None
    return promo


def _get_active_reservation(code: str, user_id: str, db) -> PromoReservation | None:
    now = now_msk()
    return db.query(PromoReservation).filter(
        PromoReservation.code == code.upper(),
        PromoReservation.user_id == user_id,
        PromoReservation.expires_at > now
    ).first()


def _promo_used_by_user(code: str, user_id: str, db) -> bool:
    return db.query(PromoRedemption).filter(
        PromoRedemption.code == code.upper(),
        PromoRedemption.user_id == user_id
    ).first() is not None


def _bonus_summary(db, user_id: str) -> dict:
    now = now_msk()
    bonuses = db.query(BonusGrant).filter(
        BonusGrant.user_id == user_id,
        BonusGrant.status.in_(["active", "reserved"]),
        (BonusGrant.expires_at.is_(None) | (BonusGrant.expires_at > now))
    ).order_by(BonusGrant.expires_at.asc().nullsfirst(), BonusGrant.id.asc()).all()
    total = sum((b.stars or 0) for b in bonuses)
    expires_at = bonuses[0].expires_at.isoformat() if bonuses and bonuses[0].expires_at else None
    return {"bonus_stars": total, "bonus_expires_at": expires_at}


def _reserve_promo(code: str, user_id: str, db) -> PromoReservation | None:
    promo = _load_promo(code, db)
    if not promo:
        return None
    if _promo_used_by_user(code, user_id, db):
        return None

    existing = _get_active_reservation(code, user_id, db)
    if existing:
        return existing

    # enforce max uses against redemptions + active reservations
    if promo.max_uses is not None:
        redemptions = db.query(PromoRedemption).filter(PromoRedemption.code == promo.code).count()
        reservations = db.query(PromoReservation).filter(
            PromoReservation.code == promo.code,
            PromoReservation.expires_at > now_msk()
        ).count()
        if redemptions + reservations >= promo.max_uses:
            return None

    expires_at = now_msk() + timedelta(minutes=15)
    reservation = PromoReservation(
        code=promo.code,
        user_id=user_id,
        percent=promo.percent,
        expires_at=expires_at
    )
    db.add(reservation)
    db.commit()
    db.refresh(reservation)
    return reservation


def _release_promo_reservation(order: Order, db) -> None:
    if not order.promo_code:
        return
    db.query(PromoReservation).filter(
        PromoReservation.code == order.promo_code,
        PromoReservation.user_id == order.user_id,
        PromoReservation.order_id == order.order_id
    ).delete()
    db.commit()


def _get_reservable_bonuses(db, user_id: str) -> list[BonusGrant]:
    now = now_msk()
    return db.query(BonusGrant).filter(
        BonusGrant.user_id == user_id,
        BonusGrant.status.in_(["active", "reserved"]),
        (BonusGrant.expires_at.is_(None) | (BonusGrant.expires_at > now))
    ).order_by(BonusGrant.expires_at.asc().nullsfirst(), BonusGrant.id.asc()).all()


def _reserve_bonus_for_order(order: Order, db) -> None:
    if order.product_type != "stars" or not order.quantity:
        return
    if order.quantity < BONUS_MIN_STARS:
        return
    if order.bonus_stars_applied and order.bonus_stars_applied > 0:
        return

    grants = _get_reservable_bonuses(db, order.user_id)
    if not grants:
        return

    total_bonus = 0
    for grant in grants:
        if grant.consumed_order_id and grant.consumed_order_id != order.order_id:
            db.query(Order).filter(Order.order_id == grant.consumed_order_id).update({
                "bonus_stars_applied": 0,
                "bonus_grant_id": None
            })
        grant.status = "reserved"
        grant.consumed_order_id = order.order_id
        total_bonus += int(grant.stars or 0)
    order.bonus_grant_id = None
    order.bonus_stars_applied = total_bonus
    db.commit()


def _release_bonus_reservation(order: Order, db) -> None:
    grants = db.query(BonusGrant).filter(
        BonusGrant.consumed_order_id == order.order_id
    ).all()
    if order.bonus_grant_id and not any(g.id == order.bonus_grant_id for g in grants):
        extra = db.query(BonusGrant).filter(BonusGrant.id == order.bonus_grant_id).first()
        if extra:
            grants.append(extra)
    if not grants:
        return
    now = now_msk()
    for grant in grants:
        if grant.status == "consumed":
            continue
        if grant.expires_at and grant.expires_at <= now:
            grant.status = "expired"
        else:
            grant.status = "active"
        if grant.consumed_order_id == order.order_id:
            grant.consumed_order_id = None
    order.bonus_stars_applied = 0
    order.bonus_grant_id = None
    db.commit()


def _consume_bonus(order: Order, db) -> None:
    grants = db.query(BonusGrant).filter(
        BonusGrant.consumed_order_id == order.order_id
    ).all()
    if order.bonus_grant_id and not any(g.id == order.bonus_grant_id for g in grants):
        extra = db.query(BonusGrant).filter(BonusGrant.id == order.bonus_grant_id).first()
        if extra:
            grants.append(extra)
    if not grants:
        return
    for grant in grants:
        if grant.status == "consumed":
            continue
        grant.status = "consumed"
        grant.consumed_at = now_msk()
        grant.consumed_order_id = order.order_id
    db.commit()


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
        _release_promo_reservation(order, db)
        _release_bonus_reservation(order, db)


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
        _release_promo_reservation(order, db)
        _release_bonus_reservation(order, db)

def _create_order(
    db,
    order_in: OrderCreateBase,
    provider: str,
    currency: str | None = None,
    payment_method: str | None = None,
    user_username: str | None = None,
) -> Order:
    order_id = str(uuid.uuid4())

    db_order = Order(
        order_id=order_id,
        user_id=order_in.user_id,
        user_username=user_username,
        recipient=order_in.recipient if order_in.recipient != "@unknown" else "self",
        product_type=order_in.product_type,
        quantity=order_in.quantity,
        months=order_in.months,
        amount=order_in.amount,
        amount_rub=order_in.amount_rub,
        amount_rub_original=order_in.amount_rub,
        currency=currency or "RUB",
        status="created",
        payment_provider=provider,
        payment_method=payment_method,
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
        _release_promo_reservation(order, db)
        _release_bonus_reservation(order, db)
    return order


@app.post("/orders/crypto")
async def create_order_crypto(order: CryptoOrderCreate, request: Request):
    if order.product_type != "stars":
        raise HTTPException(status_code=400, detail="Only Stars are supported right now")
    db = SessionLocal()
    try:
        amount_rub = _stars_base_price(order.quantity or 0)
        promo_percent = 0
        if order.promo_code:
            reservation = _get_active_reservation(order.promo_code, order.user_id, db)
            if not reservation:
                raise HTTPException(status_code=400, detail="Invalid or expired promo")
            promo_percent = reservation.percent
            amount_rub = amount_rub * (1 - promo_percent / 100)
        order.amount_rub = _round_money(amount_rub) or amount_rub
        amount_crypto = await convert_rub_to_crypto(amount_rub, order.currency)

        init_data = request.headers.get("x-telegram-init-data")
        user_username = _touch_user_from_initdata(db, order.user_id, init_data)
        db_order = _create_order(
            db,
            order,
            provider="crypto",
            currency=order.currency,
            payment_method="cryptobot",
            user_username=user_username,
        )
        if order.promo_code and promo_percent:
            db_order.promo_code = order.promo_code.upper()
            db_order.promo_percent = promo_percent
            db_order.amount_rub_original = _stars_base_price(order.quantity or 0)
            db_order.amount_rub = _round_money(amount_rub) or amount_rub
            db.query(PromoReservation).filter(
                PromoReservation.code == db_order.promo_code,
                PromoReservation.user_id == db_order.user_id
            ).update({"order_id": db_order.order_id})
            db.commit()

        _reserve_bonus_for_order(db_order, db)

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
            "amount_rub": _round_money(db_order.amount_rub),
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
async def create_order_platega(order: PlategaOrderCreate, request: Request):
    if order.product_type != "stars":
        raise HTTPException(status_code=400, detail="Only Stars are supported right now")

    payment_method = order.payment_method or PLATEGA_PAYMENT_METHOD
    if payment_method not in (2, 11):
        raise HTTPException(status_code=400, detail="Unsupported payment method")

    db = SessionLocal()
    try:
        amount_rub = _stars_base_price(order.quantity or 0)
        promo_percent = 0
        if order.promo_code:
            reservation = _get_active_reservation(order.promo_code, order.user_id, db)
            if not reservation:
                raise HTTPException(status_code=400, detail="Invalid or expired promo")
            promo_percent = reservation.percent
            amount_rub = amount_rub * (1 - promo_percent / 100)
        order.amount_rub = _round_money(amount_rub) or amount_rub

        init_data = request.headers.get("x-telegram-init-data")
        user_username = _touch_user_from_initdata(db, order.user_id, init_data)
        payment_method_label = "sbp" if payment_method == 2 else "card"
        db_order = _create_order(
            db,
            order,
            provider="platega",
            currency="RUB",
            payment_method=payment_method_label,
            user_username=user_username,
        )
        if order.promo_code and promo_percent:
            db_order.promo_code = order.promo_code.upper()
            db_order.promo_percent = promo_percent
            db_order.amount_rub_original = _stars_base_price(order.quantity or 0)
            db_order.amount_rub = _round_money(amount_rub) or amount_rub
            db.query(PromoReservation).filter(
                PromoReservation.code == db_order.promo_code,
                PromoReservation.user_id == db_order.user_id
            ).update({"order_id": db_order.order_id})
            db.commit()
        _reserve_bonus_for_order(db_order, db)
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
            # one retry for transient errors
            try:
                payment = await _create_platega_payment_with_method(
                    db_order.amount_rub,
                    db_order.order_id,
                    payment_method
                )
            except Exception:
                raise HTTPException(status_code=502, detail=detail) from exc
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
        elif status in ("expired", "failed"):
            order.status = "failed"
            db.commit()
            _release_promo_reservation(order, db)
            _release_bonus_reservation(order, db)
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
            _release_bonus_reservation(order, db)
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
            "bonus_stars_applied": order.bonus_stars_applied,
            "amount_rub": _round_money(order.amount_rub),
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
                    "amount_rub": _round_money(o.amount_rub),
                    "currency": o.currency,
                    "status": o.status,
                    "bonus_stars_applied": o.bonus_stars_applied,
                    "timestamp": o.timestamp.astimezone(MSK).isoformat()
                }
                for o in orders
            ]
        }
    finally:
        db.close()


def _admin_panel_html(authed: bool) -> str:
    if not authed:
        return """
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Admin Login</title>
  <style>
    body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;background:#0e0f12;color:#e9eef7;margin:0;padding:24px}
    .wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .card{width:100%;max-width:420px;background:#15181d;border:1px solid #1f232b;border-radius:16px;padding:20px}
    .btn{display:block;width:100%;padding:12px 14px;border-radius:10px;border:0;background:#2a8bf2;color:#fff;font-weight:700;margin-top:10px;cursor:pointer}
    .input{width:100%;padding:12px;border-radius:10px;border:1px solid #2a2f38;background:#0e1116;color:#e9eef7}
    .muted{color:#8b93a7;font-size:12px;margin-top:8px}
  </style>
</head>
<body>
  <div class="wrap">
  <div class="card">
    <h2>Admin Access</h2>
    <div class="muted">Request one-time code in Telegram, then enter it here.</div>
    <button class="btn" onclick="requestCode()">Send code</button>
    <div style="height:12px"></div>
    <input class="input" id="code" placeholder="6-digit code" />
    <button class="btn" onclick="verifyCode()">Verify</button>
    <div id="status" class="muted"></div>
  </div>
  </div>
  <script>
    async function requestCode(){
      const res = await fetch('/admin/otp/request', {method:'POST', credentials:'include'});
      document.getElementById('status').textContent = res.ok ? 'Code sent' : 'Failed to send';
    }
    async function verifyCode(){
      const code = document.getElementById('code').value.trim();
      if(!code) return;
      const res = await fetch('/admin/otp/verify', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({code}),
        credentials:'include'
      });
      if(res.ok){ location.reload(); return; }
      document.getElementById('status').textContent = 'Invalid code';
    }
  </script>
</body>
</html>
"""

    return """
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Admin Audit</title>
  <style>
    body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;background:#0e0f12;color:#e9eef7;margin:0;padding:24px}
    h1{margin:0 0 16px 0}
    .grid{display:grid;grid-template-columns:1fr;gap:14px}
    .card{background:#15181d;border:1px solid #1f232b;border-radius:16px;padding:16px}
    pre{white-space:pre-wrap;word-break:break-word;color:#c9d1e4;font-size:13px}
    .muted{color:#8b93a7;font-size:12px}
    .btn{display:inline-flex;gap:8px;align-items:center;padding:8px 12px;border-radius:10px;border:1px solid #2a2f38;background:#101318;color:#e9eef7;cursor:pointer}
    .field{display:flex;flex-direction:column;gap:6px;margin-top:10px}
    .input{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #2a2f38;background:#0e1116;color:#e9eef7}
    .row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
  </style>
</head>
<body>
  <h1>Audit</h1>
  <div class="grid">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <strong>Last 24h</strong>
        <button class="btn" onclick="loadToday()">Refresh</button>
      </div>
      <pre id="today">Loading...</pre>
    </div>
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <strong>Recent</strong>
        <button class="btn" onclick="loadRecent()">Refresh</button>
      </div>
      <pre id="recent">Loading...</pre>
      <div class="muted">Latest 200 paid stars orders.</div>
    </div>
    <div class="card">
      <strong>Settings</strong>
      <div class="row">
        <div class="field">
          <label class="muted">Report time (HH:MM)</label>
          <input class="input" id="report_time" placeholder="00:00"/>
        </div>
        <div class="field">
          <label class="muted">Referral %</label>
          <input class="input" id="ref_percent" type="number" min="0" max="100"/>
        </div>
      </div>
      <div class="row">
        <div class="field">
          <label class="muted">Rate tier 1 (<=1000)</label>
          <input class="input" id="rate1" type="number" step="0.01"/>
        </div>
        <div class="field">
          <label class="muted">Rate tier 2 (<=5000)</label>
          <input class="input" id="rate2" type="number" step="0.01"/>
        </div>
      </div>
      <div class="field">
        <label class="muted">Rate tier 3 (>5000)</label>
        <input class="input" id="rate3" type="number" step="0.01"/>
      </div>
      <button class="btn" onclick="saveSettings()" style="margin-top:10px">Save settings</button>
      <div id="settings-status" class="muted"></div>
    </div>
    <div class="card">
      <strong>Create Promo</strong>
      <div class="row">
        <div class="field">
          <label class="muted">Code</label>
          <input class="input" id="promo_code" placeholder="PROMO2026"/>
        </div>
        <div class="field">
          <label class="muted">Percent</label>
          <input class="input" id="promo_percent" type="number" min="1" max="100"/>
        </div>
      </div>
      <div class="row">
        <div class="field">
          <label class="muted">Max uses</label>
          <input class="input" id="promo_max" type="number" min="1"/>
        </div>
        <div class="field">
          <label class="muted">Expires (YYYY-MM-DD)</label>
          <input class="input" id="promo_exp" placeholder="2026-12-31"/>
        </div>
      </div>
      <button class="btn" onclick="createPromo()" style="margin-top:10px">Create promo</button>
      <div id="promo-status" class="muted"></div>
    </div>
    <div class="card">
      <strong>Create Bonus Link</strong>
      <div class="row">
        <div class="field">
          <label class="muted">Stars</label>
          <input class="input" id="bonus_stars" type="number" min="1"/>
        </div>
        <div class="field">
          <label class="muted">TTL (minutes)</label>
          <input class="input" id="bonus_ttl" type="number" min="1"/>
        </div>
      </div>
      <div class="row">
        <div class="field">
          <label class="muted">Max uses</label>
          <input class="input" id="bonus_max" type="number" min="1"/>
        </div>
        <div class="field">
          <label class="muted">Source</label>
          <input class="input" id="bonus_source" placeholder="promo_tg"/>
        </div>
      </div>
      <button class="btn" onclick="createBonus()" style="margin-top:10px">Create bonus link</button>
      <div id="bonus-status" class="muted"></div>
    </div>
  </div>
  <script>
    async function loadToday(){
      const res = await fetch('/admin/audit/today', {credentials:'include'});
      const data = await res.json();
      document.getElementById('today').textContent = (data.items || []).join('\\n') || 'No data';
    }
    async function loadRecent(){
      const res = await fetch('/admin/audit/recent', {credentials:'include'});
      const data = await res.json();
      document.getElementById('recent').textContent = (data.items || []).join('\\n') || 'No data';
    }
    async function loadSettings(){
      const res = await fetch('/admin/settings', {credentials:'include'});
      if(!res.ok) return;
      const data = await res.json();
      document.getElementById('report_time').value = data.report_time || '';
      document.getElementById('ref_percent').value = data.referral_percent ?? '';
      document.getElementById('rate1').value = data.stars_rate_1 ?? '';
      document.getElementById('rate2').value = data.stars_rate_2 ?? '';
      document.getElementById('rate3').value = data.stars_rate_3 ?? '';
    }
    async function saveSettings(){
      const payload = {
        report_time: document.getElementById('report_time').value.trim() || null,
        referral_percent: Number(document.getElementById('ref_percent').value || 0) || null,
        stars_rate_1: Number(document.getElementById('rate1').value || 0) || null,
        stars_rate_2: Number(document.getElementById('rate2').value || 0) || null,
        stars_rate_3: Number(document.getElementById('rate3').value || 0) || null,
      };
      const res = await fetch('/admin/settings', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(payload),
        credentials:'include'
      });
      document.getElementById('settings-status').textContent = res.ok ? 'Saved' : 'Save failed';
    }
    async function createPromo(){
      const payload = {
        code: document.getElementById('promo_code').value.trim(),
        percent: Number(document.getElementById('promo_percent').value || 0),
        max_uses: Number(document.getElementById('promo_max').value || 0) || null,
        expires_at: document.getElementById('promo_exp').value.trim() || null,
        active: true
      };
      const res = await fetch('/admin/promo/create', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(payload),
        credentials:'include'
      });
      const data = await res.json().catch(() => ({}));
      document.getElementById('promo-status').textContent = res.ok ? `OK: ${data.code || payload.code}` : 'Failed';
    }
    async function createBonus(){
      const payload = {
        stars: Number(document.getElementById('bonus_stars').value || 0),
        ttl_minutes: Number(document.getElementById('bonus_ttl').value || 0) || null,
        max_uses: Number(document.getElementById('bonus_max').value || 0) || null,
        source: document.getElementById('bonus_source').value.trim() || null,
      };
      const res = await fetch('/admin/bonus/claim', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(payload),
        credentials:'include'
      });
      const data = await res.json().catch(() => ({}));
      document.getElementById('bonus-status').textContent = res.ok
        ? `Link: ${data.link || ''}`
        : 'Failed';
    }
    loadToday();
    loadRecent();
    loadSettings();
  </script>
</body>
</html>
"""


@app.get("/admin/panel", response_class=HTMLResponse)
async def admin_panel(request: Request):
    token = request.cookies.get("admin_otp")
    authed = _admin_session_valid(token)
    return _admin_panel_html(authed)


@app.post("/admin/otp/request")
async def admin_otp_request():
    if not ADMIN_CHAT_IDS:
        raise HTTPException(status_code=403, detail="Admins not configured")
    if _admin_otp_expires_at and _admin_otp_expires_at > now_msk():
        raise HTTPException(status_code=429, detail="OTP already sent")
    await _admin_send_otp()
    return {"status": "ok"}


class AdminOtpVerify(BaseModel):
    code: str


@app.post("/admin/otp/verify")
async def admin_otp_verify(payload: AdminOtpVerify):
    if not _admin_otp_code or not _admin_otp_expires_at:
        raise HTTPException(status_code=400, detail="OTP not requested")
    if _admin_otp_expires_at <= now_msk():
        raise HTTPException(status_code=400, detail="OTP expired")
    if payload.code.strip() != _admin_otp_code:
        raise HTTPException(status_code=400, detail="Invalid code")

    session_token = _admin_set_session()
    response = JSONResponse({"status": "ok"})
    response.set_cookie(
        "admin_otp",
        session_token,
        httponly=True,
        secure=True,
        samesite="Lax",
        max_age=12 * 60 * 60,
    )
    return response


def _admin_require(request: Request) -> None:
    token = request.cookies.get("admin_otp")
    if not _admin_session_valid(token):
        raise HTTPException(status_code=401, detail="Admin OTP required")


class AdminSettingsPayload(BaseModel):
    referral_percent: int | None = None
    report_time: str | None = None
    stars_rate_1: float | None = None
    stars_rate_2: float | None = None
    stars_rate_3: float | None = None


@app.get("/admin/settings")
async def admin_settings(request: Request):
    _admin_require(request)
    db = SessionLocal()
    try:
        return {
            "referral_percent": _get_setting_int(db, "REFERRAL_PERCENT", REFERRAL_PERCENT),
            "report_time": _get_setting(db, "ADMIN_REPORT_TIME", ADMIN_REPORT_TIME),
            "stars_rate_1": _get_setting_float(db, "STARS_RATE_1", 1.39),
            "stars_rate_2": _get_setting_float(db, "STARS_RATE_2", 1.37),
            "stars_rate_3": _get_setting_float(db, "STARS_RATE_3", 1.35),
        }
    finally:
        db.close()


@app.post("/admin/settings")
async def admin_settings_update(request: Request, payload: AdminSettingsPayload):
    _admin_require(request)
    db = SessionLocal()
    try:
        updates = {
            "REFERRAL_PERCENT": payload.referral_percent,
            "ADMIN_REPORT_TIME": payload.report_time,
            "STARS_RATE_1": payload.stars_rate_1,
            "STARS_RATE_2": payload.stars_rate_2,
            "STARS_RATE_3": payload.stars_rate_3,
        }
        for key, value in updates.items():
            if value is None:
                continue
            row = db.query(AdminSetting).filter(AdminSetting.key == key).first()
            if not row:
                row = AdminSetting(key=key, value=str(value))
                db.add(row)
            else:
                row.value = str(value)
                row.updated_at = now_msk()
        db.commit()
        return {"status": "ok"}
    finally:
        db.close()


class AdminPromoPayload(BaseModel):
    code: str
    percent: int
    max_uses: int | None = None
    active: bool = True
    expires_at: str | None = None


@app.post("/admin/promo/create")
async def admin_promo_create(request: Request, payload: AdminPromoPayload):
    _admin_require(request)
    db = SessionLocal()
    try:
        code = payload.code.strip().upper()
        expires_at = None
        if payload.expires_at:
            expires_at = datetime.strptime(payload.expires_at, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59, tzinfo=MSK
            )
        promo = db.query(PromoCode).filter(PromoCode.code == code).first()
        if not promo:
            promo = PromoCode(
                code=code,
                percent=payload.percent,
                max_uses=payload.max_uses,
                active=payload.active,
                expires_at=expires_at
            )
            db.add(promo)
        else:
            promo.percent = payload.percent
            promo.max_uses = payload.max_uses
            promo.active = payload.active
            promo.expires_at = expires_at
        db.commit()
        return {"status": "ok", "code": code}
    finally:
        db.close()


class AdminBonusClaimPayload(BaseModel):
    stars: int
    ttl_minutes: int | None = None
    max_uses: int | None = None
    source: str | None = None


@app.post("/admin/bonus/claim")
async def admin_bonus_claim(request: Request, payload: AdminBonusClaimPayload):
    _admin_require(request)
    token = secrets.token_hex(12)
    expires_at = None
    if payload.ttl_minutes:
        expires_at = now_msk() + timedelta(minutes=payload.ttl_minutes)
    db = SessionLocal()
    try:
        claim = BonusClaim(
            token=token,
            stars=payload.stars,
            status="active",
            source=payload.source or "admin_panel",
            max_uses=payload.max_uses or 1,
            uses=0,
            expires_at=expires_at
        )
        db.add(claim)
        db.commit()
        return {
            "status": "ok",
            "token": token,
            "link": f"https://t.me/more_stars_bot?start=bonus_{token}",
            "expires_at": expires_at.isoformat() if expires_at else None
        }
    finally:
        db.close()


@app.get("/settings/public")
async def public_settings():
    db = SessionLocal()
    try:
        return {
            "stars_rate_1": _get_setting_float(db, "STARS_RATE_1", 1.39),
            "stars_rate_2": _get_setting_float(db, "STARS_RATE_2", 1.37),
            "stars_rate_3": _get_setting_float(db, "STARS_RATE_3", 1.35),
            "tier_1_max": 1000,
            "tier_2_max": 5000,
        }
    finally:
        db.close()


@app.get("/admin/audit/today")
async def admin_audit_today(request: Request):
    _admin_require(request)
    now = now_msk()
    since = now - timedelta(hours=24)
    db = SessionLocal()
    try:
        orders = (
            db.query(Order)
            .filter(
                Order.product_type == "stars",
                Order.status == "paid",
                Order.timestamp >= since
            )
            .order_by(Order.timestamp.desc())
            .limit(200)
            .all()
        )
        user_ids = list({o.user_id for o in orders})
        users = db.query(User).filter(User.user_id.in_(user_ids)).all() if user_ids else []
        user_map = {}
        for u in users:
            if u.username:
                user_map[u.user_id] = f"@{u.username}"
            elif u.full_name:
                user_map[u.user_id] = u.full_name
    finally:
        db.close()
    items = [_format_audit_line_with_user(o, user_map.get(o.user_id)) for o in orders]
    return {"items": items}


@app.get("/admin/audit/recent")
async def admin_audit_recent(request: Request, limit: int = 200):
    _admin_require(request)
    db = SessionLocal()
    try:
        orders = (
            db.query(Order)
            .filter(
                Order.product_type == "stars",
                Order.status == "paid",
            )
            .order_by(Order.timestamp.desc())
            .limit(min(limit, 500))
            .all()
        )
        user_ids = list({o.user_id for o in orders})
        users = db.query(User).filter(User.user_id.in_(user_ids)).all() if user_ids else []
        user_map = {}
        for u in users:
            if u.username:
                user_map[u.user_id] = f"@{u.username}"
            elif u.full_name:
                user_map[u.user_id] = u.full_name
    finally:
        db.close()
    items = [_format_audit_line_with_user(o, user_map.get(o.user_id)) for o in orders]
    return {"items": items}


@app.get("/promo/validate")
async def promo_validate(code: str = Query(...)):
    db = SessionLocal()
    try:
        promo = _load_promo(code, db)
        if not promo:
            return {"valid": False}
        return {"valid": True, "percent": promo.percent}
    finally:
        db.close()


@app.post("/promo/apply")
async def promo_apply(code: str = Query(...), user_id: str = Query(...)):
    db = SessionLocal()
    try:
        reservation = _reserve_promo(code, user_id, db)
        if not reservation:
            return {"valid": False}
        return {"valid": True, "percent": reservation.percent, "expires_at": reservation.expires_at.isoformat()}
    finally:
        db.close()


@app.post("/ref/attach")
async def ref_attach(user_id: str = Query(...), referrer_id: str = Query(...)):
    if user_id == referrer_id:
        return {"status": "ok"}
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user:
            user = User(user_id=user_id, referrer_id=referrer_id)
            db.add(user)
            db.commit()
            return {"status": "ok"}
        if not user.referrer_id:
            user.referrer_id = referrer_id
            db.commit()
        return {"status": "ok"}
    finally:
        db.close()


@app.post("/admin/bonus/grant")
async def admin_bonus_grant(
    user_id: str = Query(...),
    stars: int = Query(...),
    source: str | None = Query(default=None),
    expires_at: str | None = Query(default=None),
    ttl_minutes: int | None = Query(default=None),
    api_key: str | None = Query(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    if not API_AUTH_KEY:
        raise HTTPException(status_code=500, detail="API_AUTH_KEY is not configured")
    if not _constant_time_eq(API_AUTH_KEY, api_key or x_api_key or ""):
        raise HTTPException(status_code=403, detail="Forbidden")
    if stars <= 0:
        raise HTTPException(status_code=400, detail="Stars must be positive")

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user:
            user = User(user_id=user_id)
            db.add(user)
            db.commit()
            db.refresh(user)

        existing = db.query(BonusGrant).filter(
            BonusGrant.user_id == user_id,
            BonusGrant.status.in_(["active", "reserved"])
        ).first()
        if existing:
            raise HTTPException(status_code=409, detail="User already has active bonus")

        expires_dt = None
        if ttl_minutes:
            expires_dt = now_msk() + timedelta(minutes=ttl_minutes)
        elif expires_at:
            try:
                expires_dt = datetime.fromisoformat(expires_at)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="Invalid expires_at format") from exc

        grant = BonusGrant(
            user_id=user_id,
            stars=stars,
            status="active",
            source=source,
            expires_at=expires_dt
        )
        db.add(grant)
        db.commit()
        db.refresh(grant)
        return {"status": "ok", "bonus_id": grant.id, "expires_at": grant.expires_at}
    finally:
        db.close()


@app.get("/profile/summary")
async def profile_summary(user_id: str = Query(...), request: Request = None):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user:
            user = User(user_id=user_id)
            db.add(user)
            db.commit()
            db.refresh(user)
        init_data = request.headers.get("x-telegram-init-data") if request else None
        if init_data:
            _touch_user_from_initdata(db, user_id, init_data)
        bonus = _bonus_summary(db, user_id)
        return {
            "referral_balance_stars": user.referral_balance_stars or 0,
            "referrer_id": user.referrer_id,
            "bonus_balance_stars": bonus["bonus_stars"],
            "bonus_expires_at": bonus["bonus_expires_at"]
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
        return {
            "order_id": order.order_id,
            "status": order.status,
            "product_type": order.product_type,
            "quantity": order.quantity,
            "months": order.months,
            "amount": order.amount,
            "bonus_stars_applied": order.bonus_stars_applied
        }
    finally:
        db.close()


@app.get("/robokassa/success")
async def robokassa_success():
    return "<html><body><script>window.location.href='/'</script></body></html>"


@app.get("/robokassa/fail")
async def robokassa_fail():
    return "<html><body><script>window.location.href='/'</script></body></html>"
