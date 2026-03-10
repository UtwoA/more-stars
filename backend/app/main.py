import asyncio
import hashlib
import hmac
import json
import random
from decimal import Decimal, ROUND_HALF_UP
import logging
import os
import secrets
import uuid
from datetime import timedelta, datetime, time, timezone
from urllib.parse import parse_qsl, unquote_plus

import httpx
import re
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Query, Header, HTTPException
from fastapi.responses import PlainTextResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, root_validator
from sqlalchemy import text, and_, or_, func, desc
from zoneinfo import ZoneInfo

from .crypto_pay import verify_signature
from .crypto import convert_rub_to_crypto, convert_to_rub, get_usdtrub_rate, get_moex_usdrub_rate
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
REFERRAL_PERCENT = int(os.getenv("REFERRAL_PERCENT", "7"))
BONUS_MIN_STARS = int(os.getenv("BONUS_MIN_STARS", "50"))
ADMIN_REPORT_TIME = os.getenv("ADMIN_REPORT_TIME", "00:00")
STAR_COST_USD_PER_100 = float(os.getenv("STAR_COST_USD_PER_100", "1.5"))
STAR_COST_RATE_SOURCE = os.getenv("STAR_COST_RATE_SOURCE", "moex").lower()
TONCENTER_API_KEY = os.getenv("TONCENTER_API_KEY")
TONCENTER_BASE_URL = os.getenv("TONCENTER_BASE_URL") or "https://toncenter.com"
TONCONNECT_WALLET_ADDRESS = os.getenv("TONCONNECT_WALLET_ADDRESS")

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
    conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_amount FLOAT"))
    conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_amount_nano VARCHAR"))
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
            CREATE TABLE IF NOT EXISTS app_events (
                id SERIAL PRIMARY KEY,
                event_type VARCHAR NOT NULL,
                user_id VARCHAR,
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


class TonConnectOrderCreate(OrderCreateBase):
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


def _extract_user_id(init_data: str | None) -> str | None:
    if not init_data:
        return None
    try:
        parsed = dict(parse_qsl(init_data, keep_blank_values=True))
        user_raw = parsed.get("user")
        if not user_raw:
            return None
        user = json.loads(unquote_plus(user_raw))
        uid = user.get("id")
        return str(uid) if uid is not None else None
    except Exception:
        return None


def _extract_referrer_id(init_data: str | None) -> str | None:
    if not init_data:
        return None
    try:
        parsed = dict(parse_qsl(init_data, keep_blank_values=True))
        start_param = (parsed.get("start_param") or "").strip()
        if not start_param:
            return None
        if start_param.startswith("ref_"):
            start_param = start_param.replace("ref_", "", 1)
        if start_param.isdigit():
            return start_param
    except Exception:
        return None
    return None


def _touch_user_from_initdata(db, user_id: str, init_data: str | None) -> str | None:
    username, full_name, display = _extract_user_fields(init_data)
    referrer_id = _extract_referrer_id(init_data)
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
    if referrer_id and referrer_id != user_id and not user.referrer_id:
        user.referrer_id = referrer_id
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


def _parse_og_meta(html: str) -> dict:
    def _find(prop: str) -> str | None:
        pattern = re.compile(rf'<meta[^>]+property=["\']{prop}["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
        match = pattern.search(html)
        return match.group(1).strip() if match else None
    return {
        "title": _find("og:title"),
        "image": _find("og:image"),
        "description": _find("og:description"),
    }


def _next_draw_dates(now: datetime) -> list[datetime]:
    year = now.year
    month = now.month
    day = now.day

    def _safe_date(y: int, m: int, d: int) -> datetime:
        return datetime(y, m, d, 0, 0, 0, tzinfo=now.tzinfo)

    if day <= 15:
        return [_safe_date(year, month, 15), _safe_date(year, month, 30)]
    if day <= 30:
        next_month = month + 1 if month < 12 else 1
        next_year = year if month < 12 else year + 1
        return [_safe_date(year, month, 30), _safe_date(next_year, next_month, 15)]
    next_month = month + 1 if month < 12 else 1
    next_year = year if month < 12 else year + 1
    return [_safe_date(next_year, next_month, 15), _safe_date(next_year, next_month, 30)]


def _raffle_period(now: datetime) -> tuple[datetime, datetime]:
    year = now.year
    month = now.month
    if now.day <= 15:
        start = datetime(year, month, 1, 0, 0, 0, tzinfo=now.tzinfo)
        end = datetime(year, month, 16, 0, 0, 0, tzinfo=now.tzinfo)
    else:
        start = datetime(year, month, 16, 0, 0, 0, tzinfo=now.tzinfo)
        next_month = month + 1 if month < 12 else 1
        next_year = year if month < 12 else year + 1
        end = datetime(next_year, next_month, 1, 0, 0, 0, tzinfo=now.tzinfo)
    db = SessionLocal()
    try:
        reset = db.query(AdminSetting).filter(AdminSetting.key == "RAFFLE_RESET_AT").first()
        if reset and reset.value:
            try:
                reset_dt = datetime.fromisoformat(reset.value)
                if reset_dt > start and reset_dt < end:
                    start = reset_dt
            except Exception:
                pass
    finally:
        db.close()
    return start, end


def _to_nano(ton_amount: float) -> int:
    return int(Decimal(str(ton_amount)) * Decimal("1000000000"))

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
    if order.payment_provider == "tonconnect":
        return "TON Wallet"
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
        if STAR_COST_RATE_SOURCE == "moex":
            usdtrub = await get_moex_usdrub_rate()
            rate_label = "MOEX USD/RUB"
        else:
            usdtrub = await get_usdtrub_rate()
            rate_label = "Binance USDTRUB"
        cost_usd = total_stars * (STAR_COST_USD_PER_100 / 100.0)
        cost_rub = cost_usd * usdtrub
        revenue = _round_money(order.amount_rub) or 0
        cost_rub = _round_money(cost_rub) or 0
        profit = _round_money(revenue - cost_rub) or 0
        per_star = _round_money(cost_rub / total_stars) if total_stars else 0
        order.cost_rub = cost_rub
        order.profit_rub = profit
        order.usdtrub_rate = _round_money(usdtrub) or 0
        order.cost_per_star = per_star
        revenue_line = (
            f"\n💰 Выручка: {revenue} ₽"
            f"\n📦 Себестоимость: {cost_rub} ₽"
            f"\n📊 Себестоимость/звезда: {per_star} ₽"
            f"\n📈 Прибыль: {profit} ₽"
            f"\n💱 Курс {rate_label}: {_round_money(usdtrub)} ₽"
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

_payment_sync_lock = asyncio.Lock()


async def _sync_pending_orders() -> None:
    async with _payment_sync_lock:
        db = SessionLocal()
        try:
            orders = (
                db.query(Order)
                .filter(
                    or_(
                        Order.status == "created",
                        and_(
                            Order.status == "paid",
                            or_(Order.fragment_status.is_(None), Order.fragment_status != "success"),
                        ),
                    )
                )
                .order_by(Order.timestamp.desc())
                .limit(100)
                .all()
            )

            for order in orders:
                _check_order_expired(order, db)
                if order.status == "created":
                    await _sync_crypto_order_status(order, db)
                    await _sync_platega_order_status(order, db)
                    await _sync_tonconnect_order_status(order, db)
                if order.status == "paid":
                    await _fulfill_order_if_needed(order, db)
        finally:
            db.close()


async def _payment_sync_loop() -> None:
    while True:
        try:
            await _sync_pending_orders()
        except Exception:
            logger.exception("[SYNC] Failed to sync pending orders")
        await asyncio.sleep(15)


@app.on_event("startup")
async def _startup_tasks():
    asyncio.create_task(_daily_report_loop())
    asyncio.create_task(_availability_loop())
    asyncio.create_task(_payment_sync_loop())
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
            referrer = db.query(User).filter(User.user_id == user.referrer_id).first()
            if not referrer:
                referrer = User(user_id=user.referrer_id)
                db.add(referrer)
                db.commit()
                db.refresh(referrer)
            referrer.referral_balance_stars = (referrer.referral_balance_stars or 0) + bonus
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


_toncenter_cache: dict[str, tuple[float, list[dict]]] = {}
_toncenter_lock = asyncio.Lock()
_toncenter_backoff_until: float | None = None


async def _toncenter_get_transactions(address: str, limit: int = 20) -> list[dict]:
    global _toncenter_backoff_until
    now_ts = asyncio.get_event_loop().time()
    cached = _toncenter_cache.get(address)
    if cached and now_ts - cached[0] < 10:
        return cached[1]

    if _toncenter_backoff_until and now_ts < _toncenter_backoff_until:
        return cached[1] if cached else []

    params = {
        "address": address,
        "limit": str(limit),
    }
    if TONCENTER_API_KEY:
        params["api_key"] = TONCENTER_API_KEY

    async with _toncenter_lock:
        now_ts = asyncio.get_event_loop().time()
        cached = _toncenter_cache.get(address)
        if cached and now_ts - cached[0] < 10:
            return cached[1]
        if _toncenter_backoff_until and now_ts < _toncenter_backoff_until:
            return cached[1] if cached else []

        for attempt in range(3):
            try:
                async with httpx.AsyncClient() as client:
                    r = await client.get(f"{TONCENTER_BASE_URL}/api/v2/getTransactions", params=params, timeout=15)
                if r.status_code == 429:
                    _toncenter_backoff_until = asyncio.get_event_loop().time() + (5 * (attempt + 1))
                    await asyncio.sleep(0.2 * (attempt + 1))
                    continue
                r.raise_for_status()
                data = r.json()
                result = data.get("result") or []
                _toncenter_cache[address] = (asyncio.get_event_loop().time(), result)
                return result
            except httpx.HTTPStatusError as exc:
                if exc.response is not None and exc.response.status_code == 429:
                    _toncenter_backoff_until = asyncio.get_event_loop().time() + (5 * (attempt + 1))
                    await asyncio.sleep(0.2 * (attempt + 1))
                    continue
                raise
        return cached[1] if cached else []


async def _sync_tonconnect_order_status(order: Order, db) -> None:
    if order.payment_provider != "tonconnect" or order.status == "paid":
        return
    if not TONCONNECT_WALLET_ADDRESS or not order.payment_amount_nano:
        return

    try:
        txs = await _toncenter_get_transactions(TONCONNECT_WALLET_ADDRESS, limit=20)
    except Exception:
        logger.exception("[TONCONNECT] Failed to fetch transactions for %s", order.order_id)
        return

    try:
        expected = int(order.payment_amount_nano)
    except (TypeError, ValueError):
        return

    order_ts = int(order.timestamp.timestamp())
    for tx in txs:
        in_msg = tx.get("in_msg") or {}
        value = in_msg.get("value")
        if value is None:
            continue
        try:
            value = int(value)
        except (TypeError, ValueError):
            continue
        if value != expected:
            continue
        utime = int(tx.get("utime") or 0)
        if utime and utime < order_ts - 600:
            continue
        order.status = "paid"
        tx_id = tx.get("transaction_id")
        if isinstance(tx_id, dict):
            tx_id = tx_id.get("hash") or tx_id.get("lt")
        if not tx_id:
            tx_id = tx.get("hash")
        if tx_id:
            order.payment_invoice_id = str(tx_id)
        db.commit()
        await _fulfill_order_if_needed(order, db)
        return

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


@app.post("/orders/tonconnect")
async def create_order_tonconnect(order: TonConnectOrderCreate, request: Request):
    if order.product_type != "stars":
        raise HTTPException(status_code=400, detail="Only Stars are supported right now")
    if not TONCONNECT_WALLET_ADDRESS:
        raise HTTPException(status_code=503, detail="TON wallet is not configured")

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

        amount_ton = await convert_rub_to_crypto(order.amount_rub, "TON")
        amount_nano = _to_nano(amount_ton)
        # add small random offset to make amount unique
        amount_nano += secrets.randbelow(10000) + 1

        init_data = request.headers.get("x-telegram-init-data")
        user_username = _touch_user_from_initdata(db, order.user_id, init_data)
        db_order = _create_order(
            db,
            order,
            provider="tonconnect",
            currency="TON",
            payment_method="wallet",
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

        db_order.payment_amount = amount_nano / 1_000_000_000
        db_order.payment_amount_nano = str(amount_nano)
        db.commit()

        return {
            "order_id": db_order.order_id,
            "address": TONCONNECT_WALLET_ADDRESS,
            "amount_ton": db_order.payment_amount,
            "amount_nano": db_order.payment_amount_nano,
            "payload": db_order.order_id
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
        await _sync_tonconnect_order_status(order, db)
        await _sync_tonconnect_order_status(order, db)
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
            await _sync_tonconnect_order_status(order, db)
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
    const navRoot = document.querySelector('.nav');
    if (navRoot) {
      function setPage(page){
        const links = document.querySelectorAll('.nav a');
        links.forEach(a => {
          if (a.dataset.page === page) a.classList.add('active');
          else a.classList.remove('active');
        });
        document.querySelectorAll('.card[data-page]').forEach(card => {
          card.style.display = card.dataset.page === page ? 'block' : 'none';
        });
        if (page === 'dashboard') { loadToday(); loadRecent(); }
        if (page === 'analytics') { loadAnalytics(); loadAnalyticsDaily(); }
        if (page === 'users') { loadUserSearch(); }
        if (page === 'promos') { loadPromos(); }
        if (page === 'bonuses') { loadBonuses(); }
        if (page === 'raffle') { loadRaffleSummary(); }
        if (page === 'settings') { loadSettings(); }
      }
      document.querySelectorAll('.nav a').forEach(a => {
        a.addEventListener('click', (e) => {
          e.preventDefault();
          const page = a.dataset.page;
          if (!page) return;
          history.replaceState(null, '', `#${page}`);
          setPage(page);
        });
      });
      const initialPage = (location.hash || '#dashboard').replace('#','');
      setPage(initialPage);
      window.addEventListener('hashchange', () => {
        const page = (location.hash || '#dashboard').replace('#','');
        setPage(page);
      });
    }

    function renderLineChart(containerId, points, color){
      const el = document.getElementById(containerId);
      if (!el) return;
      if (!points || points.length === 0) {
        el.innerHTML = '<div class="muted">Нет данных</div>';
        return;
      }
      const w = 600, h = 180, pad = 20;
      const vals = points.map(p => p.y);
      const max = Math.max(...vals, 1);
      const min = Math.min(...vals, 0);
      const span = max - min || 1;
      const step = (w - pad * 2) / Math.max(1, points.length - 1);
      let d = '';
      points.forEach((p, i) => {
        const x = pad + i * step;
        const y = h - pad - ((p.y - min) / span) * (h - pad * 2);
        d += `${i === 0 ? 'M' : 'L'}${x.toFixed(1)} ${y.toFixed(1)} `;
      });
      const area = `${d} L ${pad + (points.length - 1) * step} ${h - pad} L ${pad} ${h - pad} Z`;
      el.innerHTML = `
        <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
          <path d="${area}" fill="${color}22"></path>
          <path d="${d}" fill="none" stroke="${color}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"></path>
        </svg>
      `;
    }
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
  <title>Админка</title>
  <style>
    body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;background:#0e0f12;color:#e9eef7;margin:0}
    h1{margin:0 0 16px 0}
    .layout{display:grid;grid-template-columns:220px 1fr;min-height:100vh}
    .sidebar{background:#0b0d11;border-right:1px solid #1f232b;padding:18px;display:flex;flex-direction:column;gap:10px}
    .brand{font-weight:800;font-size:16px;margin-bottom:8px}
    .nav{display:flex;flex-direction:column;gap:6px}
    .nav a{display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:10px;color:#c9d1e4;text-decoration:none;border:1px solid transparent}
    .nav a.active{background:#15181d;border-color:#2a2f38;color:#fff}
    .content{padding:24px}
    .grid{display:grid;grid-template-columns:1fr;gap:16px}
    .card{background:#15181d;border:1px solid #1f232b;border-radius:16px;padding:16px}
    .section-title{font-weight:800;margin:0 0 10px 0}
    .muted{color:#8b93a7;font-size:12px}
    .btn{display:inline-flex;gap:8px;align-items:center;padding:8px 12px;border-radius:10px;border:1px solid #2a2f38;background:#101318;color:#e9eef7;cursor:pointer}
    .btn.primary{background:#2a8bf2;border-color:#2a8bf2}
    .field{display:flex;flex-direction:column;gap:6px;margin-top:10px}
    .input{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #2a2f38;background:#0e1116;color:#e9eef7}
    .row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
    .metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-top:10px}
    .metric{background:#101318;border:1px solid #212632;border-radius:12px;padding:12px}
    .metric .label{color:#8b93a7;font-size:12px;margin-bottom:6px}
    .metric .value{font-size:18px;font-weight:800}
    .table{width:100%;border-collapse:collapse;font-size:13px}
    .table th,.table td{padding:8px 10px;border-bottom:1px solid #232834;text-align:left}
    .table th{color:#9aa3b5;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
    .badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:999px;font-size:11px;border:1px solid #2a2f38}
    .badge.active{background:#0f2c1e;border-color:#1c6b4b;color:#7fe8b8}
    .badge.expired{background:#2a1b1b;border-color:#6b2a2a;color:#f1a3a3}
    .badge.used{background:#2a231b;border-color:#6b562a;color:#f5d38a}
    .badge.disabled{background:#1e1f26;border-color:#2a2f38;color:#9aa3b5}
    .progress{height:8px;border-radius:999px;background:#0e1116;border:1px solid #232834;overflow:hidden}
    .bar{height:100%;background:#2a8bf2}
    .bars{display:grid;gap:6px}
    .bar-row{display:grid;grid-template-columns:120px 1fr 60px;gap:10px;align-items:center}
    .bar-label{font-size:12px;color:#9aa3b5}
    .bar-value{font-size:12px;color:#c9d1e4;text-align:right}
    .bar-track{height:8px;border-radius:999px;background:#0e1116;border:1px solid #232834;overflow:hidden}
    .bar-fill{height:100%;background:linear-gradient(90deg,#2a8bf2,#6b5bff)}
    .stack{display:flex;flex-direction:column;gap:8px}
    .pill{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:#9aa3b5}
    .pill b{color:#e9eef7}
    .chart{background:#101318;border:1px solid #212632;border-radius:12px;padding:12px}
    .chart svg{width:100%;height:180px;display:block}
    .chart-title{font-size:13px;color:#9aa3b5;margin-bottom:8px}
    .chart-legend{display:flex;gap:12px;font-size:11px;color:#9aa3b5;margin-top:6px}
    pre{white-space:pre-wrap;word-break:break-word;color:#c9d1e4;font-size:13px}
  </style>
</head>
<body>
  <div class="layout">
    <aside class="sidebar">
      <div class="brand">Админка</div>
      <nav class="nav">
        <a href="#dashboard" data-page="dashboard" class="active">Дашборд</a>
        <a href="#analytics" data-page="analytics">Аналитика</a>
        <a href="#users" data-page="users">Пользователи</a>
        <a href="#promos" data-page="promos">Промокоды</a>
        <a href="#bonuses" data-page="bonuses">Бонусы</a>
        <a href="#raffle" data-page="raffle">Розыгрыш</a>
        <a href="#settings" data-page="settings">Настройки</a>
      </nav>
    </aside>
    <main class="content">
      <h1>Панель администратора</h1>
      <div class="grid">
    <div class="card" data-page="dashboard">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div class="section-title">Аудит · 24 часа</div>
        <button class="btn" onclick="loadToday()">Обновить</button>
      </div>
      <pre id="today">Загрузка...</pre>
    </div>
    <div class="card" data-page="dashboard">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div class="section-title">Аудит · Последние</div>
        <button class="btn" onclick="loadRecent()">Обновить</button>
      </div>
      <pre id="recent">Загрузка...</pre>
      <div class="muted">Последние 200 оплаченных заказов на звёзды.</div>
    </div>
    <div class="card" data-page="analytics">
      <div class="section-title">Графики по дням (30 дней)</div>
      <div class="chart">
        <div class="chart-title">Выручка, ₽</div>
        <div id="chart-revenue"></div>
      </div>
      <div class="chart" style="margin-top:10px">
        <div class="chart-title">Прибыль, ₽</div>
        <div id="chart-profit"></div>
      </div>
      <div class="chart" style="margin-top:10px">
        <div class="chart-title">Заказы, шт</div>
        <div id="chart-orders"></div>
      </div>
    </div>
    <div class="card" data-page="analytics">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div class="section-title">Аналитика</div>
        <button class="btn" onclick="loadAnalytics()">Обновить</button>
      </div>
      <div class="metrics" id="analytics-metrics">
        <div class="metric"><div class="label">Открытия</div><div class="value">—</div></div>
      </div>
      <div class="stack" style="margin-top:12px">
        <div class="pill">Период: <b id="analytics-period">—</b></div>
        <div class="pill">Воронка (уник.): <b id="analytics-funnel-label">—</b></div>
        <div class="bars" id="funnel-bars">
          <div class="bar-row">
            <div class="bar-label">Открыли</div>
            <div class="bar-track"><div id="funnel-open" class="bar-fill" style="width:100%"></div></div>
            <div class="bar-value" id="funnel-open-val">—</div>
          </div>
          <div class="bar-row">
            <div class="bar-label">Выбрали</div>
            <div class="bar-track"><div id="funnel-select" class="bar-fill" style="width:0%"></div></div>
            <div class="bar-value" id="funnel-select-val">—</div>
          </div>
          <div class="bar-row">
            <div class="bar-label">Оплатили</div>
            <div class="bar-track"><div id="funnel-paid" class="bar-fill" style="width:0%"></div></div>
            <div class="bar-value" id="funnel-paid-val">—</div>
          </div>
        </div>
      </div>
      <div class="stack" style="margin-top:14px">
        <div class="pill">P&L: <b id="analytics-pl-label">—</b></div>
        <div class="bars">
          <div class="bar-row">
            <div class="bar-label">Выручка</div>
            <div class="bar-track"><div id="pl-revenue" class="bar-fill" style="width:0%"></div></div>
            <div class="bar-value" id="pl-revenue-val">—</div>
          </div>
          <div class="bar-row">
            <div class="bar-label">Себестоимость</div>
            <div class="bar-track"><div id="pl-cost" class="bar-fill" style="width:0%"></div></div>
            <div class="bar-value" id="pl-cost-val">—</div>
          </div>
          <div class="bar-row">
            <div class="bar-label">Прибыль</div>
            <div class="bar-track"><div id="pl-profit" class="bar-fill" style="width:0%"></div></div>
            <div class="bar-value" id="pl-profit-val">—</div>
          </div>
        </div>
        <div class="muted" id="pl-rate-note"></div>
      </div>
      <div style="margin-top:14px">
        <div class="section-title" style="font-size:14px">Провайдеры</div>
        <table class="table" id="analytics-providers">
          <thead>
            <tr><th>Провайдер</th><th>Заказы</th><th>Выручка ₽</th><th>Конв. %</th></tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
      <div style="margin-top:14px">
        <div class="section-title" style="font-size:14px">ТОП пользователей (выручка)</div>
        <table class="table" id="analytics-top">
          <thead>
            <tr><th>Пользователь</th><th>Выручка ₽</th></tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
    </div>
    <div class="card" data-page="users">
      <div class="section-title">Поиск пользователей и прибыль</div>
      <div class="row">
        <div class="field">
          <label class="muted">Поиск (id / @username)</label>
          <input class="input" id="user-search" placeholder="683310989 или @username"/>
        </div>
        <div class="field">
          <label class="muted">Период (дней)</label>
          <input class="input" id="user-search-days" type="number" min="1" value="30"/>
        </div>
      </div>
      <button class="btn" onclick="loadUserSearch()" style="margin-top:10px">Искать</button>
      <table class="table" id="users-table" style="margin-top:12px">
        <thead>
          <tr><th>Пользователь</th><th>Выручка ₽</th><th>Себестоимость ₽</th><th>Прибыль ₽</th><th>Заказы</th><th>⭐</th></tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
    <div class="card" data-page="promos">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div class="section-title">Промокоды</div>
        <div style="display:flex;gap:6px;flex-wrap:wrap">
          <button class="btn" onclick="loadPromos()">Все</button>
          <button class="btn" onclick="loadPromos('active')">Активные</button>
          <button class="btn" onclick="loadPromos('expired')">Истёкшие</button>
          <button class="btn" onclick="loadPromos('used')">Использованы</button>
        </div>
      </div>
      <table class="table" id="promo-table">
        <thead>
          <tr><th>Код</th><th>%</th><th>Исп.</th><th>Статус</th><th>До</th></tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
    <div class="card" data-page="bonuses">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div class="section-title">Бонусы</div>
        <button class="btn" onclick="loadBonuses()">Обновить</button>
      </div>
      <table class="table" id="bonus-table">
        <thead>
          <tr><th>Пользователь</th><th>⭐</th><th>Статус</th><th>Источник</th><th>До</th><th>Создан</th></tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
    <div class="card" data-page="bonuses">
      <strong>Массовая выдача бонусов</strong>
      <div class="field">
        <label class="muted">User IDs (через запятую/пробел/перенос)</label>
        <textarea class="input" id="bonus_bulk_ids" rows="4" placeholder="12345, 67890"></textarea>
      </div>
      <div class="row">
        <div class="field">
          <label class="muted">Звёзды</label>
          <input class="input" id="bonus_bulk_stars" type="number" min="1"/>
        </div>
        <div class="field">
          <label class="muted">TTL (мин)</label>
          <input class="input" id="bonus_bulk_ttl" type="number" min="1"/>
        </div>
      </div>
      <div class="field">
        <label class="muted">Источник</label>
        <input class="input" id="bonus_bulk_source" placeholder="admin_bulk"/>
      </div>
      <button class="btn" onclick="bulkBonus()" style="margin-top:10px">Выдать бонусы</button>
      <div id="bonus-bulk-status" class="muted"></div>
    </div>
    <div class="card" data-page="raffle">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <strong>Управление розыгрышем</strong>
        <div style="display:flex;gap:6px;flex-wrap:wrap">
          <button class="btn" onclick="resetRaffle()">Сбросить период</button>
          <button class="btn" onclick="recalcRaffle()">Пересчитать топ</button>
          <button class="btn" onclick="loadRaffleSummary()">Сводка</button>
          <a class="btn" href="/admin/raffle/participants?format=csv" target="_blank" rel="noopener">Экспорт CSV</a>
        </div>
      </div>
      <div class="muted">Сбросить период — начинается новый период с текущего момента.</div>
      <div class="muted">Пересчитать топ — мгновенно обновляет рейтинг участников.</div>
      <div class="muted">Сводка — кто лидирует и есть ли победитель дня.</div>
      <div class="muted">Экспорт CSV — полный список участников с шансами.</div>
      <div id="raffle-status" class="muted" style="margin-top:8px;"></div>
    </div>
    <div class="card" data-page="settings">
      <strong>Настройки</strong>
      <div class="row">
        <div class="field">
          <label class="muted">Время отчёта (HH:MM)</label>
          <input class="input" id="report_time" placeholder="00:00"/>
        </div>
        <div class="field">
          <label class="muted">Реферальный %</label>
          <input class="input" id="ref_percent" type="number" min="0" max="100"/>
        </div>
      </div>
      <div class="row">
        <div class="field">
          <label class="muted">Цена tier 1 (<=1000)</label>
          <input class="input" id="rate1" type="number" step="0.01"/>
        </div>
        <div class="field">
          <label class="muted">Цена tier 2 (<=5000)</label>
          <input class="input" id="rate2" type="number" step="0.01"/>
        </div>
      </div>
      <div class="field">
        <label class="muted">Цена tier 3 (>5000)</label>
        <input class="input" id="rate3" type="number" step="0.01"/>
      </div>
      <div class="field">
        <label class="muted">Приз (заголовок)</label>
        <input class="input" id="raffle_prize_title" placeholder="NFT-подарок или бонусные звёзды"/>
      </div>
      <div class="field">
        <label class="muted">Приз (описание)</label>
        <input class="input" id="raffle_prize_desc" placeholder="Победитель получит приз после розыгрыша."/>
      </div>
      <div class="field">
        <label class="muted">Ссылка на приз (URL)</label>
        <input class="input" id="raffle_prize_image" placeholder="https://..."/>
      </div>
      <div class="field">
        <label class="muted">Баннер включён (true/false)</label>
        <input class="input" id="banner_enabled" placeholder="false"/>
      </div>
      <div class="field">
        <label class="muted">Заголовок баннера</label>
        <input class="input" id="banner_title" placeholder="Акция недели"/>
      </div>
      <div class="field">
        <label class="muted">Текст баннера</label>
        <input class="input" id="banner_text" placeholder="Скидка 5% на звёзды"/>
      </div>
      <div class="field">
        <label class="muted">Ссылка баннера</label>
        <input class="input" id="banner_url" placeholder="https://t.me/..."/>
      </div>
      <div class="field">
        <label class="muted">Баннер до (YYYY-MM-DD или ISO)</label>
        <input class="input" id="banner_until" placeholder="2026-03-30"/>
      </div>
      <div class="field">
        <label class="muted">Текст под промокодом</label>
        <input class="input" id="promo_text" placeholder="Скидки и промокоды в нашем канале"/>
      </div>
      <button class="btn" onclick="saveSettings()" style="margin-top:10px">Сохранить</button>
      <div id="settings-status" class="muted"></div>
    </div>
    <div class="card" data-page="promos">
      <strong>Создать промокод</strong>
      <div class="row">
        <div class="field">
          <label class="muted">Код</label>
          <input class="input" id="promo_code" placeholder="PROMO2026"/>
        </div>
        <div class="field">
          <label class="muted">Процент</label>
          <input class="input" id="promo_percent" type="number" min="1" max="100"/>
        </div>
      </div>
      <div class="row">
        <div class="field">
          <label class="muted">Лимит использований</label>
          <input class="input" id="promo_max" type="number" min="1"/>
        </div>
        <div class="field">
          <label class="muted">Истекает (YYYY-MM-DD)</label>
          <input class="input" id="promo_exp" placeholder="2026-12-31"/>
        </div>
      </div>
      <button class="btn" onclick="createPromo()" style="margin-top:10px">Создать</button>
      <div id="promo-status" class="muted"></div>
    </div>
    <div class="card" data-page="bonuses">
      <strong>Создать бонус-ссылку</strong>
      <div class="row">
        <div class="field">
          <label class="muted">Звёзды</label>
          <input class="input" id="bonus_stars" type="number" min="1"/>
        </div>
        <div class="field">
          <label class="muted">TTL (мин)</label>
          <input class="input" id="bonus_ttl" type="number" min="1"/>
        </div>
      </div>
      <div class="row">
        <div class="field">
          <label class="muted">Лимит использований</label>
          <input class="input" id="bonus_max" type="number" min="1"/>
        </div>
        <div class="field">
          <label class="muted">Источник</label>
          <input class="input" id="bonus_source" placeholder="promo_tg"/>
        </div>
      </div>
      <button class="btn" onclick="createBonus()" style="margin-top:10px">Создать ссылку</button>
      <div id="bonus-status" class="muted"></div>
    </div>
    </main>
  </div>
  <script>
    async function loadToday(){
      const res = await fetch('/admin/audit/today', {credentials:'include'});
      const data = await res.json();
      document.getElementById('today').textContent = (data.items || []).join('\\n') || 'Нет данных';
    }
    async function loadRecent(){
      const res = await fetch('/admin/audit/recent', {credentials:'include'});
      const data = await res.json();
      document.getElementById('recent').textContent = (data.items || []).join('\\n') || 'Нет данных';
    }
    async function loadAnalytics(){
      const res = await fetch('/admin/analytics', {credentials:'include'});
      const data = await res.json();
      if(!res.ok){
        const metrics = document.getElementById('analytics-metrics');
        if (metrics) metrics.innerHTML = '<div class="metric"><div class="label">Ошибка</div><div class="value">Не удалось</div></div>';
        return;
      }
      const metrics = document.getElementById('analytics-metrics');
      if (metrics) {
        metrics.innerHTML = '';
        const items = [
          {label:'Открытия', value:`${data.opens} (${data.opens_unique} уник.)`},
          {label:'Выборы', value:`${data.selects} (${data.selects_unique} уник.)`},
          {label:'Создано', value:data.created_orders},
          {label:'Оплачено', value:data.paid_orders},
          {label:'Неудачи', value:data.failed_orders},
          {label:'Выручка', value:`${data.paid_total_rub} ₽`},
          {label:'Себестоимость', value:`${data.cost_total_rub ?? 0} ₽`},
          {label:'Прибыль', value:`${data.profit_total_rub ?? 0} ₽`},
          {label:'Средний чек', value:`${data.avg_check_rub} ₽`},
          {label:'Звёзды', value:`${data.stars_total} +${data.bonus_total}`},
        ];
        items.forEach(it => {
          const el = document.createElement('div');
          el.className = 'metric';
          el.innerHTML = `<div class="label">${it.label}</div><div class="value">${it.value}</div>`;
          metrics.appendChild(el);
        });
      }
      const periodEl = document.getElementById('analytics-period');
      if (periodEl) periodEl.textContent = `${data.period_start} → ${data.period_end}`;
      const funnelLabel = document.getElementById('analytics-funnel-label');
      if (funnelLabel) funnelLabel.textContent = `${data.opens_unique} → ${data.selects_unique} → ${data.paid_orders}`;
      const openBar = document.getElementById('funnel-open');
      const selectBar = document.getElementById('funnel-select');
      const paidBar = document.getElementById('funnel-paid');
      const openVal = Math.max(1, data.opens_unique || 0);
      const selectPct = data.opens_unique ? (data.selects_unique / openVal) * 100 : 0;
      const paidPct = data.opens_unique ? (data.paid_orders / openVal) * 100 : 0;
      if (openBar) openBar.style.width = '100%';
      if (selectBar) selectBar.style.width = `${Math.min(100, selectPct).toFixed(1)}%`;
      if (paidBar) paidBar.style.width = `${Math.min(100, paidPct).toFixed(1)}%`;
      const openValEl = document.getElementById('funnel-open-val');
      const selectValEl = document.getElementById('funnel-select-val');
      const paidValEl = document.getElementById('funnel-paid-val');
      if (openValEl) openValEl.textContent = `${data.opens_unique || 0}`;
      if (selectValEl) selectValEl.textContent = `${data.selects_unique || 0}`;
      if (paidValEl) paidValEl.textContent = `${data.paid_orders || 0}`;

      const revenue = Number(data.paid_total_rub || 0);
      const cost = Number(data.cost_total_rub || 0);
      const profit = Number(data.profit_total_rub || 0);
      const maxPL = Math.max(1, revenue, cost, Math.abs(profit));
      const plLabel = document.getElementById('analytics-pl-label');
      if (plLabel) plLabel.textContent = `${revenue} ₽ / ${cost} ₽ / ${profit} ₽`;
      const plRevenue = document.getElementById('pl-revenue');
      const plCost = document.getElementById('pl-cost');
      const plProfit = document.getElementById('pl-profit');
      if (plRevenue) {
        plRevenue.style.width = `${Math.min(100, (revenue / maxPL) * 100).toFixed(1)}%`;
        plRevenue.style.background = 'linear-gradient(90deg,#2a8bf2,#6b5bff)';
      }
      if (plCost) {
        plCost.style.width = `${Math.min(100, (cost / maxPL) * 100).toFixed(1)}%`;
        plCost.style.background = 'linear-gradient(90deg,#f59e0b,#f97316)';
      }
      if (plProfit) {
        plProfit.style.width = `${Math.min(100, (Math.abs(profit) / maxPL) * 100).toFixed(1)}%`;
        plProfit.style.background = profit >= 0
          ? 'linear-gradient(90deg,#22c55e,#86efac)'
          : 'linear-gradient(90deg,#ef4444,#f97316)';
      }
      const plRevenueVal = document.getElementById('pl-revenue-val');
      const plCostVal = document.getElementById('pl-cost-val');
      const plProfitVal = document.getElementById('pl-profit-val');
      if (plRevenueVal) plRevenueVal.textContent = `${revenue} ₽`;
      if (plCostVal) plCostVal.textContent = `${cost} ₽`;
      if (plProfitVal) plProfitVal.textContent = `${profit} ₽`;
      const rateNote = document.getElementById('pl-rate-note');
      if (rateNote) {
        rateNote.textContent = data.usdtrub_rate
          ? `Курс для себестоимости: ${data.cost_rate_label || 'USD/RUB'} ${data.usdtrub_rate} ₽`
          : '';
      }

      const providersTbody = document.querySelector('#analytics-providers tbody');
      if (providersTbody) {
        providersTbody.innerHTML = '';
        const providers = data.by_provider || {};
        Object.keys(providers).forEach((key) => {
          const revenue = (data.revenue_by_provider || {})[key] ?? 0;
          const conv = (data.provider_conversion_pct || {})[key] ?? 0;
          const tr = document.createElement('tr');
          tr.innerHTML = `<td>${key}</td><td>${providers[key]}</td><td>${revenue}</td><td>${conv}%</td>`;
          providersTbody.appendChild(tr);
        });
        if (!Object.keys(providers).length) {
          providersTbody.innerHTML = '<tr><td colspan="4" class="muted">Нет данных</td></tr>';
        }
      }

      const topTbody = document.querySelector('#analytics-top tbody');
      if (topTbody) {
        topTbody.innerHTML = '';
        const top = data.top_users_by_revenue || [];
        top.forEach(item => {
          const name = item.display || `id ${item.user_id}`;
          const tr = document.createElement('tr');
          tr.innerHTML = `<td>${name}</td><td>${item.revenue_rub}</td>`;
          topTbody.appendChild(tr);
        });
        if (!top.length) {
          topTbody.innerHTML = '<tr><td colspan="2" class="muted">Нет данных</td></tr>';
        }
      }
    }
    async function loadAnalyticsDaily(){
      const res = await fetch('/admin/analytics/daily?days=30', {credentials:'include'});
      const data = await res.json();
      if(!res.ok || !data.items){ 
        renderLineChart('chart-revenue', [], '#2a8bf2');
        renderLineChart('chart-profit', [], '#22c55e');
        renderLineChart('chart-orders', [], '#f59e0b');
        return;
      }
      const revenue = data.items.map((d,i)=>({x:i, y:Number(d.revenue||0)}));
      const profit = data.items.map((d,i)=>({x:i, y:Number(d.profit||0)}));
      const orders = data.items.map((d,i)=>({x:i, y:Number(d.orders||0)}));
      renderLineChart('chart-revenue', revenue, '#2a8bf2');
      renderLineChart('chart-profit', profit, '#22c55e');
      renderLineChart('chart-orders', orders, '#f59e0b');
    }

    async function loadUserSearch(){
      const q = (document.getElementById('user-search')?.value || '').trim();
      const days = Number(document.getElementById('user-search-days')?.value || 30) || 30;
      const qs = `?days=${encodeURIComponent(days)}${q ? `&q=${encodeURIComponent(q)}` : ''}`;
      const res = await fetch(`/admin/users/search${qs}`, {credentials:'include'});
      const data = await res.json();
      const body = document.querySelector('#users-table tbody');
      if (!body) return;
      if(!res.ok){ body.innerHTML = '<tr><td colspan="6" class="muted">Не удалось</td></tr>'; return; }
      const items = data.items || [];
      body.innerHTML = '';
      items.forEach(item => {
        const name = item.display || `id ${item.user_id}`;
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${name}</td><td>${item.revenue}</td><td>${item.cost}</td><td>${item.profit}</td><td>${item.orders}</td><td>${item.stars}</td>`;
        body.appendChild(tr);
      });
      if (!items.length) body.innerHTML = '<tr><td colspan="6" class="muted">Нет данных</td></tr>';
    }
    async function loadPromos(filter){
      const qs = filter ? `?filter=${encodeURIComponent(filter)}` : '';
      const res = await fetch(`/admin/promos${qs}`, {credentials:'include'});
      const data = await res.json();
      const body = document.querySelector('#promo-table tbody');
      if (!body) return;
      if(!res.ok){ body.innerHTML = '<tr><td colspan="5" class="muted">Не удалось</td></tr>'; return; }
      const items = data.items || [];
      body.innerHTML = '';
      items.forEach(p => {
        const tr = document.createElement('tr');
        const status = p.status || (p.active ? 'active' : 'disabled');
        const statusLabel = status === 'active' ? 'активен'
          : status === 'expired' ? 'истёк'
          : status === 'used' ? 'исчерпан'
          : 'выключен';
        tr.innerHTML = `
          <td>${p.code}</td>
          <td>${p.percent}%</td>
          <td>${p.uses}/${p.max_uses ?? '∞'}</td>
          <td><span class="badge ${status}">${statusLabel}</span></td>
          <td>${p.expires_at || '—'}</td>
        `;
        body.appendChild(tr);
      });
      if (!items.length) body.innerHTML = '<tr><td colspan="5" class="muted">Нет данных</td></tr>';
    }
    async function loadBonuses(){
      const res = await fetch('/admin/bonuses', {credentials:'include'});
      const data = await res.json();
      const body = document.querySelector('#bonus-table tbody');
      if (!body) return;
      if(!res.ok){ body.innerHTML = '<tr><td colspan="6" class="muted">Не удалось</td></tr>'; return; }
      const items = data.items || [];
      body.innerHTML = '';
      items.forEach(b => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${b.user_id}</td>
          <td>${b.stars} ⭐</td>
          <td>${b.status}</td>
          <td>${b.source || '—'}</td>
          <td>${b.expires_at || '—'}</td>
          <td>${b.created_at || '—'}</td>
        `;
        body.appendChild(tr);
      });
      if (!items.length) body.innerHTML = '<tr><td colspan="6" class="muted">Нет данных</td></tr>';
    }
    async function resetRaffle(){
      const res = await fetch('/admin/raffle/reset', {method:'POST', credentials:'include'});
      document.getElementById('raffle-status').textContent = res.ok ? 'Период сброшен' : 'Сброс не удался';
    }
    async function recalcRaffle(){
      const res = await fetch('/admin/raffle/recalc', {method:'POST', credentials:'include'});
      const data = await res.json().catch(() => ({}));
      document.getElementById('raffle-status').textContent = res.ok ? `Пересчёт OK (${data.recalc_at || ''})` : 'Пересчёт не удался';
    }
    async function loadRaffleSummary(){
      const res = await fetch('/admin/raffle/summary', {credentials:'include'});
      const data = await res.json();
      if(!res.ok){ document.getElementById('raffle-status').textContent = 'Сводка не получена'; return; }
      const win = data.winner ? `победитель ${data.winner.user_id} (${data.winner.total_stars} ⭐)` : 'победитель —';
      document.getElementById('raffle-status').textContent = `${data.period_start} → ${data.period_end} | участников ${data.total_participants} | звёзд ${data.total_stars} | ${win}`;
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
      document.getElementById('raffle_prize_title').value = data.raffle_prize_title ?? '';
      document.getElementById('raffle_prize_desc').value = data.raffle_prize_desc ?? '';
      document.getElementById('raffle_prize_image').value = data.raffle_prize_image ?? '';
      document.getElementById('banner_enabled').value = (data.banner_enabled ?? false).toString();
      document.getElementById('banner_title').value = data.banner_title ?? '';
      document.getElementById('banner_text').value = data.banner_text ?? '';
      document.getElementById('banner_url').value = data.banner_url ?? '';
      document.getElementById('banner_until').value = data.banner_until ?? '';
      document.getElementById('promo_text').value = data.promo_text ?? '';
    }
    async function saveSettings(){
      const payload = {
        report_time: document.getElementById('report_time').value.trim() || null,
        referral_percent: Number(document.getElementById('ref_percent').value || 0) || null,
        stars_rate_1: Number(document.getElementById('rate1').value || 0) || null,
        stars_rate_2: Number(document.getElementById('rate2').value || 0) || null,
        stars_rate_3: Number(document.getElementById('rate3').value || 0) || null,
        raffle_prize_title: document.getElementById('raffle_prize_title').value.trim() || null,
        raffle_prize_desc: document.getElementById('raffle_prize_desc').value.trim() || null,
        raffle_prize_image: document.getElementById('raffle_prize_image').value.trim() || null,
        banner_enabled: (document.getElementById('banner_enabled').value || '').trim().toLowerCase() === 'true',
        banner_title: document.getElementById('banner_title').value.trim() || null,
        banner_text: document.getElementById('banner_text').value.trim() || null,
        banner_url: document.getElementById('banner_url').value.trim() || null,
        banner_until: document.getElementById('banner_until').value.trim() || null,
        promo_text: document.getElementById('promo_text').value.trim() || null,
      };
      const res = await fetch('/admin/settings', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(payload),
        credentials:'include'
      });
      document.getElementById('settings-status').textContent = res.ok ? 'Сохранено' : 'Ошибка сохранения';
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
      document.getElementById('promo-status').textContent = res.ok ? `OK: ${data.code || payload.code}` : 'Не удалось';
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
        ? `Ссылка: ${data.link || ''}`
        : 'Не удалось';
    }
    async function bulkBonus(){
      const payload = {
        user_ids: document.getElementById('bonus_bulk_ids').value.trim(),
        stars: Number(document.getElementById('bonus_bulk_stars').value || 0),
        ttl_minutes: Number(document.getElementById('bonus_bulk_ttl').value || 0) || null,
        source: document.getElementById('bonus_bulk_source').value.trim() || null,
      };
      const res = await fetch('/admin/bonus/grant_bulk', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(payload),
        credentials:'include'
      });
      const data = await res.json().catch(() => ({}));
      document.getElementById('bonus-bulk-status').textContent = res.ok
        ? `Создано: ${data.created || 0}`
        : 'Не удалось';
    }
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
    raffle_prize_title: str | None = None
    raffle_prize_desc: str | None = None
    raffle_prize_image: str | None = None
    banner_enabled: bool | None = None
    banner_title: str | None = None
    banner_text: str | None = None
    banner_url: str | None = None
    banner_until: str | None = None
    promo_text: str | None = None


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
            "raffle_prize_title": _get_setting(db, "RAFFLE_PRIZE_TITLE", "NFT-подарок или бонусные звёзды"),
            "raffle_prize_desc": _get_setting(db, "RAFFLE_PRIZE_DESC", "Победитель получит приз после розыгрыша."),
            "raffle_prize_image": _get_setting(db, "RAFFLE_PRIZE_IMAGE", ""),
            "banner_enabled": _get_setting(db, "BANNER_ENABLED", "false").lower() in ("1", "true", "yes"),
            "banner_title": _get_setting(db, "BANNER_TITLE", ""),
            "banner_text": _get_setting(db, "BANNER_TEXT", ""),
            "banner_url": _get_setting(db, "BANNER_URL", ""),
            "banner_until": _get_setting(db, "BANNER_UNTIL", ""),
            "promo_text": _get_setting(db, "PROMO_TEXT", ""),
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
            "RAFFLE_PRIZE_TITLE": payload.raffle_prize_title,
            "RAFFLE_PRIZE_DESC": payload.raffle_prize_desc,
            "RAFFLE_PRIZE_IMAGE": payload.raffle_prize_image,
            "BANNER_ENABLED": str(payload.banner_enabled).lower() if payload.banner_enabled is not None else None,
            "BANNER_TITLE": payload.banner_title,
            "BANNER_TEXT": payload.banner_text,
            "BANNER_URL": payload.banner_url,
            "BANNER_UNTIL": payload.banner_until,
            "PROMO_TEXT": payload.promo_text,
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


class AdminBonusBulkPayload(BaseModel):
    user_ids: str
    stars: int
    ttl_minutes: int | None = None
    source: str | None = None


@app.post("/admin/bonus/grant_bulk")
async def admin_bonus_grant_bulk(request: Request, payload: AdminBonusBulkPayload):
    _admin_require(request)
    raw_ids = payload.user_ids or ""
    tokens = re.split(r"[\\s,;]+", raw_ids.strip())
    user_ids = [t for t in tokens if t]
    if not user_ids:
        raise HTTPException(status_code=400, detail="No user_ids provided")
    expires_at = None
    if payload.ttl_minutes:
        expires_at = now_msk() + timedelta(minutes=payload.ttl_minutes)
    db = SessionLocal()
    try:
        created = 0
        for uid in user_ids:
            grant = BonusGrant(
                user_id=uid,
                stars=payload.stars,
                status="active",
                source=payload.source or "admin_bulk",
                expires_at=expires_at,
            )
            db.add(grant)
            created += 1
        db.commit()
        return {"status": "ok", "created": created}
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
            "banner_enabled": _get_setting(db, "BANNER_ENABLED", "false").lower() in ("1", "true", "yes"),
            "banner_title": _get_setting(db, "BANNER_TITLE", ""),
            "banner_text": _get_setting(db, "BANNER_TEXT", ""),
            "banner_url": _get_setting(db, "BANNER_URL", ""),
            "banner_until": _get_setting(db, "BANNER_UNTIL", ""),
            "promo_text": _get_setting(db, "PROMO_TEXT", ""),
        }
    finally:
        db.close()


@app.post("/analytics/visit")
async def analytics_visit(request: Request, user_id: str | None = Query(default=None)):
    init_data = request.headers.get("x-telegram-init-data")
    uid = user_id
    if not uid and init_data and _verify_telegram_init_data(init_data):
        uid = _extract_user_id(init_data)
    db = SessionLocal()
    try:
        db.execute(
            text(
                "INSERT INTO app_events (event_type, user_id) VALUES (:event_type, :user_id)"
            ),
            {"event_type": "open", "user_id": uid},
        )
        db.commit()
        return {"status": "ok"}
    finally:
        db.close()


class AnalyticsEventPayload(BaseModel):
    event_type: str


@app.post("/analytics/event")
async def analytics_event(request: Request, payload: AnalyticsEventPayload, user_id: str | None = Query(default=None)):
    init_data = request.headers.get("x-telegram-init-data")
    uid = user_id
    if not uid and init_data and _verify_telegram_init_data(init_data):
        uid = _extract_user_id(init_data)
    if not payload.event_type:
        raise HTTPException(status_code=400, detail="event_type required")
    db = SessionLocal()
    try:
        db.execute(
            text(
                "INSERT INTO app_events (event_type, user_id) VALUES (:event_type, :user_id)"
            ),
            {"event_type": payload.event_type, "user_id": uid},
        )
        db.commit()
        return {"status": "ok"}
    finally:
        db.close()


@app.get("/raffle/prize/preview")
async def raffle_prize_preview(url: str = Query(...)):
    if not url.startswith("https://t.me/nft/"):
        raise HTTPException(status_code=400, detail="Only t.me/nft links are allowed")
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            r.raise_for_status()
            meta = _parse_og_meta(r.text)
        return {"ok": True, **meta}
    except Exception as exc:
        logger.exception("[RAFFLE] Failed to fetch prize preview")
        raise HTTPException(status_code=502, detail="Failed to fetch prize preview") from exc


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


@app.get("/admin/analytics")
async def admin_analytics(request: Request):
    _admin_require(request)
    db = SessionLocal()
    try:
        now = now_msk()
        start_msk = now - timedelta(days=30)
        end_msk = now
        start = start_msk.astimezone(timezone.utc)
        end = end_msk.astimezone(timezone.utc)

        created_orders = db.query(Order).filter(
            Order.timestamp >= start,
            Order.timestamp < end
        ).count()
        paid_orders_q = db.query(Order).filter(
            Order.status == "paid",
            Order.timestamp >= start,
            Order.timestamp < end
        )
        paid_orders = paid_orders_q.all()
        failed_orders = db.query(Order).filter(
            Order.status == "failed",
            Order.timestamp >= start,
            Order.timestamp < end
        ).count()

        paid_total = sum((o.amount_rub or 0) for o in paid_orders)
        avg_check = paid_total / len(paid_orders) if paid_orders else 0.0
        stars_total = sum((o.quantity or 0) for o in paid_orders if o.product_type == "stars")
        bonus_total = sum((o.bonus_stars_applied or 0) for o in paid_orders if o.product_type == "stars")

        need_cost_calc = any((o.cost_rub is None or o.profit_rub is None) for o in paid_orders)
        usdtrub = None
        rate_label = None
        if need_cost_calc:
            if STAR_COST_RATE_SOURCE == "moex":
                usdtrub = await get_moex_usdrub_rate()
                rate_label = "MOEX USD/RUB"
            else:
                usdtrub = await get_usdtrub_rate()
                rate_label = "Binance USDTRUB"

        total_cost = 0.0
        total_profit = 0.0
        for o in paid_orders:
            if o.cost_rub is not None and o.profit_rub is not None:
                total_cost += o.cost_rub or 0
                total_profit += o.profit_rub or 0
                continue
            total_stars = int(o.quantity or 0) + int(o.bonus_stars_applied or 0)
            if total_stars <= 0 or usdtrub is None:
                continue
            cost_usd = total_stars * (STAR_COST_USD_PER_100 / 100.0)
            cost_rub = _round_money(cost_usd * usdtrub) or 0
            revenue = _round_money(o.amount_rub) or 0
            profit = _round_money(revenue - cost_rub) or 0
            per_star = _round_money(cost_rub / total_stars) if total_stars else 0
            o.cost_rub = cost_rub
            o.profit_rub = profit
            o.cost_per_star = per_star
            o.usdtrub_rate = _round_money(usdtrub) or 0
            total_cost += cost_rub
            total_profit += profit

        if need_cost_calc:
            try:
                db.commit()
            except Exception:
                db.rollback()

        by_provider = {}
        revenue_by_provider = {}
        created_by_provider = {}
        paid_by_provider = {}
        for o in paid_orders:
            key = o.payment_provider or "unknown"
            by_provider[key] = by_provider.get(key, 0) + 1
            revenue_by_provider[key] = round(revenue_by_provider.get(key, 0) + (o.amount_rub or 0), 2)
            paid_by_provider[key] = paid_by_provider.get(key, 0) + 1
        created_rows = (
            db.query(Order.payment_provider, func.count())
            .filter(Order.timestamp >= start, Order.timestamp < end)
            .group_by(Order.payment_provider)
            .all()
        )
        for provider, cnt in created_rows:
            key = provider or "unknown"
            created_by_provider[key] = int(cnt)

        provider_conversion = {}
        for key, created_cnt in created_by_provider.items():
            paid_cnt = paid_by_provider.get(key, 0)
            provider_conversion[key] = round((paid_cnt / created_cnt * 100), 2) if created_cnt else 0.0

        conversion = round((len(paid_orders) / created_orders * 100), 2) if created_orders else 0.0

        opens = db.execute(
            text(
                "SELECT COUNT(*) FROM app_events WHERE event_type = 'open' AND created_at >= :start AND created_at < :end"
            ),
            {"start": start, "end": end},
        ).scalar() or 0
        opens_unique = db.execute(
            text(
                "SELECT COUNT(DISTINCT user_id) FROM app_events WHERE event_type = 'open' AND user_id IS NOT NULL AND created_at >= :start AND created_at < :end"
            ),
            {"start": start, "end": end},
        ).scalar() or 0
        selects = db.execute(
            text(
                "SELECT COUNT(*) FROM app_events WHERE event_type LIKE 'select_%' AND created_at >= :start AND created_at < :end"
            ),
            {"start": start, "end": end},
        ).scalar() or 0
        selects_unique = db.execute(
            text(
                "SELECT COUNT(DISTINCT user_id) FROM app_events WHERE event_type LIKE 'select_%' AND user_id IS NOT NULL AND created_at >= :start AND created_at < :end"
            ),
            {"start": start, "end": end},
        ).scalar() or 0

        paid_users_unique = db.query(func.count(func.distinct(Order.user_id))).filter(
            Order.status == "paid",
            Order.timestamp >= start,
            Order.timestamp < end,
        ).scalar() or 0

        open_to_select = round((selects_unique / opens_unique * 100), 2) if opens_unique else 0.0
        select_to_paid = round((paid_users_unique / selects_unique * 100), 2) if selects_unique else 0.0
        open_to_created = round((created_orders / opens * 100), 2) if opens else 0.0

        top_users = (
            db.query(Order.user_id, func.sum(Order.amount_rub).label("total"))
            .filter(Order.status == "paid", Order.timestamp >= start, Order.timestamp < end)
            .group_by(Order.user_id)
            .order_by(desc(func.sum(Order.amount_rub)))
            .limit(10)
            .all()
        )
        top_items = []
        if top_users:
            ids = [u.user_id for u in top_users]
            users = db.query(User).filter(User.user_id.in_(ids)).all()
            user_map = {}
            for u in users:
                if u.username:
                    user_map[u.user_id] = f"@{u.username}"
                elif u.full_name:
                    user_map[u.user_id] = u.full_name
            for uid, total in top_users:
                top_items.append({
                    "user_id": uid,
                    "display": user_map.get(uid),
                    "revenue_rub": round(float(total or 0), 2),
                })

        return {
            "period_start": start_msk.strftime("%Y-%m-%d"),
            "period_end": end_msk.strftime("%Y-%m-%d"),
            "opens": int(opens),
            "opens_unique": int(opens_unique),
            "selects": int(selects),
            "selects_unique": int(selects_unique),
            "created_orders": created_orders,
            "paid_orders": len(paid_orders),
            "failed_orders": failed_orders,
            "conversion_paid_pct": conversion,
            "conversion_open_to_created_pct": open_to_created,
            "conversion_open_to_select_pct": open_to_select,
            "conversion_select_to_paid_pct": select_to_paid,
            "paid_total_rub": round(paid_total, 2),
            "cost_total_rub": round(total_cost, 2),
            "profit_total_rub": round(total_profit, 2),
            "cost_rate_label": rate_label,
            "usdtrub_rate": round(float(usdtrub), 2) if usdtrub is not None else None,
            "avg_check_rub": round(avg_check, 2),
            "stars_total": int(stars_total),
            "bonus_total": int(bonus_total),
            "by_provider": by_provider,
            "revenue_by_provider": revenue_by_provider,
            "provider_conversion_pct": provider_conversion,
            "top_users_by_revenue": top_items,
        }
    finally:
        db.close()


@app.get("/admin/analytics/daily")
async def admin_analytics_daily(request: Request, days: int = 30):
    _admin_require(request)
    days = max(1, min(days, 120))
    db = SessionLocal()
    try:
        now = now_msk()
        start_msk = (now - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
        end_msk = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        start = start_msk.astimezone(timezone.utc)
        end = end_msk.astimezone(timezone.utc)

        orders = db.query(Order).filter(
            Order.status == "paid",
            Order.timestamp >= start,
            Order.timestamp < end,
        ).all()

        need_cost_calc = any((o.cost_rub is None or o.profit_rub is None) for o in orders)
        usdtrub = None
        if need_cost_calc:
            usdtrub = await get_moex_usdrub_rate() if STAR_COST_RATE_SOURCE == "moex" else await get_usdtrub_rate()

        daily = {}
        for o in orders:
            key = o.timestamp.astimezone(MSK).date().isoformat()
            if key not in daily:
                daily[key] = {"revenue": 0.0, "cost": 0.0, "profit": 0.0, "orders": 0}
            revenue = _round_money(o.amount_rub) or 0
            cost = o.cost_rub
            profit = o.profit_rub
            if (cost is None or profit is None) and usdtrub is not None:
                total_stars = int(o.quantity or 0) + int(o.bonus_stars_applied or 0)
                if total_stars > 0:
                    cost_usd = total_stars * (STAR_COST_USD_PER_100 / 100.0)
                    cost = _round_money(cost_usd * usdtrub) or 0
                    profit = _round_money(revenue - cost) or 0
                    o.cost_rub = cost
                    o.profit_rub = profit
                    o.cost_per_star = _round_money(cost / total_stars) if total_stars else 0
                    o.usdtrub_rate = _round_money(usdtrub) or 0
            daily[key]["revenue"] += revenue
            daily[key]["cost"] += cost or 0
            daily[key]["profit"] += profit or 0
            daily[key]["orders"] += 1

        if need_cost_calc:
            try:
                db.commit()
            except Exception:
                db.rollback()

        items = []
        for i in range(days):
            day = (start_msk.date() + timedelta(days=i)).isoformat()
            row = daily.get(day, {"revenue": 0.0, "cost": 0.0, "profit": 0.0, "orders": 0})
            items.append({
                "date": day,
                "revenue": round(row["revenue"], 2),
                "cost": round(row["cost"], 2),
                "profit": round(row["profit"], 2),
                "orders": row["orders"],
            })
        return {"items": items}
    finally:
        db.close()


@app.get("/admin/users/search")
async def admin_users_search(request: Request, q: str | None = Query(default=None), days: int = 30, limit: int = 50):
    _admin_require(request)
    days = max(1, min(days, 365))
    limit = max(1, min(limit, 200))
    db = SessionLocal()
    try:
        now = now_msk()
        start_msk = (now - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
        end_msk = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        start = start_msk.astimezone(timezone.utc)
        end = end_msk.astimezone(timezone.utc)

        ids = set()
        query = (q or "").strip()
        if query:
            qnorm = query[1:] if query.startswith("@") else query
            if qnorm.isdigit():
                ids.add(qnorm)
            users = db.query(User).filter(
                or_(
                    User.user_id == qnorm,
                    User.username.ilike(f"%{qnorm}%"),
                    User.full_name.ilike(f"%{qnorm}%"),
                )
            ).all()
            for u in users:
                ids.add(u.user_id)
            if not ids:
                return {"items": []}

        q_orders = db.query(Order).filter(
            Order.status == "paid",
            Order.timestamp >= start,
            Order.timestamp < end,
        )
        if ids:
            q_orders = q_orders.filter(Order.user_id.in_(list(ids)))
        orders = q_orders.all()

        need_cost_calc = any((o.cost_rub is None or o.profit_rub is None) for o in orders)
        usdtrub = None
        if need_cost_calc:
            usdtrub = await get_moex_usdrub_rate() if STAR_COST_RATE_SOURCE == "moex" else await get_usdtrub_rate()

        agg = {}
        for o in orders:
            uid = o.user_id
            if uid not in agg:
                agg[uid] = {"revenue": 0.0, "cost": 0.0, "profit": 0.0, "orders": 0, "stars": 0}
            revenue = _round_money(o.amount_rub) or 0
            cost = o.cost_rub
            profit = o.profit_rub
            if (cost is None or profit is None) and usdtrub is not None:
                total_stars = int(o.quantity or 0) + int(o.bonus_stars_applied or 0)
                if total_stars > 0:
                    cost_usd = total_stars * (STAR_COST_USD_PER_100 / 100.0)
                    cost = _round_money(cost_usd * usdtrub) or 0
                    profit = _round_money(revenue - cost) or 0
                    o.cost_rub = cost
                    o.profit_rub = profit
                    o.cost_per_star = _round_money(cost / total_stars) if total_stars else 0
                    o.usdtrub_rate = _round_money(usdtrub) or 0
            agg[uid]["revenue"] += revenue
            agg[uid]["cost"] += cost or 0
            agg[uid]["profit"] += profit or 0
            agg[uid]["orders"] += 1
            agg[uid]["stars"] += int(o.quantity or 0) + int(o.bonus_stars_applied or 0)

        if need_cost_calc:
            try:
                db.commit()
            except Exception:
                db.rollback()

        users = db.query(User).filter(User.user_id.in_(list(agg.keys()))).all() if agg else []
        user_map = {}
        for u in users:
            if u.username:
                user_map[u.user_id] = f"@{u.username}"
            elif u.full_name:
                user_map[u.user_id] = u.full_name

        items = []
        for uid, row in agg.items():
            items.append({
                "user_id": uid,
                "display": user_map.get(uid),
                "revenue": round(row["revenue"], 2),
                "cost": round(row["cost"], 2),
                "profit": round(row["profit"], 2),
                "orders": row["orders"],
                "stars": row["stars"],
            })
        items.sort(key=lambda x: x["profit"], reverse=True)
        return {"items": items[:limit]}
    finally:
        db.close()


@app.get("/admin/promos")
async def admin_promos(request: Request, filter: str | None = Query(default=None)):
    _admin_require(request)
    db = SessionLocal()
    try:
        promos = db.query(PromoCode).order_by(PromoCode.code.asc()).all()
        now = now_msk()
        items = []
        for p in promos:
            expired = bool(p.expires_at and p.expires_at <= now)
            used_up = bool(p.max_uses is not None and p.uses >= p.max_uses)
            status = "active"
            if not p.active:
                status = "disabled"
            elif expired:
                status = "expired"
            elif used_up:
                status = "used"
            if filter == "active" and status != "active":
                continue
            if filter == "expired" and status != "expired":
                continue
            if filter == "used" and status != "used":
                continue
            items.append({
                "code": p.code,
                "percent": p.percent,
                "max_uses": p.max_uses,
                "uses": p.uses,
                "active": p.active,
                "expires_at": p.expires_at.isoformat() if p.expires_at else None,
                "status": status,
            })
        return {"items": items}
    finally:
        db.close()


@app.get("/admin/bonuses")
async def admin_bonuses(request: Request):
    _admin_require(request)
    db = SessionLocal()
    try:
        bonuses = db.query(BonusGrant).order_by(BonusGrant.created_at.desc()).limit(300).all()
        items = []
        for b in bonuses:
            items.append({
                "user_id": b.user_id,
                "stars": b.stars,
                "status": b.status,
                "source": b.source,
                "expires_at": b.expires_at.isoformat() if b.expires_at else None,
                "created_at": b.created_at.isoformat() if b.created_at else None,
                "consumed_at": b.consumed_at.isoformat() if b.consumed_at else None,
                "consumed_order_id": b.consumed_order_id,
            })
        return {"items": items}
    finally:
        db.close()


@app.post("/admin/raffle/reset")
async def admin_raffle_reset(request: Request):
    _admin_require(request)
    db = SessionLocal()
    try:
        now = now_msk().isoformat()
        row = db.query(AdminSetting).filter(AdminSetting.key == "RAFFLE_RESET_AT").first()
        if not row:
            row = AdminSetting(key="RAFFLE_RESET_AT", value=now)
            db.add(row)
        else:
            row.value = now
            row.updated_at = now_msk()
        db.commit()
        return {"status": "ok", "reset_at": now}
    finally:
        db.close()


@app.post("/admin/raffle/recalc")
async def admin_raffle_recalc(request: Request):
    _admin_require(request)
    db = SessionLocal()
    try:
        now = now_msk()
        period_start, period_end = _raffle_period(now)
        totals = (
            db.query(
                Order.user_id.label("user_id"),
                func.sum(Order.quantity).label("total")
            )
            .filter(
                Order.status == "paid",
                Order.product_type == "stars",
                Order.timestamp >= period_start,
                Order.timestamp < period_end,
            )
            .group_by(Order.user_id)
            .subquery()
        )
        top_rows = (
            db.query(totals.c.user_id, totals.c.total)
            .order_by(desc(totals.c.total))
            .limit(10)
            .all()
        )
        total_all = db.query(func.sum(totals.c.total)).scalar() or 0
        items = []
        for row in top_rows:
            total = int(row.total or 0)
            chance = 0.0
            if total_all:
                chance = float(Decimal(str(total / total_all * 100)).quantize(Decimal("0.01")))
            items.append({"user_id": row.user_id, "total_stars": total, "chance_percent": chance})
        stamp = now_msk().isoformat()
        row = db.query(AdminSetting).filter(AdminSetting.key == "RAFFLE_RECALC_AT").first()
        if not row:
            row = AdminSetting(key="RAFFLE_RECALC_AT", value=stamp)
            db.add(row)
        else:
            row.value = stamp
            row.updated_at = now_msk()
        db.commit()
        return {"status": "ok", "recalc_at": stamp, "top": items}
    finally:
        db.close()


@app.get("/admin/raffle/summary")
async def admin_raffle_summary(request: Request):
    _admin_require(request)
    db = SessionLocal()
    try:
        now = now_msk()
        period_start, period_end = _raffle_period(now)
        totals = (
            db.query(
                Order.user_id.label("user_id"),
                func.sum(Order.quantity).label("total")
            )
            .filter(
                Order.status == "paid",
                Order.product_type == "stars",
                Order.timestamp >= period_start,
                Order.timestamp < period_end,
            )
            .group_by(Order.user_id)
            .subquery()
        )
        all_rows = db.query(totals.c.user_id, totals.c.total).all()
        total_all = db.query(func.sum(totals.c.total)).scalar() or 0
        is_draw_day = now.day in (15, 30)
        winner = None
        if is_draw_day and total_all and all_rows:
            seed = f"raffle-{now.date().isoformat()}-{period_start.date().isoformat()}"
            rng = random.Random(seed)
            pick = rng.uniform(0, float(total_all))
            acc = 0.0
            for row in all_rows:
                weight = float(row.total or 0)
                acc += weight
                if pick <= acc:
                    winner = {"user_id": row.user_id, "total_stars": int(row.total or 0)}
                    break
            if winner is None and all_rows:
                row = all_rows[0]
                winner = {"user_id": row.user_id, "total_stars": int(row.total or 0)}
        return {
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "total_participants": int(db.query(func.count()).select_from(totals).scalar() or 0),
            "total_stars": int(total_all or 0),
            "draw_day": is_draw_day,
            "winner": winner,
        }
    finally:
        db.close()


@app.get("/admin/raffle/participants")
async def admin_raffle_participants(request: Request, format: str | None = Query(default=None)):
    _admin_require(request)
    db = SessionLocal()
    try:
        now = now_msk()
        period_start, period_end = _raffle_period(now)
        totals = (
            db.query(
                Order.user_id.label("user_id"),
                func.sum(Order.quantity).label("total")
            )
            .filter(
                Order.status == "paid",
                Order.product_type == "stars",
                Order.timestamp >= period_start,
                Order.timestamp < period_end,
            )
            .group_by(Order.user_id)
            .subquery()
        )
        rows = db.query(totals.c.user_id, totals.c.total).order_by(desc(totals.c.total)).all()
        total_all = db.query(func.sum(totals.c.total)).scalar() or 0
        ids = [r.user_id for r in rows]
        user_map = {}
        if ids:
            users = db.query(User).filter(User.user_id.in_(ids)).all()
            for u in users:
                if u.username:
                    user_map[u.user_id] = f"@{u.username}"
                elif u.full_name:
                    user_map[u.user_id] = u.full_name
        items = []
        for r in rows:
            total = int(r.total or 0)
            chance = 0.0
            if total_all:
                chance = float(Decimal(str(total / total_all * 100)).quantize(Decimal("0.01")))
            items.append({
                "user_id": r.user_id,
                "username": user_map.get(r.user_id),
                "total_stars": total,
                "chance_percent": chance,
            })
        if (format or "").lower() == "csv":
            lines = ["user_id,username,total_stars,chance_percent"]
            for item in items:
                username = (item["username"] or "").replace(",", " ")
                lines.append(f"{item['user_id']},{username},{item['total_stars']},{item['chance_percent']}")
            return PlainTextResponse("\n".join(lines), media_type="text/csv")
        return {"items": items}
    finally:
        db.close()


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
        invited_count = db.query(User).filter(User.referrer_id == user_id).count()
        return {
            "referral_balance_stars": user.referral_balance_stars or 0,
            "referrer_id": user.referrer_id,
            "invited_count": invited_count,
            "bonus_balance_stars": bonus["bonus_stars"],
            "bonus_expires_at": bonus["bonus_expires_at"]
        }
    finally:
        db.close()


@app.get("/raffle/summary")
async def raffle_summary(user_id: str = Query(...)):
    db = SessionLocal()
    try:
        now = now_msk()
        period_start, period_end = _raffle_period(now)
        totals = (
            db.query(
                Order.user_id.label("user_id"),
                func.sum(Order.quantity).label("total")
            )
            .filter(
                Order.status == "paid",
                Order.product_type == "stars",
                Order.timestamp >= period_start,
                Order.timestamp < period_end,
            )
            .group_by(Order.user_id)
            .subquery()
        )

        top_rows = (
            db.query(totals.c.user_id, totals.c.total)
            .order_by(desc(totals.c.total))
            .limit(10)
            .all()
        )
        all_rows = db.query(totals.c.user_id, totals.c.total).all()

        user_total = db.query(totals.c.total).filter(totals.c.user_id == user_id).scalar() or 0
        total_all = db.query(func.sum(totals.c.total)).scalar() or 0

        rank = None
        if user_total:
            higher = db.query(func.count()).select_from(totals).filter(totals.c.total > user_total).scalar() or 0
            rank = int(higher) + 1

        ids = {row.user_id for row in top_rows}
        if user_id:
            ids.add(user_id)

        user_map = {}
        if ids:
            users = db.query(User).filter(User.user_id.in_(list(ids))).all()
            for u in users:
                if u.username:
                    user_map[u.user_id] = f"@{u.username}"
                elif u.full_name:
                    user_map[u.user_id] = u.full_name

        top = []
        for row in top_rows:
            total = int(row.total or 0)
            chance = 0.0
            if total_all:
                chance = float(Decimal(str(total / total_all * 100)).quantize(Decimal("0.01")))
            top.append({
                "user_id": row.user_id,
                "display": user_map.get(row.user_id),
                "total_stars": total,
                "chance_percent": chance,
            })

        next_draws = [d.isoformat() for d in _next_draw_dates(now)]
        is_draw_day = now.day in (15, 30)
        chance_percent = 0.0
        if total_all and user_total:
            chance_percent = float(Decimal(str(user_total / total_all * 100)).quantize(Decimal("0.01")))

        prize = {
            "title": _get_setting(db, "RAFFLE_PRIZE_TITLE", "NFT-подарок или бонусные звёзды"),
            "description": _get_setting(db, "RAFFLE_PRIZE_DESC", "Победитель получит приз после розыгрыша."),
            "image": _get_setting(db, "RAFFLE_PRIZE_IMAGE", ""),
        }

        winner = None
        if is_draw_day and total_all and all_rows:
            seed = f"raffle-{now.date().isoformat()}-{period_start.date().isoformat()}"
            rng = random.Random(seed)
            pick = rng.uniform(0, float(total_all))
            acc = 0.0
            for row in all_rows:
                weight = float(row.total or 0)
                acc += weight
                if pick <= acc:
                    winner = {
                        "user_id": row.user_id,
                        "display": user_map.get(row.user_id),
                        "total_stars": int(row.total or 0),
                        "chance_percent": float(Decimal(str((row.total or 0) / total_all * 100)).quantize(Decimal("0.01"))) if total_all else 0.0,
                    }
                    break
            if winner is None:
                row = all_rows[0]
                winner = {
                    "user_id": row.user_id,
                    "display": user_map.get(row.user_id),
                    "total_stars": int(row.total or 0),
                    "chance_percent": float(Decimal(str((row.total or 0) / total_all * 100)).quantize(Decimal("0.01"))) if total_all else 0.0,
                }

        return {
            "next_draws": next_draws,
            "top": top,
            "user": {
                "user_id": user_id,
                "display": user_map.get(user_id),
                "total_stars": int(user_total or 0),
                "rank": rank,
                "chance_percent": chance_percent,
            },
            "prize": prize,
            "draw_day": is_draw_day,
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "winner": winner,
            "total_participants": int(db.query(func.count()).select_from(totals).scalar() or 0),
            "total_stars": int(total_all or 0),
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
