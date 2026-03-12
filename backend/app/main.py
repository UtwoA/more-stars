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
from sqlalchemy import text, and_, or_, func, desc
from zoneinfo import ZoneInfo

from .config import (
    ADMIN_CHAT_IDS,
    ADMIN_OTP_TTL_MIN,
    ADMIN_REPORT_TIME,
    API_AUTH_KEY,
    BOT_TOKEN,
    MSK,
    REFERRAL_PERCENT,
    STAR_COST_RATE_SOURCE,
    STAR_COST_USD_PER_100,
)
from .admin_notify import notify_admin
from .audit import (
    format_audit_line,
    format_audit_line_with_user,
    format_gift_audit_line_with_user,
    format_payment_method,
)
from .api.admin import router as admin_router
from .api.public import router as public_router
from .api.orders import build_orders_router
from .api.webhooks import build_webhooks_router
from .admin_panel import render_admin_panel
from . import admin_auth
from .crypto_pay import verify_signature
from .crypto import convert_rub_to_crypto, convert_to_rub, get_usdtrub_rate, get_moex_usdrub_rate
from .database import SessionLocal, Base, engine
from .db_init import init_schema
from .money import round_money, to_nano
from .og_meta import parse_og_meta
from .bonus_service import bonus_summary
from .models import Order, User, PromoCode, PromoRedemption, PromoReservation, ReferralEarning, PaymentTransaction, BonusGrant, BonusClaim, BonusClaimRedemption, AdminSetting, GiftCatalog
from .promo_service import (
    get_active_reservation,
    load_promo,
    promo_used_by_user,
    reserve_promo,
)
from .raffle_utils import next_draw_dates, raffle_period
from .rate_limit import RateLimiter
from .schemas import (
    AdminBonusBulkPayload,
    AdminBonusClaimPayload,
    AdminOtpVerify,
    AdminPromoPayload,
    AdminSettingsPayload,
    AnalyticsEventPayload,
    CryptoOrderCreate,
    OrderCreateBase,
    PlategaOrderCreate,
    RobokassaOrderCreate,
    TonConnectOrderCreate,
)
from .security import constant_time_eq
from .telegram_initdata import (
    extract_user_id,
    touch_user_from_initdata,
    verify_telegram_init_data,
)
from .settings_store import get_report_time, get_setting, get_setting_float, get_setting_int
from .utils import now_msk
from .robokassa_service import verify_result_signature
from .fragment import send_purchase_to_fragment
from .gifts import send_star_gift, close_gift_client
from bot import send_user_message, send_admin_message, send_user_notice, build_admin_dispatcher, get_bot


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
MINI_APP_URL = os.getenv("MINI_APP_URL")
BONUS_MIN_STARS = int(os.getenv("BONUS_MIN_STARS", "50"))
TONCENTER_API_KEY = os.getenv("TONCENTER_API_KEY")
TONCENTER_BASE_URL = os.getenv("TONCENTER_BASE_URL") or "https://toncenter.com"
TONCONNECT_WALLET_ADDRESS = os.getenv("TONCONNECT_WALLET_ADDRESS")
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "30"))
ALLOW_UNVERIFIED_INITDATA = os.getenv("ALLOW_UNVERIFIED_INITDATA", "false").lower() in ("1", "true", "yes")
ADMIN_OTP_SECRET = os.getenv("ADMIN_OTP_SECRET") or API_AUTH_KEY or "change-me"
PLATEGA_RETRY_ATTEMPTS = int(os.getenv("PLATEGA_RETRY_ATTEMPTS", "3"))
PLATEGA_RETRY_BASE = float(os.getenv("PLATEGA_RETRY_BASE", "0.6"))
PLATEGA_RETRY_JITTER = float(os.getenv("PLATEGA_RETRY_JITTER", "0.4"))
PLATEGA_NOTIFY_TTL_SECONDS = int(os.getenv("PLATEGA_NOTIFY_TTL_SECONDS", "300"))

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
logger = logging.getLogger("main")

app = FastAPI()
app.include_router(admin_router)
app.include_router(public_router)
_last_app_up: bool | None = None
_platega_client: httpx.AsyncClient | None = None
_platega_notify_last: dict[str, float] = {}


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
    if order.product_type == "gift":
        if order.gift_title:
            return f"Gift {order.gift_title}"
        if order.gift_id:
            return f"Gift #{order.gift_id}"
    return order.product_type


def _constant_time_eq(a: str, b: str) -> bool:
    return constant_time_eq(a, b)


def _verify_telegram_init_data(init_data: str) -> bool:
    return verify_telegram_init_data(init_data, bot_token=BOT_TOKEN)


def _extract_user_id(init_data: str | None) -> str | None:
    return extract_user_id(init_data)


def _touch_user_from_initdata(db, user_id: str, init_data: str | None) -> str | None:
    return touch_user_from_initdata(db, user_id=user_id, init_data=init_data, user_model=User)


def _get_setting(db, key: str, default: str) -> str:
    return get_setting(db, key, default)


def _get_setting_float(db, key: str, default: float) -> float:
    return get_setting_float(db, key, default)


def _get_setting_int(db, key: str, default: int) -> int:
    return get_setting_int(db, key, default)


def _get_report_time(db) -> time:
    return get_report_time(db)


def _round_money(value: float | None) -> float | None:
    return round_money(value)


def _parse_og_meta(html: str) -> dict:
    return parse_og_meta(html)


def _next_draw_dates(now: datetime) -> list[datetime]:
    return next_draw_dates(now)


def _raffle_period(now: datetime) -> tuple[datetime, datetime]:
    return raffle_period(now)


def _to_nano(ton_amount: float) -> int:
    return to_nano(ton_amount)


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


_rate_limiter = RateLimiter(RATE_LIMIT_PER_MIN)

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


async def _safe_send_user_notice(order: Order, text: str) -> None:
    try:
        chat_id = int(order.user_id)
    except (TypeError, ValueError):
        logger.warning("[BOT] Invalid user_id for chat_id: %s", order.user_id)
        return
    await send_user_notice(chat_id=chat_id, text=text)


async def _notify_admin(text: str) -> None:
    await notify_admin(text)


def _format_payment_method(order: Order) -> str:
    return format_payment_method(order)


def _format_audit_line(order: Order) -> str:
    return format_audit_line(order)


def _format_audit_line_with_user(order: Order, display_name: str | None) -> str:
    return format_audit_line_with_user(order, display_name)


def _format_gift_audit_line_with_user(order: Order, display_name: str | None) -> str:
    return format_gift_audit_line_with_user(order, display_name)


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


async def _send_gift_audit_if_needed(order: Order, db) -> None:
    if order.audit_sent:
        return
    if order.product_type != "gift" or order.status != "paid":
        return
    display = None
    if not order.user_username:
        user = db.query(User).filter(User.user_id == order.user_id).first()
        if user:
            display = f"@{user.username}" if user.username else user.full_name
    line = _format_gift_audit_line_with_user(order, display)
    revenue = _round_money(order.amount_rub) or 0
    text = (
        "✅ Покупка подарка\n"
        f"{line}\n"
        f"💰 Выручка: {revenue} ₽"
    )
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
                            or_(
                                and_(
                                    Order.product_type == "stars",
                                    or_(Order.fragment_status.is_(None), Order.fragment_status != "success"),
                                ),
                                and_(
                                    Order.product_type == "gift",
                                    or_(Order.gift_status.is_(None), Order.gift_status != "success"),
                                ),
                            ),
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
    init_schema(engine=engine, base=Base)
    asyncio.create_task(_daily_report_loop())
    asyncio.create_task(_availability_loop())
    asyncio.create_task(_payment_sync_loop())
    dp = build_admin_dispatcher(ADMIN_CHAT_IDS or set())
    asyncio.create_task(dp.start_polling(get_bot()))


@app.on_event("shutdown")
async def _shutdown_tasks():
    global _platega_client
    if _platega_client is not None:
        await _platega_client.aclose()
        _platega_client = None
    await close_gift_client()


async def _fulfill_order_if_needed(order: Order, db) -> None:
    if order.product_type == "gift":
        if order.status != "paid":
            return
        if (order.gift_status or "").lower() == "success":
            return

        claim = db.execute(
            text(
                """
                UPDATE orders
                SET gift_in_progress = TRUE,
                    gift_attempts = COALESCE(gift_attempts, 0) + 1
                WHERE order_id = :order_id
                  AND (gift_in_progress IS NULL OR gift_in_progress = FALSE)
                  AND (gift_status IS NULL OR gift_status != 'success')
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
                message_text = _build_gift_message(order, db)
                chat_id = order.recipient
                if isinstance(chat_id, str) and chat_id.isdigit():
                    chat_id = int(chat_id)
                await send_star_gift(
                    chat_id=chat_id,
                    gift_id=int(order.gift_id or 0),
                    text=message_text,
                    hide_my_name=order.gift_hide_name,
                    pay_for_upgrade=order.gift_pay_for_upgrade,
                )
                last_error = None
                break
            except Exception as exc:
                last_error = exc
                logger.exception("[GIFT] Failed to send gift")

        if last_error:
            err_text = str(last_error)
            if "PEER_INVALID" in err_text:
                order.gift_status = "peer_invalid"
                order.gift_last_error = err_text
                order.gift_in_progress = False
                db.commit()
                await _notify_admin(
                    f"⚠️ Gift delivery blocked (peer invalid)\n"
                    f"order_id={order.order_id}\n"
                    f"user_id={order.user_id}\n"
                    f"recipient={order.recipient}\n"
                    f"error={order.gift_last_error}"
                )
                try:
                    await _safe_send_user_notice(
                        order,
                        "Не удалось доставить подарок: получатель недоступен.\n"
                        "Укажите @username получателя или убедитесь, что аккаунт продавца уже общался с ним.",
                    )
                except Exception:
                    logger.exception("[BOT] Failed to send gift peer notice")
                return

            order.status = "failed"
            order.gift_status = "failed"
            order.gift_last_error = err_text
            order.gift_in_progress = False
            db.commit()
            _release_promo_reservation(order, db)
            await _notify_admin(
                f"❗ Gift delivery failed\n"
                f"order_id={order.order_id}\n"
                f"user_id={order.user_id}\n"
                f"error={order.gift_last_error}"
            )
            return

        order.gift_status = "success"
        order.gift_in_progress = False
        db.commit()
        try:
            await _safe_send_user_message(order)
        except Exception:
            logger.exception("[BOT] Failed to send user message")

        await _send_gift_audit_if_needed(order, db)
        _redeem_promo_if_needed(order, db)
        return

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

    _redeem_promo_if_needed(order, db)

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


def _redeem_promo_if_needed(order: Order, db) -> None:
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


def _build_gift_message(order: Order, db) -> str | None:
    base_text = (order.gift_text or "").strip()
    if not order.gift_with_signature:
        return base_text or None

    signature = (order.gift_signature or "").strip()
    if not signature:
        return base_text or None

    if base_text:
        return f"{base_text}\n— {signature}"
    return f"— {signature}"


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
    return load_promo(code, db)


def _get_active_reservation(code: str, user_id: str, db) -> PromoReservation | None:
    return get_active_reservation(code, user_id, db)


def _promo_used_by_user(code: str, user_id: str, db) -> bool:
    return promo_used_by_user(code, user_id, db)


def _bonus_summary(db, user_id: str) -> dict:
    return bonus_summary(db, user_id)


def _reserve_promo(code: str, user_id: str, db) -> PromoReservation | None:
    return reserve_promo(code, user_id, db)


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


def _get_platega_client() -> httpx.AsyncClient:
    global _platega_client
    if _platega_client is None:
        timeout = httpx.Timeout(connect=5.0, read=15.0, write=15.0, pool=5.0)
        limits = httpx.Limits(max_keepalive_connections=10, max_connections=20)
        _platega_client = httpx.AsyncClient(timeout=timeout, limits=limits)
    return _platega_client


def _platega_should_notify(key: str) -> bool:
    now_ts = asyncio.get_event_loop().time()
    last = _platega_notify_last.get(key)
    if last and now_ts - last < PLATEGA_NOTIFY_TTL_SECONDS:
        return False
    _platega_notify_last[key] = now_ts
    return True


async def _platega_request(method: str, url: str, *, headers: dict, json_body: dict | None, order_id: str, action: str) -> httpx.Response:
    retry_statuses = {502, 503, 504, 520, 521, 522, 523, 524}
    last_exc: Exception | None = None

    for attempt in range(1, PLATEGA_RETRY_ATTEMPTS + 1):
        try:
            client = _get_platega_client()
            if json_body is None:
                r = await client.request(method, url, headers=headers)
            else:
                r = await client.request(method, url, headers=headers, json=json_body)
            if r.status_code in retry_statuses and attempt < PLATEGA_RETRY_ATTEMPTS:
                delay = (PLATEGA_RETRY_BASE * (2 ** (attempt - 1))) + random.uniform(0, PLATEGA_RETRY_JITTER)
                await asyncio.sleep(delay)
                continue
            return r
        except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.ConnectError, httpx.RemoteProtocolError) as exc:
            last_exc = exc
            if attempt < PLATEGA_RETRY_ATTEMPTS:
                delay = (PLATEGA_RETRY_BASE * (2 ** (attempt - 1))) + random.uniform(0, PLATEGA_RETRY_JITTER)
                await asyncio.sleep(delay)
                continue
            break

    if last_exc is None:
        last_exc = RuntimeError("PLATEGA request failed without response")
    if _platega_should_notify(f"{action}:{order_id}"):
        await notify_admin(f"[PLATEGA] {action} failed for order {order_id}: {type(last_exc).__name__}")
    raise last_exc


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

    r = await _platega_request(
        "POST",
        f"{PLATEGA_BASE_URL}/transaction/process",
        headers=headers,
        json_body=payload,
        order_id=order_id,
        action="create_payment",
    )
    if r.status_code >= 400:
        logger.error("[PLATEGA] Create payment failed: %s %s", r.status_code, r.text)
        if r.status_code >= 500 and _platega_should_notify(f"create_payment_http:{order_id}"):
            await notify_admin(f"[PLATEGA] create_payment HTTP {r.status_code} for order {order_id}")
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

    r = await _platega_request(
        "GET",
        f"{PLATEGA_BASE_URL}/transaction/{transaction_id}",
        headers=headers,
        json_body=None,
        order_id=order_id or transaction_id,
        action="get_status",
    )
    if r.status_code >= 400:
        logger.error("[PLATEGA] Status request failed: %s %s", r.status_code, r.text)
        if r.status_code >= 500 and _platega_should_notify(f"get_status_http:{order_id or transaction_id}"):
            await notify_admin(f"[PLATEGA] get_status HTTP {r.status_code} for order {order_id or transaction_id}")
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
    ttl_minutes = 10
    if provider == "tg_stars":
        ttl_minutes = int(os.getenv("TG_STARS_ORDER_TTL_MIN", "1440"))

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
        gift_id=order_in.gift_id,
        gift_title=getattr(order_in, "gift_title", None),
        gift_text=order_in.gift_text,
        gift_hide_name=order_in.gift_hide_name,
        gift_pay_for_upgrade=order_in.gift_pay_for_upgrade,
        gift_with_signature=order_in.gift_with_signature,
        gift_signature=order_in.gift_signature,
        currency=currency or "RUB",
        status="created",
        payment_provider=provider,
        payment_method=payment_method,
        timestamp=now_msk(),
        expires_at=now_msk() + timedelta(minutes=ttl_minutes)
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


def _include_orders_and_webhooks() -> None:
    from types import SimpleNamespace

    ctx = SimpleNamespace(
        SessionLocal=SessionLocal,
        Order=Order,
        PromoReservation=PromoReservation,
        GiftCatalog=GiftCatalog,
        MSK=MSK,
        PLATEGA_PAYMENT_METHOD=PLATEGA_PAYMENT_METHOD,
        TONCONNECT_WALLET_ADDRESS=TONCONNECT_WALLET_ADDRESS,
        PLATEGA_MERCHANT_ID=PLATEGA_MERCHANT_ID,
        PLATEGA_SECRET=PLATEGA_SECRET,
        PLATEGA_WEBHOOK_SIGNING_SECRET=PLATEGA_WEBHOOK_SIGNING_SECRET,
        PLATEGA_WEBHOOK_IP_ALLOWLIST=PLATEGA_WEBHOOK_IP_ALLOWLIST,
        PLATEGA_WEBHOOK_TOKEN=PLATEGA_WEBHOOK_TOKEN,
        logger=logger,
        convert_rub_to_crypto=convert_rub_to_crypto,
        _stars_base_price=_stars_base_price,
        _get_active_reservation=_get_active_reservation,
        _round_money=_round_money,
        _touch_user_from_initdata=_touch_user_from_initdata,
        _create_order=_create_order,
        _reserve_bonus_for_order=_reserve_bonus_for_order,
        _create_crypto_invoice=_create_crypto_invoice,
        _create_platega_payment_with_method=_create_platega_payment_with_method,
        _to_nano=_to_nano,
        _sync_crypto_order_status=_sync_crypto_order_status,
        _sync_platega_order_status=_sync_platega_order_status,
        _sync_tonconnect_order_status=_sync_tonconnect_order_status,
        _check_order_expired=_check_order_expired,
        _notify_admin=_notify_admin,
        _constant_time_eq=_constant_time_eq,
        _client_ip=_client_ip,
        _extract_order_id=_extract_order_id,
        _release_promo_reservation=_release_promo_reservation,
        _release_bonus_reservation=_release_bonus_reservation,
        _fulfill_order_if_needed=_fulfill_order_if_needed,
    )

    app.include_router(build_orders_router(ctx))
    app.include_router(build_webhooks_router(ctx))


_include_orders_and_webhooks()


@app.get("/admin/panel", response_class=HTMLResponse)
async def admin_panel(request: Request):
    token = request.cookies.get("admin_otp")
    authed = admin_auth.session_valid(token)
    return render_admin_panel(authed)


@app.get("/robokassa/success")
async def robokassa_success():
    return "<html><body><script>window.location.href='/'</script></body></html>"


@app.get("/robokassa/fail")
async def robokassa_fail():
    return "<html><body><script>window.location.href='/'</script></body></html>"
