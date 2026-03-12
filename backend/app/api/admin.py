import random
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from fastapi import APIRouter, Header, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import desc, func, or_, text

from .. import admin_auth
from ..audit import format_audit_line_with_user, format_gift_audit_line_with_user
from ..config import (
    ADMIN_REPORT_TIME,
    API_AUTH_KEY,
    MSK,
    REFERRAL_PERCENT,
    STAR_COST_RATE_SOURCE,
    STAR_COST_USD_PER_100,
)
from ..crypto import get_moex_usdrub_rate, get_usdtrub_rate
from ..database import SessionLocal
from ..money import round_money
from ..models import AdminSetting, BonusClaim, BonusGrant, Order, PromoCode, User, GiftCatalog
from ..raffle_utils import raffle_period
from ..schemas import (
    AdminBonusBulkPayload,
    AdminBonusClaimPayload,
    AdminOtpVerify,
    AdminPromoPayload,
    AdminSettingsPayload,
    AdminGiftPayload,
)
from ..security import constant_time_eq
from ..settings_store import get_setting, get_setting_float, get_setting_int
from ..utils import now_msk

router = APIRouter()
logger = logging.getLogger("admin_api")


@router.post("/admin/otp/request")
async def admin_otp_request():
    return await admin_auth.otp_request()


@router.post("/admin/otp/verify")
async def admin_otp_verify(payload: AdminOtpVerify):
    return await admin_auth.otp_verify(payload)


@router.get("/admin/settings")
async def admin_settings(request: Request):
    admin_auth.require_admin(request)
    db = SessionLocal()
    try:
        return {
            "referral_percent": get_setting_int(db, "REFERRAL_PERCENT", REFERRAL_PERCENT),
            "report_time": get_setting(db, "ADMIN_REPORT_TIME", ADMIN_REPORT_TIME),
            "stars_rate_1": get_setting_float(db, "STARS_RATE_1", 1.39),
            "stars_rate_2": get_setting_float(db, "STARS_RATE_2", 1.37),
            "stars_rate_3": get_setting_float(db, "STARS_RATE_3", 1.35),
            "raffle_prize_title": get_setting(db, "RAFFLE_PRIZE_TITLE", "NFT-подарок или бонусные звёзды"),
            "raffle_prize_desc": get_setting(db, "RAFFLE_PRIZE_DESC", "Победитель получит приз после розыгрыша."),
            "raffle_prize_image": get_setting(db, "RAFFLE_PRIZE_IMAGE", ""),
            "banner_enabled": get_setting(db, "BANNER_ENABLED", "false").lower() in ("1", "true", "yes"),
            "banner_title": get_setting(db, "BANNER_TITLE", ""),
            "banner_text": get_setting(db, "BANNER_TEXT", ""),
            "banner_url": get_setting(db, "BANNER_URL", ""),
            "banner_until": get_setting(db, "BANNER_UNTIL", ""),
            "promo_text": get_setting(db, "PROMO_TEXT", ""),
        }
    finally:
        db.close()


@router.post("/admin/settings")
async def admin_settings_update(request: Request, payload: AdminSettingsPayload):
    admin_auth.require_admin(request)
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


@router.post("/admin/promo/create")
async def admin_promo_create(request: Request, payload: AdminPromoPayload):
    admin_auth.require_admin(request)
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
                expires_at=expires_at,
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


@router.post("/admin/bonus/claim")
async def admin_bonus_claim(request: Request, payload: AdminBonusClaimPayload):
    admin_auth.require_admin(request)
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
            expires_at=expires_at,
        )
        db.add(claim)
        db.commit()
        return {
            "status": "ok",
            "token": token,
            "link": f"https://t.me/more_stars_bot?start=bonus_{token}",
            "expires_at": expires_at.isoformat() if expires_at else None,
        }
    finally:
        db.close()


@router.post("/admin/bonus/grant_bulk")
async def admin_bonus_grant_bulk(request: Request, payload: AdminBonusBulkPayload):
    admin_auth.require_admin(request)
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


@router.get("/admin/gifts")
async def admin_gifts_list(request: Request):
    admin_auth.require_admin(request)
    db = SessionLocal()
    try:
        gifts = db.query(GiftCatalog).order_by(GiftCatalog.sort_order.asc().nulls_last(), GiftCatalog.id.asc()).all()
        return {
            "gifts": [
                {
                    "gift_id": str(g.gift_id),
                    "title": g.title,
                    "price_rub": g.price_rub,
                    "price_stars": g.price_stars,
                    "image_url": g.image_url,
                    "sort_order": g.sort_order,
                    "active": bool(g.active),
                }
                for g in gifts
            ]
        }
    finally:
        db.close()


@router.post("/admin/gifts")
async def admin_gifts_upsert(request: Request, payload: AdminGiftPayload):
    admin_auth.require_admin(request)
    db = SessionLocal()
    try:
        gift = db.query(GiftCatalog).filter(GiftCatalog.gift_id == payload.gift_id).first()
        if not gift:
            gift = GiftCatalog(
                gift_id=payload.gift_id,
                title=payload.title.strip(),
                price_rub=payload.price_rub,
                price_stars=payload.price_stars,
                image_url=payload.image_url,
                sort_order=payload.sort_order,
                active=payload.active,
            )
            db.add(gift)
        else:
            gift.title = payload.title.strip()
            gift.price_rub = payload.price_rub
            gift.price_stars = payload.price_stars
            gift.image_url = payload.image_url
            gift.sort_order = payload.sort_order
            gift.active = payload.active
            gift.updated_at = now_msk()
        db.commit()
        return {"status": "ok", "gift_id": gift.gift_id}
    except Exception:
        logger.exception("[ADMIN] Failed to upsert gift")
        raise
    finally:
        db.close()


@router.get("/admin/audit/today")
async def admin_audit_today(request: Request):
    admin_auth.require_admin(request)
    now = now_msk()
    since = now - timedelta(hours=24)
    db = SessionLocal()
    try:
        orders = (
            db.query(Order)
            .filter(
                Order.product_type == "stars",
                Order.status == "paid",
                Order.timestamp >= since,
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
    items = [format_audit_line_with_user(o, user_map.get(o.user_id)) for o in orders]
    return {"items": items}


@router.get("/admin/audit/recent")
async def admin_audit_recent(request: Request, limit: int = 200):
    admin_auth.require_admin(request)
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
    items = [format_audit_line_with_user(o, user_map.get(o.user_id)) for o in orders]
    return {"items": items}


@router.get("/admin/audit/gifts/today")
async def admin_audit_gifts_today(request: Request):
    admin_auth.require_admin(request)
    now = now_msk()
    since = now - timedelta(hours=24)
    db = SessionLocal()
    try:
        orders = (
            db.query(Order)
            .filter(
                Order.product_type == "gift",
                Order.status == "paid",
                Order.timestamp >= since,
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
    items = [format_gift_audit_line_with_user(o, user_map.get(o.user_id)) for o in orders]
    return {"items": items}


@router.get("/admin/audit/gifts/recent")
async def admin_audit_gifts_recent(request: Request, limit: int = 200):
    admin_auth.require_admin(request)
    db = SessionLocal()
    try:
        orders = (
            db.query(Order)
            .filter(
                Order.product_type == "gift",
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
    items = [format_gift_audit_line_with_user(o, user_map.get(o.user_id)) for o in orders]
    return {"items": items}


@router.get("/admin/analytics")
async def admin_analytics(request: Request):
    admin_auth.require_admin(request)
    db = SessionLocal()
    try:
        now = now_msk()
        start_msk = now - timedelta(days=30)
        end_msk = now
        start = start_msk.astimezone(timezone.utc)
        end = end_msk.astimezone(timezone.utc)

        created_orders = (
            db.query(Order)
            .filter(
                Order.timestamp >= start,
                Order.timestamp < end,
            )
            .count()
        )
        paid_orders_q = db.query(Order).filter(
            Order.status == "paid",
            Order.timestamp >= start,
            Order.timestamp < end,
        )
        paid_orders = paid_orders_q.all()
        failed_orders = (
            db.query(Order)
            .filter(
                Order.status == "failed",
                Order.timestamp >= start,
                Order.timestamp < end,
            )
            .count()
        )

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
            cost_rub = round_money(cost_usd * usdtrub) or 0
            revenue = round_money(o.amount_rub) or 0
            profit = round_money(revenue - cost_rub) or 0
            per_star = round_money(cost_rub / total_stars) if total_stars else 0
            o.cost_rub = cost_rub
            o.profit_rub = profit
            o.cost_per_star = per_star
            o.usdtrub_rate = round_money(usdtrub) or 0
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

        opens = (
            db.execute(
                text(
                    "SELECT COUNT(*) FROM app_events WHERE event_type = 'open' AND created_at >= :start AND created_at < :end"
                ),
                {"start": start, "end": end},
            ).scalar()
            or 0
        )
        opens_unique = (
            db.execute(
                text(
                    "SELECT COUNT(DISTINCT user_id) FROM app_events WHERE event_type = 'open' AND user_id IS NOT NULL AND created_at >= :start AND created_at < :end"
                ),
                {"start": start, "end": end},
            ).scalar()
            or 0
        )
        selects = (
            db.execute(
                text(
                    "SELECT COUNT(*) FROM app_events WHERE event_type LIKE 'select_%' AND created_at >= :start AND created_at < :end"
                ),
                {"start": start, "end": end},
            ).scalar()
            or 0
        )
        selects_unique = (
            db.execute(
                text(
                    "SELECT COUNT(DISTINCT user_id) FROM app_events WHERE event_type LIKE 'select_%' AND user_id IS NOT NULL AND created_at >= :start AND created_at < :end"
                ),
                {"start": start, "end": end},
            ).scalar()
            or 0
        )

        paid_users_unique = (
            db.query(func.count(func.distinct(Order.user_id)))
            .filter(
                Order.status == "paid",
                Order.timestamp >= start,
                Order.timestamp < end,
            )
            .scalar()
            or 0
        )

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
                top_items.append(
                    {
                        "user_id": uid,
                        "display": user_map.get(uid),
                        "revenue_rub": round(float(total or 0), 2),
                    }
                )

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


@router.get("/admin/analytics/daily")
async def admin_analytics_daily(request: Request, days: int = 30):
    admin_auth.require_admin(request)
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
            revenue = round_money(o.amount_rub) or 0
            cost = o.cost_rub
            profit = o.profit_rub
            if (cost is None or profit is None) and usdtrub is not None:
                total_stars = int(o.quantity or 0) + int(o.bonus_stars_applied or 0)
                if total_stars > 0:
                    cost_usd = total_stars * (STAR_COST_USD_PER_100 / 100.0)
                    cost = round_money(cost_usd * usdtrub) or 0
                    profit = round_money(revenue - cost) or 0
                    o.cost_rub = cost
                    o.profit_rub = profit
                    o.cost_per_star = round_money(cost / total_stars) if total_stars else 0
                    o.usdtrub_rate = round_money(usdtrub) or 0
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
            items.append(
                {
                    "date": day,
                    "revenue": round(row["revenue"], 2),
                    "cost": round(row["cost"], 2),
                    "profit": round(row["profit"], 2),
                    "orders": row["orders"],
                }
            )
        return {"items": items}
    finally:
        db.close()


@router.get("/admin/users/search")
async def admin_users_search(request: Request, q: str | None = Query(default=None), days: int = 30, limit: int = 50):
    admin_auth.require_admin(request)
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
            revenue = round_money(o.amount_rub) or 0
            cost = o.cost_rub
            profit = o.profit_rub
            if (cost is None or profit is None) and usdtrub is not None:
                total_stars = int(o.quantity or 0) + int(o.bonus_stars_applied or 0)
                if total_stars > 0:
                    cost_usd = total_stars * (STAR_COST_USD_PER_100 / 100.0)
                    cost = round_money(cost_usd * usdtrub) or 0
                    profit = round_money(revenue - cost) or 0
                    o.cost_rub = cost
                    o.profit_rub = profit
                    o.cost_per_star = round_money(cost / total_stars) if total_stars else 0
                    o.usdtrub_rate = round_money(usdtrub) or 0
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
            items.append(
                {
                    "user_id": uid,
                    "display": user_map.get(uid),
                    "revenue": round(row["revenue"], 2),
                    "cost": round(row["cost"], 2),
                    "profit": round(row["profit"], 2),
                    "orders": row["orders"],
                    "stars": row["stars"],
                }
            )
        items.sort(key=lambda x: x["profit"], reverse=True)
        return {"items": items[:limit]}
    finally:
        db.close()


@router.get("/admin/promos")
async def admin_promos(request: Request, filter: str | None = Query(default=None)):
    admin_auth.require_admin(request)
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
            items.append(
                {
                    "code": p.code,
                    "percent": p.percent,
                    "max_uses": p.max_uses,
                    "uses": p.uses,
                    "active": p.active,
                    "expires_at": p.expires_at.isoformat() if p.expires_at else None,
                    "status": status,
                }
            )
        return {"items": items}
    finally:
        db.close()


@router.get("/admin/bonuses")
async def admin_bonuses(request: Request):
    admin_auth.require_admin(request)
    db = SessionLocal()
    try:
        bonuses = db.query(BonusGrant).order_by(BonusGrant.created_at.desc()).limit(300).all()
        items = []
        for b in bonuses:
            items.append(
                {
                    "user_id": b.user_id,
                    "stars": b.stars,
                    "status": b.status,
                    "source": b.source,
                    "expires_at": b.expires_at.isoformat() if b.expires_at else None,
                    "created_at": b.created_at.isoformat() if b.created_at else None,
                    "consumed_at": b.consumed_at.isoformat() if b.consumed_at else None,
                    "consumed_order_id": b.consumed_order_id,
                }
            )
        return {"items": items}
    finally:
        db.close()


@router.post("/admin/raffle/reset")
async def admin_raffle_reset(request: Request):
    admin_auth.require_admin(request)
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


@router.post("/admin/raffle/recalc")
async def admin_raffle_recalc(request: Request):
    admin_auth.require_admin(request)
    db = SessionLocal()
    try:
        now = now_msk()
        period_start, period_end = raffle_period(now)
        totals = (
            db.query(
                Order.user_id.label("user_id"),
                func.sum(Order.quantity).label("total"),
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


@router.get("/admin/raffle/summary")
async def admin_raffle_summary(request: Request):
    admin_auth.require_admin(request)
    db = SessionLocal()
    try:
        now = now_msk()
        period_start, period_end = raffle_period(now)
        totals = (
            db.query(
                Order.user_id.label("user_id"),
                func.sum(Order.quantity).label("total"),
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


@router.get("/admin/raffle/participants")
async def admin_raffle_participants(request: Request, format: str | None = Query(default=None)):
    admin_auth.require_admin(request)
    db = SessionLocal()
    try:
        now = now_msk()
        period_start, period_end = raffle_period(now)
        totals = (
            db.query(
                Order.user_id.label("user_id"),
                func.sum(Order.quantity).label("total"),
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
            items.append(
                {
                    "user_id": r.user_id,
                    "username": user_map.get(r.user_id),
                    "total_stars": total,
                    "chance_percent": chance,
                }
            )
        if (format or "").lower() == "csv":
            lines = ["user_id,username,total_stars,chance_percent"]
            for item in items:
                username = (item["username"] or "").replace(",", " ")
                lines.append(f"{item['user_id']},{username},{item['total_stars']},{item['chance_percent']}")
            return PlainTextResponse("\n".join(lines), media_type="text/csv")
        return {"items": items}
    finally:
        db.close()


@router.post("/admin/bonus/grant")
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
    if not constant_time_eq(API_AUTH_KEY, api_key or x_api_key or ""):
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

        existing = (
            db.query(BonusGrant)
            .filter(
                BonusGrant.user_id == user_id,
                BonusGrant.status.in_(["active", "reserved"]),
            )
            .first()
        )
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
            expires_at=expires_dt,
        )
        db.add(grant)
        db.commit()
        db.refresh(grant)
        return {"status": "ok", "bonus_id": grant.id, "expires_at": grant.expires_at}
    finally:
        db.close()
