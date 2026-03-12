import logging
import random
from decimal import Decimal

import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import desc, func, text

from ..bonus_service import bonus_summary
from ..config import BOT_TOKEN
from ..database import SessionLocal
from ..og_meta import parse_og_meta
from ..promo_service import load_promo, reserve_promo
from ..raffle_utils import next_draw_dates, raffle_period
from ..schemas import AnalyticsEventPayload
from ..settings_store import get_setting, get_setting_float
from ..telegram_initdata import extract_user_id, verify_telegram_init_data, touch_user_from_initdata
from ..models import Order, User, GiftCatalog
from ..utils import now_msk

logger = logging.getLogger("public_api")
router = APIRouter()


@router.get("/settings/public")
async def public_settings():
    db = SessionLocal()
    try:
        return {
            "stars_rate_1": get_setting_float(db, "STARS_RATE_1", 1.39),
            "stars_rate_2": get_setting_float(db, "STARS_RATE_2", 1.37),
            "stars_rate_3": get_setting_float(db, "STARS_RATE_3", 1.35),
            "tier_1_max": 1000,
            "tier_2_max": 5000,
            "banner_enabled": get_setting(db, "BANNER_ENABLED", "false").lower() in ("1", "true", "yes"),
            "banner_title": get_setting(db, "BANNER_TITLE", ""),
            "banner_text": get_setting(db, "BANNER_TEXT", ""),
            "banner_url": get_setting(db, "BANNER_URL", ""),
            "banner_until": get_setting(db, "BANNER_UNTIL", ""),
            "promo_text": get_setting(db, "PROMO_TEXT", ""),
        }
    finally:
        db.close()


@router.post("/analytics/visit")
async def analytics_visit(request: Request, user_id: str | None = Query(default=None)):
    init_data = request.headers.get("x-telegram-init-data")
    uid = user_id
    if not uid and init_data and verify_telegram_init_data(init_data, bot_token=BOT_TOKEN):
        uid = extract_user_id(init_data)
    db = SessionLocal()
    try:
        db.execute(
            text("INSERT INTO app_events (event_type, user_id) VALUES (:event_type, :user_id)"),
            {"event_type": "open", "user_id": uid},
        )
        db.commit()
        return {"status": "ok"}
    finally:
        db.close()


@router.post("/analytics/event")
async def analytics_event(request: Request, payload: AnalyticsEventPayload, user_id: str | None = Query(default=None)):
    event_type = payload.event_type
    init_data = request.headers.get("x-telegram-init-data")
    uid = user_id
    if not uid and init_data and verify_telegram_init_data(init_data, bot_token=BOT_TOKEN):
        uid = extract_user_id(init_data)
    if not event_type:
        raise HTTPException(status_code=400, detail="event_type required")
    db = SessionLocal()
    try:
        db.execute(
            text("INSERT INTO app_events (event_type, user_id) VALUES (:event_type, :user_id)"),
            {"event_type": event_type, "user_id": uid},
        )
        db.commit()
        return {"status": "ok"}
    finally:
        db.close()


@router.get("/raffle/prize/preview")
async def raffle_prize_preview(url: str = Query(...)):
    if not url.startswith("https://t.me/nft/"):
        raise HTTPException(status_code=400, detail="Only t.me/nft links are allowed")
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            r.raise_for_status()
            meta = parse_og_meta(r.text)
        return {"ok": True, **meta}
    except Exception as exc:
        logger.exception("[RAFFLE] Failed to fetch prize preview")
        raise HTTPException(status_code=502, detail="Failed to fetch prize preview") from exc


@router.get("/promo/validate")
async def promo_validate(code: str = Query(...)):
    db = SessionLocal()
    try:
        promo = load_promo(code, db)
        if not promo:
            return {"valid": False}
        return {"valid": True, "percent": promo.percent}
    finally:
        db.close()


@router.get("/gifts")
async def gifts_list():
    db = SessionLocal()
    try:
        gifts = db.query(GiftCatalog).filter(GiftCatalog.active.is_(True)).order_by(
            GiftCatalog.sort_order.asc().nulls_last(),
            GiftCatalog.id.asc(),
        ).all()
        return {
            "gifts": [
                {
                    "gift_id": str(g.gift_id),
                    "title": g.title,
                    "price_rub": g.price_rub,
                    "price_stars": g.price_stars,
                    "image_url": g.image_url,
                    "sort_order": g.sort_order,
                }
                for g in gifts
            ]
        }
    finally:
        db.close()


@router.post("/promo/apply")
async def promo_apply(code: str = Query(...), user_id: str = Query(...)):
    db = SessionLocal()
    try:
        reservation = reserve_promo(code, user_id, db)
        if not reservation:
            return {"valid": False}
        return {"valid": True, "percent": reservation.percent, "expires_at": reservation.expires_at.isoformat()}
    finally:
        db.close()


@router.post("/ref/attach")
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


@router.get("/profile/summary")
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
            touch_user_from_initdata(db, user_id=user_id, init_data=init_data, user_model=User)
        bonus = bonus_summary(db, user_id)
        invited_count = db.query(User).filter(User.referrer_id == user_id).count()
        return {
            "referral_balance_stars": user.referral_balance_stars or 0,
            "referrer_id": user.referrer_id,
            "invited_count": invited_count,
            "bonus_balance_stars": bonus["bonus_stars"],
            "bonus_expires_at": bonus["bonus_expires_at"],
        }
    finally:
        db.close()


@router.get("/raffle/summary")
async def raffle_summary(user_id: str = Query(...)):
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
            db.query(totals.c.user_id, totals.c.total).order_by(desc(totals.c.total)).limit(10).all()
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
            top.append(
                {
                    "user_id": row.user_id,
                    "display": user_map.get(row.user_id),
                    "total_stars": total,
                    "chance_percent": chance,
                }
            )

        next_draws = [d.isoformat() for d in next_draw_dates(now)]
        is_draw_day = now.day in (15, 30)
        chance_percent = 0.0
        if total_all and user_total:
            chance_percent = float(Decimal(str(user_total / total_all * 100)).quantize(Decimal("0.01")))

        prize = {
            "title": get_setting(db, "RAFFLE_PRIZE_TITLE", "NFT-подарок или бонусные звёзды"),
            "description": get_setting(db, "RAFFLE_PRIZE_DESC", "Победитель получит приз после розыгрыша."),
            "image": get_setting(db, "RAFFLE_PRIZE_IMAGE", ""),
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
                        "chance_percent": float(
                            Decimal(str((row.total or 0) / total_all * 100)).quantize(Decimal("0.01"))
                        )
                        if total_all
                        else 0.0,
                    }
                    break
            if winner is None:
                row = all_rows[0]
                winner = {
                    "user_id": row.user_id,
                    "display": user_map.get(row.user_id),
                    "total_stars": int(row.total or 0),
                    "chance_percent": float(
                        Decimal(str((row.total or 0) / total_all * 100)).quantize(Decimal("0.01"))
                    )
                    if total_all
                    else 0.0,
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
