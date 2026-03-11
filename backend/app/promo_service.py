from datetime import timedelta

from .models import PromoCode, PromoRedemption, PromoReservation
from .utils import now_msk


def load_promo(code: str, db) -> PromoCode | None:
    raw = (code or "").upper()
    if not raw.strip():
        return None
    promo = db.query(PromoCode).filter(PromoCode.code == raw).first()
    if not promo:
        return None
    if not promo.active:
        return None
    if promo.expires_at and promo.expires_at < now_msk():
        return None
    if promo.max_uses is not None and promo.uses >= promo.max_uses:
        return None
    return promo


def get_active_reservation(code: str, user_id: str, db) -> PromoReservation | None:
    now = now_msk()
    return db.query(PromoReservation).filter(
        PromoReservation.code == (code or "").upper(),
        PromoReservation.user_id == user_id,
        PromoReservation.expires_at > now,
    ).first()


def promo_used_by_user(code: str, user_id: str, db) -> bool:
    return db.query(PromoRedemption).filter(
        PromoRedemption.code == (code or "").upper(),
        PromoRedemption.user_id == user_id,
    ).first() is not None


def reserve_promo(code: str, user_id: str, db) -> PromoReservation | None:
    promo = load_promo(code, db)
    if not promo:
        return None
    if promo_used_by_user(code, user_id, db):
        return None
    existing = get_active_reservation(code, user_id, db)
    if existing:
        return existing
    if promo.max_uses is not None:
        redemptions = db.query(PromoRedemption).filter(PromoRedemption.code == promo.code).count()
        reservations = db.query(PromoReservation).filter(
            PromoReservation.code == promo.code,
            PromoReservation.expires_at > now_msk(),
        ).count()
        if redemptions + reservations >= promo.max_uses:
            return None

    expires_at = now_msk() + timedelta(minutes=15)
    reservation = PromoReservation(code=promo.code, user_id=user_id, percent=promo.percent, expires_at=expires_at)
    db.add(reservation)
    db.commit()
    db.refresh(reservation)
    return reservation
