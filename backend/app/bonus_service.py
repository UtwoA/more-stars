from .models import BonusGrant
from .utils import now_msk


def bonus_summary(db, user_id: str) -> dict:
    now = now_msk()
    bonuses = (
        db.query(BonusGrant)
        .filter(
            BonusGrant.user_id == user_id,
            BonusGrant.status.in_(["active", "reserved"]),
            (BonusGrant.expires_at.is_(None) | (BonusGrant.expires_at > now)),
        )
        .order_by(BonusGrant.expires_at.asc().nullsfirst(), BonusGrant.id.asc())
        .all()
    )
    total = sum((b.stars or 0) for b in bonuses)
    expires_at = bonuses[0].expires_at.isoformat() if bonuses and bonuses[0].expires_at else None
    return {"bonus_stars": total, "bonus_expires_at": expires_at}
