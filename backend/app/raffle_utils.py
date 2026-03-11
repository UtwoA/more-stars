from datetime import datetime

from .config import MSK
from .database import SessionLocal
from .models import AdminSetting


def next_draw_dates(now: datetime) -> list[datetime]:
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


def raffle_period(now: datetime) -> tuple[datetime, datetime]:
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
                    start = reset_dt.replace(tzinfo=MSK) if reset_dt.tzinfo is None else reset_dt
            except Exception:
                pass
    finally:
        db.close()
    return start, end

