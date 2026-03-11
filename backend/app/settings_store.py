from datetime import time

from .config import ADMIN_REPORT_TIME
from .models import AdminSetting


def get_setting(db, key: str, default: str) -> str:
    row = db.query(AdminSetting).filter(AdminSetting.key == key).first()
    if row and row.value is not None:
        return row.value
    return default


def get_setting_float(db, key: str, default: float) -> float:
    raw = get_setting(db, key, str(default))
    try:
        return float(raw)
    except ValueError:
        return default


def get_setting_int(db, key: str, default: int) -> int:
    raw = get_setting(db, key, str(default))
    try:
        return int(raw)
    except ValueError:
        return default


def get_report_time(db) -> time:
    raw = get_setting(db, "ADMIN_REPORT_TIME", ADMIN_REPORT_TIME)
    try:
        parts = raw.split(":")
        if len(parts) != 2:
            raise ValueError("invalid")
        hour = int(parts[0])
        minute = int(parts[1])
        return time(hour=hour, minute=minute)
    except Exception:
        return time(0, 0)

