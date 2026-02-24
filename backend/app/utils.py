# app/utils.py
from datetime import datetime
from zoneinfo import ZoneInfo

MSK = ZoneInfo("Europe/Moscow")

def now_msk():
    return datetime.now(MSK)
