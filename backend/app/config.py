import os
from zoneinfo import ZoneInfo

from dotenv import load_dotenv

load_dotenv()

MSK = ZoneInfo("Europe/Moscow")

ADMIN_CHAT_IDS = {item.strip() for item in (os.getenv("ADMIN_CHAT_ID") or "").split(",") if item.strip()}
REFERRAL_PERCENT = int(os.getenv("REFERRAL_PERCENT", "7"))
ADMIN_REPORT_TIME = os.getenv("ADMIN_REPORT_TIME", "00:00")
ADMIN_OTP_TTL_MIN = int(os.getenv("ADMIN_OTP_TTL_MIN", "5"))

STAR_COST_USD_PER_100 = float(os.getenv("STAR_COST_USD_PER_100", "1.5"))
STAR_COST_RATE_SOURCE = os.getenv("STAR_COST_RATE_SOURCE", "moex").lower()

API_AUTH_KEY = os.getenv("API_AUTH_KEY")
BOT_TOKEN = os.getenv("BOT_TOKEN")
