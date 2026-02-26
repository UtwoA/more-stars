import os
from aiogram import Bot, types
from aiogram import Dispatcher
from aiogram.filters import Command
from aiogram.types import Message
from datetime import datetime
from app.database import SessionLocal
from app.models import PromoCode
from app.utils import now_msk
from aiogram.client.default import DefaultBotProperties
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is not set")

bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode="HTML"))


def build_admin_dispatcher(admin_chat_id: str):
    dp = Dispatcher()

    @dp.message(Command("info"))
    async def cmd_info(message: Message):
        if str(message.from_user.id) != str(admin_chat_id):
            return
        from app.admin_reports import build_admin_report
        text = await build_admin_report()
        await message.answer(text)

    @dp.message(Command("promo"))
    async def cmd_promo(message: Message):
        if str(message.from_user.id) != str(admin_chat_id):
            return

        parts = (message.text or "").split()
        if len(parts) < 4:
            await message.answer(
                "Usage: /promo CODE PERCENT MAX_USES [ACTIVE] [EXPIRES_YYYY-MM-DD]\n"
                "Example: /promo PROMO10 10 100 true 2026-12-31"
            )
            return

        code = parts[1].strip().upper()
        try:
            percent = int(parts[2])
            max_uses = int(parts[3])
        except ValueError:
            await message.answer("PERCENT and MAX_USES must be integers.")
            return

        active = True
        if len(parts) >= 5:
            active = parts[4].lower() in ("1", "true", "yes")

        expires_at = None
        if len(parts) >= 6:
            try:
                expires_at = datetime.strptime(parts[5], "%Y-%m-%d").replace(
                    hour=23, minute=59, second=59, tzinfo=now_msk().tzinfo
                )
            except ValueError:
                await message.answer("EXPIRES must be YYYY-MM-DD.")
                return

        db = SessionLocal()
        try:
            promo = db.query(PromoCode).filter(PromoCode.code == code).first()
            if not promo:
                promo = PromoCode(code=code, percent=percent, max_uses=max_uses, active=active, expires_at=expires_at)
                db.add(promo)
            else:
                promo.percent = percent
                promo.max_uses = max_uses
                promo.active = active
                promo.expires_at = expires_at
            db.commit()
        finally:
            db.close()

        await message.answer(
            f"Promo saved: {code}\n"
            f"percent={percent}\n"
            f"max_uses={max_uses}\n"
            f"active={active}\n"
            f"expires_at={expires_at.date().isoformat() if expires_at else 'none'}"
        )

    return dp

async def send_user_message(chat_id: int, product_name: str):
    link = "https://t.me/more_stars_bot/app?startapp=1"
    text = (
        f"🎉 Оплата за <b>{product_name}</b> прошла успешно!\n\n"
        f"<b><a href=\"{link}\">Купить еще</a></b>"
    )
    await bot.send_message(chat_id=chat_id, text=text)


async def send_admin_message(chat_id: int, text: str):
    await bot.send_message(chat_id=chat_id, text=text)
