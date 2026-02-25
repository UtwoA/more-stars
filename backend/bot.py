import os
from aiogram import Bot, types
from aiogram import Dispatcher
from aiogram.filters import Command
from aiogram.types import Message
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
