from aiogram import Bot, types
from aiogram.client.default import DefaultBotProperties
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton

BOT_TOKEN = "8586920536:AAHmc9iFU073Zvj-Ebt9G9OtSut9FsWxB0c"
bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode="HTML"))

async def send_user_message(chat_id: int, product_name: str):
    link = "https://t.me/more_stars_bot/app?startapp=1"
    text = (
        f"🎉 Оплата за <b>{product_name}</b> прошла успешно!\n\n"
        f"<b><a href=\"{link}\">Купить еще</a></b>"
    )
    await bot.send_message(chat_id=chat_id, text=text)