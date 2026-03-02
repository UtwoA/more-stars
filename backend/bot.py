import os
from aiogram import Bot, types
from aiogram import Dispatcher
from aiogram.filters import Command
from aiogram.types import Message
from datetime import datetime, timedelta
from app.database import SessionLocal
from app.models import PromoCode, BonusGrant, BonusClaim, BonusClaimRedemption, Order
from app.utils import now_msk
from aiogram.client.default import DefaultBotProperties
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is not set")

bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode="HTML"))


def build_admin_dispatcher(admin_chat_ids: set[str]):
    dp = Dispatcher()
    admin_ids = {str(item) for item in admin_chat_ids if item}

    @dp.message(Command("start"))
    async def cmd_start(message: Message):
        parts = (message.text or "").split(maxsplit=1)
        if len(parts) > 1 and parts[1].startswith("bonus_"):
            token = parts[1].replace("bonus_", "", 1).strip()
            await _claim_bonus(message, token)
            return
        link = "https://t.me/more_stars_bot/app?startapp=1"
        kb = InlineKeyboardMarkup(
            inline_keyboard=[
                [InlineKeyboardButton(text="Открыть приложение", url=link)]
            ]
        )
        await message.answer(
            "Привет! Это More Stars.\n"
            "Нажмите кнопку ниже, чтобы открыть приложение.",
            reply_markup=kb,
        )

    @dp.message(Command("info"))
    async def cmd_info(message: Message):
        if str(message.from_user.id) not in admin_ids:
            return
        from app.admin_reports import build_admin_report
        text = await build_admin_report()
        await message.answer(text)

    @dp.message(Command("today"))
    async def cmd_today(message: Message):
        if str(message.from_user.id) not in admin_ids:
            return
        now = now_msk()
        since = now - timedelta(hours=24)
        db = SessionLocal()
        try:
            orders = (
                db.query(Order)
                .filter(
                    Order.product_type == "stars",
                    Order.status == "paid",
                    Order.timestamp >= since
                )
                .order_by(Order.timestamp.desc())
                .limit(200)
                .all()
            )
        finally:
            db.close()

        if not orders:
            await message.answer("За последние 24 часа покупок не было.")
            return

        lines = []
        for o in orders:
            bonus = int(o.bonus_stars_applied or 0)
            qty = int(o.quantity or 0)
            total = qty + bonus
            when = o.timestamp.astimezone(now.tzinfo).strftime("%Y-%m-%d %H:%M")
            if o.user_username:
                user = f"{o.user_username} (id {o.user_id})"
            else:
                user = f"id {o.user_id}"
            if o.payment_provider == "platega":
                pay = "SBP" if o.payment_method == "sbp" else "Card"
            elif o.payment_provider == "crypto":
                pay = "CryptoBot"
            else:
                pay = o.payment_provider or "unknown"
            lines.append(f"{when} | ⭐ {total} ({qty}+{bonus}) | {user} | {pay}")

        text = "Покупки за 24 часа:\n" + "\n".join(lines)
        await message.answer(text)

    @dp.message(Command("promo"))
    async def cmd_promo(message: Message):
        if str(message.from_user.id) not in admin_ids:
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

    @dp.message(Command("grant"))
    async def cmd_grant(message: Message):
        if str(message.from_user.id) not in admin_ids:
            return
        parts = (message.text or "").split()
        if len(parts) < 2:
            await message.answer("Usage: /grant STARS [TTL_MINUTES] [MAX_USES] [SOURCE]")
            return
        try:
            stars = int(parts[1])
        except ValueError:
            await message.answer("STARS must be integer")
            return
        ttl_minutes = None
        max_uses = 1
        source = None
        if len(parts) >= 3:
            try:
                ttl_minutes = int(parts[2])
            except ValueError:
                source = parts[2]
        if len(parts) >= 4:
            try:
                max_uses = int(parts[3])
            except ValueError:
                source = parts[3]
        if len(parts) >= 5:
            source = " ".join(parts[4:])

        token = _create_bonus_claim(stars=stars, ttl_minutes=ttl_minutes, max_uses=max_uses, source=source)
        link = f"https://t.me/more_stars_bot?start=bonus_{token}"
        await message.answer(
            f"Бонус создан: {stars} ⭐\n"
            f"Ссылка: {link}\n"
            f"TTL: {ttl_minutes or 'no'} minutes\n"
            f"MAX_USES: {max_uses}\n"
            f"Source: {source or 'n/a'}"
        )

    return dp


def _create_bonus_claim(stars: int, ttl_minutes: int | None, max_uses: int, source: str | None) -> str:
    token = os.urandom(12).hex()
    expires_at = None
    if ttl_minutes:
        expires_at = now_msk() + timedelta(minutes=ttl_minutes)
    db = SessionLocal()
    try:
        claim = BonusClaim(
            token=token,
            stars=stars,
            status="active",
            source=source,
            max_uses=max_uses,
            uses=0,
            expires_at=expires_at
        )
        db.add(claim)
        db.commit()
    finally:
        db.close()
    return token


async def _claim_bonus(message: Message, token: str) -> None:
    if not token:
        await message.answer("Ссылка с бонусом недействительна.")
        return
    user_id = str(message.from_user.id)
    db = SessionLocal()
    bonus_stars = None
    bonus_expires = None
    try:
        claim = db.query(BonusClaim).filter(BonusClaim.token == token).first()
        if not claim or claim.status != "active":
            await message.answer("Бонус уже использован или недействителен.")
            return

        now = now_msk()
        if claim.expires_at and claim.expires_at <= now:
            claim.status = "expired"
            db.commit()
            await message.answer("Срок действия бонуса истек.")
            return

        if claim.max_uses is not None and claim.uses is not None and claim.uses >= claim.max_uses:
            claim.status = "exhausted"
            db.commit()
            await message.answer("Бонус уже использован или недействителен.")
            return

        already_claimed = db.query(BonusClaimRedemption).filter(
            BonusClaimRedemption.claim_id == claim.id,
            BonusClaimRedemption.user_id == user_id
        ).first()
        if already_claimed:
            await message.answer("Этот бонус уже был вами использован.")
            return

        grant = BonusGrant(
            user_id=user_id,
            stars=claim.stars,
            status="active",
            source=claim.source or "grant_link",
            expires_at=claim.expires_at
        )
        db.add(grant)
        redemption = BonusClaimRedemption(claim_id=claim.id, user_id=user_id)
        db.add(redemption)
        claim.uses = (claim.uses or 0) + 1
        claim.claimed_user_id = user_id
        claim.claimed_at = now
        if claim.max_uses is not None and claim.uses >= claim.max_uses:
            claim.status = "exhausted"
        db.commit()
        bonus_stars = claim.stars
        bonus_expires = claim.expires_at
    finally:
        db.close()

    expiry_text = ""
    if bonus_expires:
        expiry_text = f"\nДействует до: {bonus_expires.astimezone(now_msk().tzinfo).strftime('%Y-%m-%d %H:%M')}"
    link = "https://t.me/more_stars_bot/app?startapp=1"
    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Открыть приложение", url=link)]
        ]
    )
    await message.answer(
        f"✅ Бонус активирован: {bonus_stars or 0} ⭐"
        f"{expiry_text}\n"
        f"Он будет автоматически применён при покупке от 50 звёзд.",
        reply_markup=kb
    )

async def send_user_message(chat_id: int, product_name: str):
    link = "https://t.me/more_stars_bot/app?startapp=1"
    text = (
        f"🎉 Оплата за <b>{product_name}</b> прошла успешно!\n\n"
        f"<b><a href=\"{link}\">Купить еще</a></b>"
    )
    await bot.send_message(chat_id=chat_id, text=text)


async def send_admin_message(chat_id: int, text: str):
    await bot.send_message(chat_id=chat_id, text=text)
