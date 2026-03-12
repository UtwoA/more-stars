import os
import asyncio
import logging
from aiogram import Bot, types
from aiogram import Dispatcher
from aiogram.filters import Command
from aiogram.types import Message
from datetime import datetime, timedelta
from app.database import SessionLocal
from app.models import PromoCode, BonusGrant, BonusClaim, BonusClaimRedemption, Order, User
from app.utils import now_msk
from aiogram.client.default import DefaultBotProperties
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from dotenv import load_dotenv

load_dotenv()

_bot: Bot | None = None
logger = logging.getLogger("bot")


def get_bot() -> Bot:
    global _bot
    if _bot is not None:
        return _bot
    token = os.getenv("BOT_TOKEN")
    if not token:
        raise RuntimeError("BOT_TOKEN is not set")
    _bot = Bot(token=token, default=DefaultBotProperties(parse_mode="HTML"))
    return _bot


_pending_broadcast: dict[str, str | None] = {}


def build_admin_dispatcher(admin_chat_ids: set[str]):
    dp = Dispatcher()
    admin_ids = {str(item) for item in admin_chat_ids if item}
    bot = get_bot()

    @dp.message(Command("start"))
    async def cmd_start(message: Message):
        parts = (message.text or "").split(maxsplit=1)
        if len(parts) > 1 and parts[1].startswith("bonus_"):
            token = parts[1].replace("bonus_", "", 1).strip()
            await _claim_bonus(message, token)
            return
        link = "https://t.me/more_stars_bot/app?startapp=1"
        channel = "https://t.me/more_stars_channel"
        kb = InlineKeyboardMarkup(
            inline_keyboard=[
                [InlineKeyboardButton(text="Открыть приложение", url=link)],
                [InlineKeyboardButton(text="Канал More Stars", url=channel)]
            ]
        )
        await message.answer(
            "Привет! Это More Stars.\n"
            "Нажмите кнопку ниже, чтобы открыть приложение.\n"
            "Скидки и промокоды — в нашем телеграм-канале.",
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

        user_map = {}
        user_ids = list({o.user_id for o in orders})
        if user_ids:
            users = db.query(User).filter(User.user_id.in_(user_ids)).all()
            for u in users:
                if u.username:
                    user_map[u.user_id] = f"@{u.username}"
                elif u.full_name:
                    user_map[u.user_id] = u.full_name

        lines = []
        for o in orders:
            bonus = int(o.bonus_stars_applied or 0)
            qty = int(o.quantity or 0)
            total = qty + bonus
            when = o.timestamp.astimezone(now.tzinfo).strftime("%Y-%m-%d %H:%M")
            display = o.user_username or user_map.get(o.user_id)
            if display:
                user = f"{display} (id {o.user_id})"
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

    @dp.message(Command("report"))
    async def cmd_report(message: Message):
        if str(message.from_user.id) not in admin_ids:
            return
        from app.admin_reports import build_admin_report
        parts = (message.text or "").split(maxsplit=1)
        target = None
        if len(parts) > 1:
            raw = parts[1].strip()
            try:
                target = datetime.strptime(raw, "%d/%m/%y").replace(tzinfo=now_msk().tzinfo)
            except ValueError:
                await message.answer("Формат даты: /report DD/MM/YY")
                return
        text = await build_admin_report(target)
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

    @dp.message(Command("broadcast_wait"))
    async def cmd_broadcast_wait(message: Message):
        if str(message.from_user.id) not in admin_ids:
            return
        parts = (message.text or "").split(maxsplit=1)
        target_id = None
        if len(parts) > 1:
            target_id = parts[1].strip()
            if not target_id.isdigit():
                await message.answer("ID должен быть числом.")
                return
        _pending_broadcast[str(message.from_user.id)] = target_id
        if target_id:
            await message.answer(
                f"Ок. Отправь сообщение для пользователя {target_id} "
                f"(текст или фото/гиф + подпись)."
            )
        else:
            await message.answer(
                "Ок. Отправь сообщение для рассылки всем пользователям "
                "(текст или фото/гиф + подпись)."
            )

    @dp.message(Command("broadcast"))
    async def cmd_broadcast(message: Message):
        if str(message.from_user.id) not in admin_ids:
            return

        target = message.reply_to_message
        payload_text = None
        photo_id = None
        animation_id = None

        if target:
            if target.photo:
                photo_id = target.photo[-1].file_id
                payload_text = target.caption or ""
            elif target.animation:
                animation_id = target.animation.file_id
                payload_text = target.caption or ""
            else:
                payload_text = target.text or target.caption or ""
        else:
            parts = (message.text or "").split(maxsplit=1)
            if len(parts) > 1:
                payload_text = parts[1].strip()

        if not (payload_text or photo_id or animation_id):
            await message.answer(
                "Использование: /broadcast <текст>\n"
                "Или ответьте командой /broadcast на сообщение с текстом/картинкой/гифкой."
            )
            return

        db = SessionLocal()
        try:
            user_ids = [u.user_id for u in db.query(User.user_id).all()]
        finally:
            db.close()

        if not user_ids:
            await message.answer("Пользователей нет.")
            return

        sent = 0
        failed = 0
        for uid in user_ids:
            try:
                if photo_id:
                    await bot.send_photo(chat_id=int(uid), photo=photo_id, caption=payload_text or None)
                elif animation_id:
                    await bot.send_animation(chat_id=int(uid), animation=animation_id, caption=payload_text or None)
                else:
                    await bot.send_message(chat_id=int(uid), text=payload_text)
                sent += 1
                await asyncio.sleep(0.03)
            except Exception:
                failed += 1
                await asyncio.sleep(0.03)

        await message.answer(f"Рассылка завершена. Успешно: {sent}, Ошибок: {failed}.")

    @dp.message()
    async def handle_pending_broadcast(message: Message):
        admin_id = str(message.from_user.id)
        if admin_id not in admin_ids:
            return
        if admin_id not in _pending_broadcast:
            return
        if (message.text or "").lstrip().startswith("/"):
            return

        target_id = _pending_broadcast.pop(admin_id, None)
        payload_text = None
        photo_id = None
        animation_id = None

        if message.photo:
            photo_id = message.photo[-1].file_id
            payload_text = message.caption or ""
        elif message.animation:
            animation_id = message.animation.file_id
            payload_text = message.caption or ""
        else:
            payload_text = message.text or ""

        if not (payload_text or photo_id or animation_id):
            await message.answer("Пустое сообщение. Отменено.")
            return

        if target_id:
            try:
                if photo_id:
                    await bot.send_photo(chat_id=int(target_id), photo=photo_id, caption=payload_text or None)
                elif animation_id:
                    await bot.send_animation(chat_id=int(target_id), animation=animation_id, caption=payload_text or None)
                else:
                    await bot.send_message(chat_id=int(target_id), text=payload_text)
                await message.answer(f"Отправлено пользователю {target_id}.")
            except Exception:
                await message.answer(f"Не удалось отправить пользователю {target_id}.")
            return

        db = SessionLocal()
        try:
            user_ids = [u.user_id for u in db.query(User.user_id).all()]
        finally:
            db.close()

        if not user_ids:
            await message.answer("Пользователей нет.")
            return

        sent = 0
        failed = 0
        for uid in user_ids:
            try:
                if photo_id:
                    await bot.send_photo(chat_id=int(uid), photo=photo_id, caption=payload_text or None)
                elif animation_id:
                    await bot.send_animation(chat_id=int(uid), animation=animation_id, caption=payload_text or None)
                else:
                    await bot.send_message(chat_id=int(uid), text=payload_text)
                sent += 1
                await asyncio.sleep(0.03)
            except Exception:
                failed += 1
                await asyncio.sleep(0.03)

        await message.answer(f"Рассылка завершена. Успешно: {sent}, Ошибок: {failed}.")

    @dp.pre_checkout_query()
    async def handle_pre_checkout(pre_checkout_query: types.PreCheckoutQuery):
        try:
            await bot.answer_pre_checkout_query(pre_checkout_query.id, ok=True)
        except Exception:
            logger.exception("[BOT] Failed to answer pre_checkout")

    @dp.message(lambda message: message.successful_payment is not None)
    async def handle_successful_payment(message: Message):
        try:
            payment = message.successful_payment
            if not payment:
                return
            order_id = payment.invoice_payload
            if not order_id:
                return
            logger.info("[BOT] Successful payment for order %s", order_id)

            db = SessionLocal()
            try:
                order = db.query(Order).filter(Order.order_id == order_id).first()
                if not order:
                    return
                if order.status == "paid":
                    return
                order.status = "paid"
                order.payment_provider = "tg_stars"
                order.payment_method = "invoice"
                charge_id = payment.telegram_payment_charge_id or payment.provider_payment_charge_id
                if charge_id:
                    order.payment_invoice_id = str(charge_id)
                db.commit()
            finally:
                db.close()
        except Exception:
            logger.exception("[BOT] Failed to handle successful payment")

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
    bot = get_bot()
    link = "https://t.me/more_stars_bot/app?startapp=1"
    text = (
        f"🎉 Оплата за <b>{product_name}</b> прошла успешно!\n\n"
        f"<b><a href=\"{link}\">Купить еще</a></b>"
    )
    await bot.send_message(chat_id=chat_id, text=text)


async def send_admin_message(chat_id: int, text: str):
    bot = get_bot()
    await bot.send_message(chat_id=chat_id, text=text)


async def send_user_notice(chat_id: int, text: str):
    bot = get_bot()
    await bot.send_message(chat_id=chat_id, text=text)
