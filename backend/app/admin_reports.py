import os
from datetime import datetime, time, timedelta, timezone

import httpx

from .database import SessionLocal
from .models import Order, PaymentTransaction
from .utils import now_msk
from zoneinfo import ZoneInfo

MSK = ZoneInfo("Europe/Moscow")
MINI_APP_URL = os.getenv("MINI_APP_URL")


async def build_admin_report(target_date: datetime | None = None) -> str:
    db = SessionLocal()
    try:
        now = now_msk()
        if target_date is None:
            target_date = now
        start_msk = datetime.combine(now.date(), time(0, 0), tzinfo=MSK)
        end_msk = start_msk + timedelta(days=1)
        if target_date:
            start_msk = datetime.combine(target_date.date(), time(0, 0), tzinfo=MSK)
            end_msk = start_msk + timedelta(days=1)
        start = start_msk.astimezone(timezone.utc)
        end = end_msk.astimezone(timezone.utc)

        paid_orders = db.query(Order).filter(
            Order.status == "paid",
            Order.timestamp >= start,
            Order.timestamp < end
        ).all()
        failed_orders = db.query(Order).filter(
            Order.status == "failed",
            Order.timestamp >= start,
            Order.timestamp < end
        ).count()

        total_paid = sum((o.amount_rub or 0) for o in paid_orders)
        total_stars = sum((o.quantity or 0) for o in paid_orders if o.product_type == "stars")
        total_bonus = sum((o.bonus_stars_applied or 0) for o in paid_orders if o.product_type == "stars")
        total_gifts = sum(1 for o in paid_orders if o.product_type == "gift")
        total_gifts_revenue = sum((o.amount_rub or 0) for o in paid_orders if o.product_type == "gift")
        avg_check = (total_paid / len(paid_orders)) if paid_orders else 0.0

        by_provider = {}
        for o in paid_orders:
            key = o.payment_provider or "unknown"
            by_provider[key] = by_provider.get(key, 0) + 1

        last = (
            db.query(Order)
            .order_by(Order.timestamp.desc())
            .first()
        )

        platega_failures = db.query(Order).filter(
            Order.payment_provider == "platega",
            Order.status == "failed",
            Order.timestamp >= start,
            Order.timestamp < end
        ).count()

        app_status = "unknown"
        if MINI_APP_URL:
            try:
                async with httpx.AsyncClient() as client:
                    r = await client.get(MINI_APP_URL, timeout=10)
                app_status = "up" if r.status_code < 400 else "down"
            except Exception:
                app_status = "down"

        lines = [
            "📊 Ежедневный отчёт",
            f"Дата: {start_msk.date().strftime('%d.%m.%Y')}",
            f"Оплаченных заказов: {len(paid_orders)}",
            f"Сумма оплат: {total_paid:.2f} ₽",
            f"Средний чек: {avg_check:.2f} ₽",
            f"Звёзд куплено: {int(total_stars)} (+{int(total_bonus)} бонус)",
            f"Подарков куплено: {int(total_gifts)}",
            f"Выручка подарков: {total_gifts_revenue:.2f} ₽",
            f"Неудачных заказов: {failed_orders}",
            f"Ошибок Platega: {platega_failures}",
            f"По провайдерам: {by_provider}",
            f"Статус мини‑приложения: {app_status}",
        ]
        if last:
            lines.append(
                f"Последний заказ: {last.order_id} | {last.status} | "
                f"{last.amount_rub or 0:.2f} ₽ | {last.payment_provider}"
            )
        return "\n".join(lines)
    finally:
        db.close()
