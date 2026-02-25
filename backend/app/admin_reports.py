import os
from datetime import datetime, time, timedelta

import httpx

from .database import SessionLocal
from .models import Order, PaymentTransaction
from .utils import now_msk
from zoneinfo import ZoneInfo

MSK = ZoneInfo("Europe/Moscow")
MINI_APP_URL = os.getenv("MINI_APP_URL")


async def build_admin_report() -> str:
    db = SessionLocal()
    try:
        now = now_msk()
        start = datetime.combine(now.date(), time(0, 0), tzinfo=MSK)
        end = start + timedelta(days=1)

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

        last = (
            db.query(Order)
            .order_by(Order.timestamp.desc())
            .first()
        )

        platega_failures = db.query(PaymentTransaction).filter(
            PaymentTransaction.provider == "platega",
            PaymentTransaction.status != "PENDING",
            PaymentTransaction.created_at >= start,
            PaymentTransaction.created_at < end
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
            "📊 Admin report",
            f"date={start.date().isoformat()}",
            f"paid_orders={len(paid_orders)}",
            f"paid_total_rub={total_paid:.2f}",
            f"failed_orders={failed_orders}",
            f"platega_failures={platega_failures}",
            f"mini_app={app_status}",
        ]
        if last:
            lines.append(f"last_order={last.order_id} status={last.status}")
        return "\n".join(lines)
    finally:
        db.close()

