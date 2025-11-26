import asyncio

from fastapi import FastAPI, Request
from pydantic import BaseModel
from dotenv import load_dotenv
import os, datetime, uuid, httpx

from bot import send_user_message
from .database import SessionLocal, Base, engine
from .models import Order
from .crypto import convert_to_rub
from datetime import timedelta
from .cactuspay import cactuspay_create_payment, cactuspay_get_status
from datetime import datetime
from zoneinfo import ZoneInfo

from .utils import now_msk

MSK = ZoneInfo("Europe/Moscow")

load_dotenv()
CRYPTOBOT_TOKEN = os.getenv("CRYPTOBOT_TOKEN")  # твой testnet токен
CRYPTO_PAY_API_URL = "https://testnet-pay.crypt.bot/api/createInvoice"

app = FastAPI()
Base.metadata.create_all(bind=engine)


class OrderCreate(BaseModel):
    user_id: str
    recipient: str
    product: str
    amount: float
    currency: str  # TON / USDT


async def create_crypto_invoice(amount: float, currency: str, order_id: str, recipient: str):
    payload = {
        "currency_type": "crypto",        # тип платежа
        "asset": currency.upper(),        # криптовалюта
        "amount": amount,                 # сумма
        "description": f"Покупка {recipient}",
        "payload": order_id,
        "allow_comments": False,
        "allow_anonymous": False
    }
    headers = {
        "Crypto-Pay-API-Token": CRYPTOBOT_TOKEN,
        "Content-Type": "application/json"
    }
    async with httpx.AsyncClient() as client:
        r = await client.post(CRYPTO_PAY_API_URL, json=payload, headers=headers, timeout=15)
        return r.json()


@app.post("/create_order")
async def create_order(order: OrderCreate):
    amount_rub = await convert_to_rub(order.currency, order.amount)
    db = SessionLocal()
    order_id = str(uuid.uuid4())
    db_order = Order(
        order_id=order_id,
        user_id=order.user_id,
        recipient=order.recipient if order.recipient != "@unknown" else "self",
        product=order.product,
        amount_rub=amount_rub,
        currency=order.currency,
        status="created",
        type_of_payment="crypto",
        timestamp=now_msk(),
        expires_at=now_msk() + timedelta(minutes=10)
    )

    db.add(db_order)
    db.commit()
    db.refresh(db_order)

    # создаём инвойс в Crypto Pay Testnet
    invoice = await create_crypto_invoice(order.amount, order.currency, order_id, db_order.recipient)

    db.close()
    return {
        "order_id": order_id,
        "amount_rub": amount_rub,
        "crypto_invoice": invoice  # тут будет JSON с ссылкой на оплату
    }


@app.post("/webhook/crypto")
async def crypto_webhook(request: Request):
    data = await request.json()
    print("WEBHOOK DATA:", data)

    order_id = data.get("order_id")  # пусто для этого webhook
    # Для crypto-платежа берём ID из payload
    if "payload" in data:
        order_id = data["payload"].get("payload")

    if not order_id:
        return {"status": "error", "message": "No order_id found"}

    db = SessionLocal()
    order = db.query(Order).filter(Order.order_id == order_id).first()
    if order:
        status = data.get("status") or data.get("payload", {}).get("status")
        if status == "paid":
            order.status = "paid"
            db.commit()
            asyncio.create_task(
                send_user_message(
                    chat_id=int(order.user_id),
                    product_name=order.product
                )
            )
    db.close()
    return {"status": "ok"}



from fastapi import Query
@app.get("/order_status")
async def order_status(order_id: str = Query(...)):
    db = SessionLocal()
    order = db.query(Order).filter(Order.order_id == order_id).first()

    if not order:
        db.close()
        return {"error": "Order not found"}

    # проверяем таймер до закрытия сессии
    check_order_expired(order, db)

    result = {"order_id": order.order_id, "status": order.status}
    db.close()
    return result



@app.get("/last_order_status")
async def last_order_status(user_id: str = Query(...)):
    print("USER_ID:", user_id)
    db = SessionLocal()
    order = (
        db.query(Order)
        .filter(Order.user_id == user_id)
        .order_by(Order.timestamp.desc())
        .first()
    )

    if order:
        result = {
            "order_id": order.order_id,
            "status": order.status,
            "product": order.product,
            "show_success_page": False,
            "show_failure_page": False
        }

        if order.status == "paid" and order.success_page_shown == 0:
            result["show_success_page"] = True
            order.success_page_shown = 1
            db.commit()
        elif order.status == "failed" and order.failure_page_shown == 0:
            result["show_failure_page"] = True
            order.failure_page_shown = 1
            db.commit()
        check_order_expired(order, db)
        db.close()
        return result

    db.close()
    return {"status": "none"}

from fastapi import Query
from typing import List

@app.get("/order_history")
async def order_history(user_id: str = Query(...), limit: int = 10):
    """
    Возвращает историю последних заказов пользователя
    """
    db = SessionLocal()
    orders = (
        db.query(Order)
        .filter(Order.user_id == user_id)
        .order_by(Order.timestamp.desc())
        .limit(limit)
        .all()
    )
    db.close()

    result = [
        {
            "order_id": o.order_id,
            "product": o.product,
            "amount_rub": o.amount_rub,
            "currency": o.currency,
            "status": o.status,
            "timestamp": o.timestamp.astimezone(MSK).isoformat()  # всегда МСК
        }
        for o in orders
    ]

    return {"orders": result}


from datetime import datetime, timezone

def check_order_expired(order, db):
    now = now_msk()
    if order.status == "created" and order.expires_at < now:
        order.status = "failed"
        db.commit()
    return order

@app.post("/create_order_sbp")
async def create_order_sbp(order: OrderCreate):
    db = SessionLocal()

    order_id = str(uuid.uuid4())

    db_order = Order(
        order_id=order_id,
        user_id=order.user_id,
        recipient=order.recipient,
        product=order.product,
        amount_rub=order.amount,
        currency="RUB",
        status="created",
        type_of_payment="cactuspay_sbp",
        timestamp=now_msk(),
        expires_at=now_msk() + timedelta(minutes=10)
    )

    db.add(db_order)
    db.commit()
    db.refresh(db_order)

    # создаём платёж
    payment = await cactuspay_create_payment(
        order_id=order_id,
        amount=order.amount,
        description=f"Покупка {order.product}",
        method="sbp"
    )

    # Возвращаем URL для внешнего открытия
    return {"order_id": order_id, "pay_url": payment["response"]["url"]}

from fastapi import Form

@app.post("/webhook/cactuspay")
async def cactuspay_webhook(
    id: str = Form(...),
    order_id: str = Form(...),
    amount: float = Form(...)
):
    print("CACTUSPAY WEBHOOK RECEIVED:", id, order_id, amount)

    db = SessionLocal()
    order = db.query(Order).filter(Order.order_id == order_id).first()

    if not order:
        db.close()
        return {"status": "error", "message": "Order not found"}

    # после получения webhook ОБЯЗАНЫ проверить статус
    cactus = await cactuspay_get_status(order_id)
    status = cactus.get("response", {}).get("status")

    # statuses: ACCEPT / WAIT
    if status == "ACCEPT":
        order.status = "paid"
        db.commit()

        asyncio.create_task(
            send_user_message(
                chat_id=int(order.user_id),
                product_name=order.product
            )
        )

    db.close()
    return {"status": "ok"}
