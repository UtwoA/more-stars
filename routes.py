from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database import get_db
from models import Order, OrderLog
from app.crypto import create_cryptobot_invoice
import json
from websocket import notify_frontend

router = APIRouter()


@router.post("/orders/create")
async def create_order_api(user_id: int, recipient: str, product: str, amount_rub: float, crypto: str = "TON",
                           db: Session = Depends(get_db)):
    # Создание заказа
    new_order = Order(
        user_id=user_id,
        recipient=recipient,
        product=product,
        amount_rub=amount_rub,
        currency=crypto,
        status="pending"
    )
    db.add(new_order)
    db.commit()
    db.refresh(new_order)

    # Создание invoice
    invoice_link, crypto_amount = await create_cryptobot_invoice(amount_rub, crypto, recipient, new_order.id)

    # Обновление заказа
    new_order.crypto_amount = crypto_amount
    new_order.cryptobot_link = invoice_link
    db.commit()

    return {
        "order_id": new_order.id,
        "invoice_link": invoice_link,
        "crypto_amount": crypto_amount,
        "currency": crypto,
        "amount_rub": amount_rub
    }


@router.post("/webhook/cryptobot")
async def cryptobot_webhook(data: dict, db: Session = Depends(get_db)):
    """
    Webhook от CryptoBot: paid / failed
    """
    order_id = data.get("order_id")
    status = data.get("status")

    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        return {"error": "Order not found"}

    order.status = status
    db.commit()

    # Лог и уведомление фронта
    log = OrderLog(order_id=order.id, event=status, details=json.dumps(data))
    db.add(log)
    db.commit()

    await notify_frontend(order.id, status)

    return {"ok": True}
