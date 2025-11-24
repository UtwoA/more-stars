from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from models import Order, OrderLog
from crypto import create_cryptobot_invoice, verify_cryptobot_signature
import json

# Создаём таблицы
Base.metadata.create_all(bind=engine)

app = FastAPI()

# CORS для фронтенда
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Webhook от CryptoBot
# -----------------------------
@app.post("/orders/cryptobot-webhook")
async def cryptobot_webhook(req: Request):
    payload_bytes = await req.body()
    payload_str = payload_bytes.decode()
    signature = req.headers.get("X-CryptoBot-Signature", "")

    if not verify_cryptobot_signature(payload_str, signature):
        raise HTTPException(status_code=403, detail="Invalid signature")

    data = json.loads(payload_str)
    invoice_id = data.get("invoice_id")
    status = data.get("status")  # paid, failed, pending

    db: Session = SessionLocal()
    try:
        order: Order = db.query(Order).filter(Order.invoice_id == invoice_id).first()
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        order.status = status
        db.add(order)

        log = OrderLog(
            order_id=order.id,
            event=f"cryptobot_webhook_{status}",
            payload=data
        )
        db.add(log)
        db.commit()

        return {"ok": True}
    finally:
        db.close()

# -----------------------------
# Эндпоинт создания заказа и ссылки на оплату
# -----------------------------
@app.post("/orders/create")
async def create_order(request: Request):
    """
    Пример запроса:
    {
        "user_id": 123456,
        "recipient": "@username",
        "item_id": "s50",
        "item_title": "50 ⭐",
        "amount_rub": 49.0,
        "payment_method": "cryptobot"
    }
    """
    data = await request.json()
    user_id = data["user_id"]
    recipient = data["recipient"]
    item_id = data["item_id"]
    item_title = data["item_title"]
    amount_rub = float(data["amount_rub"])
    payment_method = data["payment_method"]

    db: Session = SessionLocal()
    try:
        order = Order(
            user_id=user_id,
            recipient_username=recipient,
            item_id=item_id,
            item_title=item_title,
            amount_rub=amount_rub,
            currency="RUB",
            payment_method=payment_method,
        )
        db.add(order)
        db.commit()
        db.refresh(order)

        payment_url, invoice_id = None, None
        if payment_method == "cryptobot":
            payment_url, invoice_id = create_cryptobot_invoice(order.id, amount_rub, item_title, recipient)
            order.invoice_id = invoice_id
            db.add(order)
            db.commit()

        return {
            "order_id": order.id,
            "payment_url": payment_url,
            "invoice_id": invoice_id,
            "status": order.status
        }
    finally:
        db.close()
