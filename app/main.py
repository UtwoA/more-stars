from fastapi import FastAPI, Request, Header, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
import os, hmac, hashlib, json, datetime
from .database import SessionLocal, engine, Base
from .models import Order
from .crypto import convert_to_rub
import uuid

load_dotenv()
CRYPTOBOT_TOKEN = os.getenv("CRYPTOBOT_TOKEN").encode()

app = FastAPI()
Base.metadata.create_all(bind=engine)

# Pydantic модель для create_order
class OrderCreate(BaseModel):
    user_id: str
    recipient: str
    product: str
    amount: float
    currency: str  # TON / USDT

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
        timestamp=datetime.datetime.utcnow()
    )
    db.add(db_order)
    db.commit()
    db.refresh(db_order)
    db.close()
    return {"order_id": order_id, "amount_rub": amount_rub}

@app.post("/webhook/crypto")
async def crypto_webhook(request: Request):

    data = await request.json()
    db = SessionLocal()
    order = db.query(Order).filter(Order.order_id == data.get("order_id")).first()
    if order:
        order.status = data.get("status", order.status)
        db.commit()
    db.close()
    return {"status": "ok"}
