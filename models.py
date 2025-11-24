from sqlalchemy import Column, Integer, String, Numeric, TIMESTAMP, JSON
from sqlalchemy.sql import func
from database import Base

class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    recipient_username = Column(String, nullable=False)
    item_id = Column(String, nullable=False)
    item_title = Column(String, nullable=False)
    amount_rub = Column(Numeric(10,2), nullable=False)
    currency = Column(String, nullable=False)  # RUB, TON, USDT
    payment_method = Column(String, nullable=False)  # cryptobot, wallet, sbp
    status = Column(String, nullable=False, default="pending")  # pending, paid, failed
    invoice_id = Column(String, nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

class OrderLog(Base):
    __tablename__ = "order_logs"

    id = Column(Integer, primary_key=True, index=True)
    order_id = Column(Integer, nullable=False)
    event = Column(String, nullable=False)
    payload = Column(JSON)
    created_at = Column(TIMESTAMP, server_default=func.now())
