from datetime import timedelta
from sqlalchemy import Column, String, Integer, Float, DateTime
from .database import Base
from .utils import now_msk


class Order(Base):
    __tablename__ = "orders"

    order_id = Column(String, primary_key=True, index=True)
    user_id = Column(String, index=True)
    recipient = Column(String)
    product = Column(String)
    amount_rub = Column(Float)
    currency = Column(String)
    status = Column(String)
    type_of_payment = Column(String)
    timestamp = Column(DateTime(timezone=True), default=now_msk)
    success_page_shown = Column(Integer, default=0)
    failure_page_shown = Column(Integer, default=0)
    expires_at = Column(DateTime(timezone=True), default=lambda: now_msk() + timedelta(minutes=10))
    idempotency_key = Column(String, nullable=True)
