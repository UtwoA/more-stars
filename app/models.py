from sqlalchemy import Column, String, Integer, Float, DateTime
from .database import Base
import datetime

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
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    success_page_shown = Column(Integer, default=0)
    failure_page_shown = Column(Integer, default=0)
    expires_at = Column(DateTime, default=lambda: datetime.datetime.utcnow() + datetime.timedelta(minutes=30))