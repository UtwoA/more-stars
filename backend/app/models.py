from datetime import timedelta
from sqlalchemy import Column, String, Integer, Float, DateTime, Boolean, Text
from .database import Base
from .utils import now_msk


class Order(Base):
    __tablename__ = "orders"

    order_id = Column(String, primary_key=True, index=True)
    user_id = Column(String, index=True)
    recipient = Column(String)
    product_type = Column(String)
    quantity = Column(Integer, nullable=True)
    months = Column(Integer, nullable=True)
    amount = Column(Float, nullable=True)
    amount_rub = Column(Float)
    currency = Column(String)
    status = Column(String)
    payment_provider = Column(String)
    payment_invoice_id = Column(String, nullable=True)
    payment_url = Column(String, nullable=True)
    idempotency_key = Column(String, nullable=True)
    robynhood_transaction_id = Column(String, nullable=True)
    robynhood_status = Column(String, nullable=True)
    fragment_transaction_id = Column(String, nullable=True)
    fragment_status = Column(String, nullable=True)
    fragment_in_progress = Column(Boolean, nullable=True)
    fragment_attempts = Column(Integer, nullable=True)
    fragment_last_error = Column(String, nullable=True)
    promo_code = Column(String, nullable=True)
    promo_percent = Column(Integer, nullable=True)
    promo_redeemed = Column(Boolean, default=False)
    amount_rub_original = Column(Float, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=now_msk)
    success_page_shown = Column(Integer, default=0)
    failure_page_shown = Column(Integer, default=0)
    expires_at = Column(DateTime(timezone=True), default=lambda: now_msk() + timedelta(minutes=10))


class PaymentTransaction(Base):
    __tablename__ = "payment_transactions"

    id = Column(Integer, primary_key=True, index=True)
    order_id = Column(String, index=True)
    provider = Column(String)
    provider_txn_id = Column(String, nullable=True)
    status = Column(String, nullable=True)
    amount = Column(Float, nullable=True)
    currency = Column(String, nullable=True)
    raw_response = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=now_msk)


class User(Base):
    __tablename__ = "users"

    user_id = Column(String, primary_key=True, index=True)
    referrer_id = Column(String, nullable=True, index=True)
    referral_balance_stars = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=now_msk)


class PromoCode(Base):
    __tablename__ = "promo_codes"

    code = Column(String, primary_key=True, index=True)
    percent = Column(Integer, nullable=False)
    max_uses = Column(Integer, nullable=True)
    uses = Column(Integer, default=0)
    active = Column(Boolean, default=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)


class PromoRedemption(Base):
    __tablename__ = "promo_redemptions"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String, index=True)
    user_id = Column(String, index=True)
    order_id = Column(String, index=True)
    percent = Column(Integer)
    created_at = Column(DateTime(timezone=True), default=now_msk)


class ReferralEarning(Base):
    __tablename__ = "referral_earnings"

    id = Column(Integer, primary_key=True, index=True)
    referrer_id = Column(String, index=True)
    referred_user_id = Column(String, index=True)
    order_id = Column(String, index=True)
    stars = Column(Integer)
    created_at = Column(DateTime(timezone=True), default=now_msk)
