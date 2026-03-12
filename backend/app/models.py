from datetime import timedelta
from sqlalchemy import Column, String, Integer, Float, DateTime, Boolean, Text, BigInteger
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
    payment_method = Column(String, nullable=True)
    user_username = Column(String, nullable=True)
    payment_amount = Column(Float, nullable=True)
    payment_amount_nano = Column(String, nullable=True)
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
    bonus_stars_applied = Column(Integer, default=0)
    bonus_grant_id = Column(Integer, nullable=True)
    cost_rub = Column(Float, nullable=True)
    profit_rub = Column(Float, nullable=True)
    usdtrub_rate = Column(Float, nullable=True)
    cost_per_star = Column(Float, nullable=True)
    gift_id = Column(BigInteger, nullable=True)
    gift_title = Column(String, nullable=True)
    gift_text = Column(Text, nullable=True)
    gift_hide_name = Column(Boolean, nullable=True)
    gift_pay_for_upgrade = Column(Boolean, nullable=True)
    gift_with_signature = Column(Boolean, nullable=True)
    gift_signature = Column(String, nullable=True)
    gift_status = Column(String, nullable=True)
    gift_in_progress = Column(Boolean, nullable=True)
    gift_attempts = Column(Integer, nullable=True)
    gift_last_error = Column(String, nullable=True)
    audit_sent = Column(Boolean, default=False)
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
    username = Column(String, nullable=True)
    full_name = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=now_msk)


class BonusGrant(Base):
    __tablename__ = "bonus_grants"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True)
    stars = Column(Integer, nullable=False)
    status = Column(String, default="active")
    source = Column(String, nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=now_msk)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    consumed_order_id = Column(String, nullable=True)


class BonusClaim(Base):
    __tablename__ = "bonus_claims"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True)
    stars = Column(Integer, nullable=False)
    status = Column(String, default="active")
    source = Column(String, nullable=True)
    max_uses = Column(Integer, default=1)
    uses = Column(Integer, default=0)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=now_msk)
    claimed_user_id = Column(String, nullable=True)
    claimed_at = Column(DateTime(timezone=True), nullable=True)


class BonusClaimRedemption(Base):
    __tablename__ = "bonus_claim_redemptions"

    id = Column(Integer, primary_key=True, index=True)
    claim_id = Column(Integer, index=True)
    user_id = Column(String, index=True)
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


class PromoReservation(Base):
    __tablename__ = "promo_reservations"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String, index=True)
    user_id = Column(String, index=True)
    percent = Column(Integer)
    order_id = Column(String, nullable=True, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=now_msk)


class ReferralEarning(Base):
    __tablename__ = "referral_earnings"

    id = Column(Integer, primary_key=True, index=True)
    referrer_id = Column(String, index=True)
    referred_user_id = Column(String, index=True)
    order_id = Column(String, index=True)
    stars = Column(Integer)
    created_at = Column(DateTime(timezone=True), default=now_msk)


class AdminSetting(Base):
    __tablename__ = "admin_settings"

    key = Column(String, primary_key=True, index=True)
    value = Column(String, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=now_msk)


class GiftCatalog(Base):
    __tablename__ = "gift_catalog"

    id = Column(Integer, primary_key=True, index=True)
    gift_id = Column(BigInteger, unique=True, index=True, nullable=False)
    title = Column(String, nullable=False)
    price_rub = Column(Float, nullable=False)
    price_stars = Column(Integer, nullable=True)
    image_url = Column(String, nullable=True)
    sort_order = Column(Integer, nullable=True)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=now_msk)
    updated_at = Column(DateTime(timezone=True), default=now_msk)
