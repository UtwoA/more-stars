import logging

from sqlalchemy import text

logger = logging.getLogger("db_init")


def init_schema(*, engine, base) -> None:
    base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS fragment_transaction_id VARCHAR"))
        conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS fragment_status VARCHAR"))
        conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS fragment_in_progress BOOLEAN"))
        conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS fragment_attempts INTEGER"))
        conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS fragment_last_error VARCHAR"))
        conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS promo_code VARCHAR"))
        conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS promo_percent INTEGER"))
        conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS promo_redeemed BOOLEAN"))
        conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS amount_rub_original FLOAT"))
        conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS bonus_stars_applied INTEGER DEFAULT 0"))
        conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS bonus_grant_id INTEGER"))
        conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_method VARCHAR"))
        conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS user_username VARCHAR"))
        conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS audit_sent BOOLEAN DEFAULT FALSE"))
        conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_amount FLOAT"))
        conn.execute(text("ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_amount_nano VARCHAR"))
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR"))
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR"))
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS admin_settings (
                    key VARCHAR PRIMARY KEY,
                    value VARCHAR NOT NULL,
                    updated_at TIMESTAMPTZ DEFAULT now()
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS payment_transactions (
                    id SERIAL PRIMARY KEY,
                    order_id VARCHAR NOT NULL,
                    provider VARCHAR NOT NULL,
                    provider_txn_id VARCHAR,
                    status VARCHAR,
                    amount FLOAT,
                    currency VARCHAR,
                    raw_response TEXT,
                    created_at TIMESTAMPTZ DEFAULT now()
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS app_events (
                    id SERIAL PRIMARY KEY,
                    event_type VARCHAR NOT NULL,
                    user_id VARCHAR,
                    created_at TIMESTAMPTZ DEFAULT now()
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id VARCHAR PRIMARY KEY,
                    referrer_id VARCHAR,
                    referral_balance_stars INTEGER DEFAULT 0,
                    created_at TIMESTAMPTZ DEFAULT now()
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS bonus_grants (
                    id SERIAL PRIMARY KEY,
                    user_id VARCHAR NOT NULL,
                    stars INTEGER NOT NULL,
                    status VARCHAR DEFAULT 'active',
                    source VARCHAR,
                    expires_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ DEFAULT now(),
                    consumed_at TIMESTAMPTZ,
                    consumed_order_id VARCHAR
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS bonus_claims (
                    id SERIAL PRIMARY KEY,
                    token VARCHAR UNIQUE,
                    stars INTEGER NOT NULL,
                    status VARCHAR DEFAULT 'active',
                    source VARCHAR,
                    max_uses INTEGER DEFAULT 1,
                    uses INTEGER DEFAULT 0,
                    expires_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ DEFAULT now(),
                    claimed_user_id VARCHAR,
                    claimed_at TIMESTAMPTZ
                )
                """
            )
        )
        conn.execute(text("ALTER TABLE bonus_claims ADD COLUMN IF NOT EXISTS max_uses INTEGER DEFAULT 1"))
        conn.execute(text("ALTER TABLE bonus_claims ADD COLUMN IF NOT EXISTS uses INTEGER DEFAULT 0"))
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS bonus_claim_redemptions (
                    id SERIAL PRIMARY KEY,
                    claim_id INTEGER NOT NULL,
                    user_id VARCHAR NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT now()
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS promo_codes (
                    code VARCHAR PRIMARY KEY,
                    percent INTEGER NOT NULL,
                    max_uses INTEGER,
                    uses INTEGER DEFAULT 0,
                    active BOOLEAN DEFAULT TRUE,
                    expires_at TIMESTAMPTZ
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS promo_redemptions (
                    id SERIAL PRIMARY KEY,
                    code VARCHAR,
                    user_id VARCHAR,
                    order_id VARCHAR,
                    percent INTEGER,
                    created_at TIMESTAMPTZ DEFAULT now()
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS promo_reservations (
                    id SERIAL PRIMARY KEY,
                    code VARCHAR,
                    user_id VARCHAR,
                    percent INTEGER,
                    order_id VARCHAR,
                    expires_at TIMESTAMPTZ NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT now()
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS referral_earnings (
                    id SERIAL PRIMARY KEY,
                    referrer_id VARCHAR,
                    referred_user_id VARCHAR,
                    order_id VARCHAR,
                    stars INTEGER,
                    created_at TIMESTAMPTZ DEFAULT now()
                )
                """
            )
        )

    logger.info("DB schema ensured")

