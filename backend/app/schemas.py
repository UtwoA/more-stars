from pydantic import BaseModel, root_validator


class OrderCreateBase(BaseModel):
    user_id: str
    recipient: str
    product_type: str
    quantity: int | None = None
    months: int | None = None
    amount: float | None = None
    amount_rub: float

    @root_validator(skip_on_failure=True)
    def validate_product_fields(cls, values):
        product_type = (values.get("product_type") or "").lower()
        values["product_type"] = product_type

        quantity = values.get("quantity")
        months = values.get("months")
        amount = values.get("amount")
        recipient = (values.get("recipient") or "").strip()

        if product_type == "stars":
            if not quantity:
                raise ValueError("quantity is required for stars")
        elif product_type == "premium":
            if not months:
                raise ValueError("months is required for premium")
        elif product_type == "ads":
            if amount is None:
                raise ValueError("amount is required for ads")
        else:
            raise ValueError("product_type must be one of: stars, premium, ads")

        if recipient not in ("self", "@unknown"):
            if not recipient.startswith("@"):
                raise ValueError("recipient must start with @")
            handle = recipient[1:]
            if not handle or len(handle) < 5 or len(handle) > 32:
                raise ValueError("recipient username length is invalid")
            if not handle.replace("_", "").isalnum():
                raise ValueError("recipient username contains invalid characters")

        user_id = values.get("user_id")
        if not user_id or not str(user_id).isdigit():
            raise ValueError("user_id must be numeric")

        return values


class CryptoOrderCreate(OrderCreateBase):
    currency: str  # TON / USDT
    promo_code: str | None = None


class RobokassaOrderCreate(OrderCreateBase):
    pass


class PlategaOrderCreate(OrderCreateBase):
    payment_method: int | None = None
    promo_code: str | None = None


class TonConnectOrderCreate(OrderCreateBase):
    promo_code: str | None = None


class AdminOtpVerify(BaseModel):
    code: str


class AdminSettingsPayload(BaseModel):
    referral_percent: int | None = None
    report_time: str | None = None
    stars_rate_1: float | None = None
    stars_rate_2: float | None = None
    stars_rate_3: float | None = None
    raffle_prize_title: str | None = None
    raffle_prize_desc: str | None = None
    raffle_prize_image: str | None = None
    banner_enabled: bool | None = None
    banner_title: str | None = None
    banner_text: str | None = None
    banner_url: str | None = None
    banner_until: str | None = None
    promo_text: str | None = None


class AdminPromoPayload(BaseModel):
    code: str
    percent: int
    max_uses: int | None = None
    active: bool = True
    expires_at: str | None = None


class AdminBonusClaimPayload(BaseModel):
    stars: int
    ttl_minutes: int | None = None
    max_uses: int | None = None
    source: str | None = None


class AdminBonusBulkPayload(BaseModel):
    user_ids: str
    stars: int
    ttl_minutes: int | None = None
    source: str | None = None


class AnalyticsEventPayload(BaseModel):
    event_type: str

