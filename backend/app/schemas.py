from pydantic import BaseModel, root_validator


class OrderCreateBase(BaseModel):
    user_id: str
    recipient: str
    product_type: str
    quantity: int | None = None
    months: int | None = None
    amount: float | None = None
    gift_id: int | None = None
    gift_title: str | None = None
    gift_text: str | None = None
    gift_hide_name: bool | None = None
    gift_pay_for_upgrade: bool | None = None
    gift_with_signature: bool | None = None
    gift_signature: str | None = None
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
        elif product_type == "gift":
            if not values.get("gift_id"):
                raise ValueError("gift_id is required for gift")
            if values.get("gift_with_signature") and not (values.get("gift_signature") or "").strip():
                raise ValueError("gift_signature is required when gift_with_signature is true")
        else:
            raise ValueError("product_type must be one of: stars, premium, ads, gift")

        if product_type == "gift":
            if recipient not in ("self", "me", "@unknown"):
                if recipient.isdigit():
                    pass
                else:
                    handle = recipient[1:] if recipient.startswith("@") else recipient
                    if not handle or len(handle) < 5 or len(handle) > 32:
                        raise ValueError("recipient username length is invalid")
                    if not handle.replace("_", "").isalnum():
                        raise ValueError("recipient username contains invalid characters")
                    values["recipient"] = f"@{handle}"
        else:
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


class AdminGiftPayload(BaseModel):
    gift_id: int
    title: str
    price_rub: float
    price_stars: int | None = None
    image_url: str | None = None
    sort_order: int | None = None
    active: bool = True


class StarsInvoiceOrderCreate(OrderCreateBase):
    promo_code: str | None = None
