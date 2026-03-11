from decimal import Decimal, ROUND_HALF_UP


def round_money(value: float | None) -> float | None:
    if value is None:
        return None
    return float(Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def to_nano(ton_amount: float) -> int:
    return int(Decimal(str(ton_amount)) * Decimal("1000000000"))

