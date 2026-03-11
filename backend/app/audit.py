from .config import MSK


def format_payment_method(order) -> str:
    if order.payment_provider == "platega":
        return "SBP" if order.payment_method == "sbp" else "Card"
    if order.payment_provider == "crypto":
        return "CryptoBot"
    if order.payment_provider == "tonconnect":
        return "TON"
    if order.payment_provider == "robokassa":
        return "Robokassa"
    return order.payment_provider or "unknown"


def format_audit_line(order) -> str:
    bonus = int(order.bonus_stars_applied or 0)
    qty = int(order.quantity or 0)
    total = qty + bonus
    when = order.timestamp.astimezone(MSK).strftime("%Y-%m-%d %H:%M")
    user = f"id {order.user_id}"
    pay = format_payment_method(order)
    return (
        f"⭐ {total} ({qty}+{bonus}) | {user} | {pay} | {when}\n"
        f"order: {order.order_id}"
    )


def format_audit_line_with_user(order, display_name: str | None) -> str:
    bonus = int(order.bonus_stars_applied or 0)
    qty = int(order.quantity or 0)
    total = qty + bonus
    when = order.timestamp.astimezone(MSK).strftime("%Y-%m-%d %H:%M")
    if display_name:
        user = f"{display_name} (id {order.user_id})"
    elif getattr(order, "user_username", None):
        user = f"{order.user_username} (id {order.user_id})"
    else:
        user = f"id {order.user_id}"
    pay = format_payment_method(order)
    return (
        f"⭐ {total} ({qty}+{bonus}) | {user} | {pay} | {when}\n"
        f"order: {order.order_id}"
    )

