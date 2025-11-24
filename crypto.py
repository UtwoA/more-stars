import requests
import os
import hmac
import hashlib

CRYPTOBOT_TOKEN = os.getenv("CRYPTOBOT_TOKEN")
DOMAIN = os.getenv("DOMAIN", "https://more-stars.online")

def create_cryptobot_invoice(order_id: int, amount_rub: float, item_title: str, recipient: str):
    """
    Создаёт инвойс в CryptoBot и возвращает ссылку на оплату и invoice_id
    """
    url = "https://api.crypto.bot/v1/invoice/create"
    payload = {
        "token": CRYPTOBOT_TOKEN,
        "amount": float(amount_rub),
        "currency": "RUB",
        "description": f"{item_title} для {recipient}",
        "webhook_url": f"{DOMAIN}/orders/cryptobot-webhook",
        "order_id": order_id
    }
    resp = requests.post(url, json=payload)
    data = resp.json()
    if not data.get("ok"):
        raise Exception(f"CryptoBot error: {data}")
    invoice_id = data["result"]["invoice_id"]
    return data["result"]["payment_url"], invoice_id


def verify_cryptobot_signature(payload: str, signature: str):
    """
    Проверка подписи webhook через токен CryptoBot
    """
    secret = CRYPTOBOT_TOKEN.encode()
    computed_sig = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, computed_sig)
