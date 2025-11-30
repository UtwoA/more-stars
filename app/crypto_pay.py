import os
import hmac
import hashlib
import httpx
import json
import asyncio
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Header, HTTPException

from app.main import logger

load_dotenv()

CRYPTO_PAY_API_URL = "https://testnet-pay.crypt.bot/v1/invoice"
API_TOKEN = os.getenv("CRYPTOBOT_TOKEN")  # твой токен

app = FastAPI()


def create_invoice(amount: float, currency: str, order_id: str, recipient: str):
    """
    Создаем инвойс в Crypto Pay API
    """
    payload = {
        "currency_type": "crypto",
        "asset": currency.upper(),
        "amount": amount,
        "payload": order_id,
        "description": f"Покупка {recipient}",
        "allow_comments": False,
        "allow_anonymous": False
    }

    headers = {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json"
    }

    response = httpx.post(CRYPTO_PAY_API_URL, json=payload, headers=headers, timeout=15)
    response.raise_for_status()
    return response.json()



def verify_signature(request_body: bytes, signature: str) -> bool:
    """
    Проверка HMAC подписи вебхука Crypto Pay
    """
    computed_signature = hmac.new(API_TOKEN.encode(), request_body, hashlib.sha256).hexdigest()
    logger.info(f"Computed signature: {computed_signature}")
    return hmac.compare_digest(computed_signature, signature)