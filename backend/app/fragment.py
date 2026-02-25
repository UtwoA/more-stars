import base64
import json
import logging
import os
import re
from urllib.parse import urlencode

import httpx
from dotenv import load_dotenv
from TonTools import TonCenterClient, Wallet
from tonsdk.contract.wallet import Wallets, WalletVersionEnum
from tonsdk.utils import from_nano

from .database import SessionLocal
from .models import Order

load_dotenv()

logger = logging.getLogger("fragment")

FRAGMENT_BASE_URL = "https://fragment.com"

FRAGMENT_COOKIES_JSON = os.getenv("FRAGMENT_COOKIES_JSON")
FRAGMENT_COOKIES = os.getenv("FRAGMENT_COOKIES")
FRAGMENT_COOKIE_STEL_DT = os.getenv("FRAGMENT_COOKIE_STEL_DT")
FRAGMENT_COOKIE_STEL_SSID = os.getenv("FRAGMENT_COOKIE_STEL_SSID")
FRAGMENT_COOKIE_STEL_TOKEN = os.getenv("FRAGMENT_COOKIE_STEL_TOKEN")
FRAGMENT_COOKIE_STEL_TON_TOKEN = os.getenv("FRAGMENT_COOKIE_STEL_TON_TOKEN")

FRAGMENT_WALLET_MNEMONICS = os.getenv("FRAGMENT_WALLET_MNEMONICS")
FRAGMENT_WALLET_VERSION = os.getenv("FRAGMENT_WALLET_VERSION", "v4r2")
FRAGMENT_TESTNET = os.getenv("FRAGMENT_TESTNET", "false").lower() in ("1", "true", "yes")
FRAGMENT_SEND_MODE = int(os.getenv("FRAGMENT_SEND_MODE", "1"))
FRAGMENT_SHOW_SENDER = int(os.getenv("FRAGMENT_SHOW_SENDER", "0"))
TONCENTER_API_KEY = os.getenv("TONCENTER_API_KEY")


def _load_fragment_cookies() -> dict:
    if FRAGMENT_COOKIES_JSON:
        with open(FRAGMENT_COOKIES_JSON, "r", encoding="utf-8") as f:
            raw = json.load(f)
            if isinstance(raw, list):
                return {item["name"]: item["value"] for item in raw if "name" in item and "value" in item}
            if isinstance(raw, dict):
                return raw
            raise RuntimeError("Unsupported cookies JSON format")
    if FRAGMENT_COOKIES:
        return json.loads(FRAGMENT_COOKIES)

    cookie_map = {}
    if FRAGMENT_COOKIE_STEL_DT:
        cookie_map["stel_dt"] = FRAGMENT_COOKIE_STEL_DT
    if FRAGMENT_COOKIE_STEL_SSID:
        cookie_map["stel_ssid"] = FRAGMENT_COOKIE_STEL_SSID
    if FRAGMENT_COOKIE_STEL_TOKEN:
        cookie_map["stel_token"] = FRAGMENT_COOKIE_STEL_TOKEN
    if FRAGMENT_COOKIE_STEL_TON_TOKEN:
        cookie_map["stel_ton_token"] = FRAGMENT_COOKIE_STEL_TON_TOKEN

    if cookie_map:
        return cookie_map

    raise RuntimeError("Fragment cookies are not configured")


def _get_mnemonics() -> list[str]:
    if not FRAGMENT_WALLET_MNEMONICS:
        raise RuntimeError("FRAGMENT_WALLET_MNEMONICS is not set")
    return [word for word in FRAGMENT_WALLET_MNEMONICS.split() if word]


def _get_public_key_hex(mnemonics: list[str], version: str) -> str:
    _, pub_k, _, _ = Wallets.from_mnemonics(
        mnemonics=mnemonics,
        version=getattr(WalletVersionEnum, version),
        workchain=0,
    )
    return pub_k.hex()


async def _get_fragment_hash(cookies: dict) -> str:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/132.0.0.0 Safari/537.36 OPR/117.0.0.0"
        )
    }
    async with httpx.AsyncClient(headers=headers, follow_redirects=True) as client:
        r = await client.get(f"{FRAGMENT_BASE_URL}/stars/buy", cookies=cookies, timeout=15)
        r.raise_for_status()
        text = r.text.replace("\\/", "/")
        match = re.search(r"api\?hash=([a-zA-Z0-9]+)", text)
        if not match:
            match = re.search(r"hash\\s*[:=]\\s*\"([a-zA-Z0-9]+)\"", text)
        if not match:
            match = re.search(r"apiHash\\s*[:=]\\s*\"([a-zA-Z0-9]+)\"", text)
        if not match:
            logger.error(
                "Fragment hash not found. Status=%s Url=%s BodyHead=%s",
                r.status_code,
                str(r.url),
                text[:500].replace("\n", " "),
            )
            raise RuntimeError("Fragment hash not found (check cookies / auth)")
        return match.group(1)


def _build_payload(req_id: str, public_key_hex: str) -> str:
    payload = {
        "account": json.dumps({"chain": "-239", "publicKey": public_key_hex}),
        "device": json.dumps(
            {
                "platform": "web",
                "appName": "telegram-wallet",
                "appVersion": "1",
                "maxProtocolVersion": 2,
                "features": ["SendTransaction", {"name": "SendTransaction", "maxMessages": 4}],
            }
        ),
        "transaction": 1,
        "id": req_id,
        "show_sender": FRAGMENT_SHOW_SENDER,
        "method": "getBuyStarsLink",
    }
    return urlencode(payload)


def _decode_payload(encoded_payload: str) -> str:
    padding_needed = len(encoded_payload) % 4
    if padding_needed:
        encoded_payload += "=" * (4 - padding_needed)
    decoded_payload = base64.b64decode(encoded_payload)
    return decoded_payload.split(b"\x00")[-1].decode("utf-8")


async def _get_payment_data(recipient: str, quantity: int, mnemonics: list[str]) -> tuple[str, int, str]:
    cookies = _load_fragment_cookies()
    public_key_hex = _get_public_key_hex(mnemonics, FRAGMENT_WALLET_VERSION)
    hash_value = await _get_fragment_hash(cookies)
    url = f"{FRAGMENT_BASE_URL}/api?hash={hash_value}"

    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Referer": f"{FRAGMENT_BASE_URL}/stars/buy",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/132.0.0.0 Safari/537.36 OPR/117.0.0.0"
        ),
    }

    async with httpx.AsyncClient(headers=headers, cookies=cookies) as client:
        search_resp = await client.post(
            url,
            data=f"query={recipient}&quantity=&method=searchStarsRecipient",
            timeout=15,
        )
        search_resp.raise_for_status()
        recipient_id = search_resp.json().get("found", {}).get("recipient", "")
        if not recipient_id:
            raise RuntimeError("Fragment recipient not found")

        init_resp = await client.post(
            url,
            data=f"recipient={recipient_id}&quantity={quantity}&method=initBuyStarsRequest",
            timeout=15,
        )
        init_resp.raise_for_status()
        req_id = init_resp.json().get("req_id", "")
        if not req_id:
            raise RuntimeError("Fragment request id not received")

        payload = _build_payload(req_id, public_key_hex)
        payload_resp = await client.post(url, data=payload, timeout=15)
        payload_resp.raise_for_status()
        payload_json = payload_resp.json()

    message = payload_json["transaction"]["messages"][0]
    address = message["address"]
    amount = int(message["amount"])
    decoded_payload = _decode_payload(message["payload"])
    return address, amount, decoded_payload


async def _send_ton(
    mnemonics: list[str],
    destination_address: str,
    amount: int,
    payload: str,
) -> bool:
    provider = TonCenterClient(testnet=FRAGMENT_TESTNET, api_key=TONCENTER_API_KEY)
    wallet = Wallet(mnemonics=mnemonics, version=FRAGMENT_WALLET_VERSION, provider=provider)

    ton_amount = from_nano(amount, "ton")
    clean_payload = payload.replace("\n", " ")
    logger.warning(
        "Sending %s TON to %s with payload: %s",
        ton_amount,
        destination_address,
        clean_payload,
    )

    status = await wallet.transfer_ton(
        destination_address=destination_address,
        amount=ton_amount,
        message=payload,
        send_mode=FRAGMENT_SEND_MODE,
    )
    if status != 200:
        logger.error("Fragment transaction failed")
        return False

    logger.info("Fragment transaction sent")
    return True


async def send_purchase_to_fragment(order: Order) -> dict:
    if order.product_type != "stars":
        raise RuntimeError("Fragment API currently supports only stars")

    mnemonics = _get_mnemonics()
    address, amount, payload = await _get_payment_data(
        recipient=order.recipient,
        quantity=order.quantity,
        mnemonics=mnemonics,
    )

    success = await _send_ton(mnemonics, address, amount, payload)
    resp = {"status": "success" if success else "failed"}

    db = SessionLocal()
    db_order = db.query(Order).filter(Order.order_id == order.order_id).first()
    if db_order:
        db_order.robynhood_transaction_id = address
        db_order.robynhood_status = resp.get("status")
        db.commit()
    db.close()

    return resp
