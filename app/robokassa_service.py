# app/robokassa_service.py
import os
import json
import hashlib
from urllib.parse import urlencode, quote_plus

from dotenv import load_dotenv

load_dotenv()

ROBOKASSA_MERCHANT_LOGIN = os.getenv("ROBOKASSA_LOGIN")
ROBOKASSA_PASSWORD1 = os.getenv("ROBOKASSA_PASS1")  # для подписи/redirect
ROBOKASSA_PASSWORD2 = os.getenv("ROBOKASSA_PASS2")  # для проверки webhook
ROBOKASSA_IS_TEST = os.getenv("ROBOKASSA_TEST", "1")
ROBOKASSA_BASE_URL = "https://auth.robokassa.ru/Merchant/Index.aspx"
FRONTEND_ROOT = os.getenv("FRONTEND_ROOT", "/")

# ------------------------
# UTILS
# ------------------------
def _format_amount(amount: float) -> str:
    return f"{amount:.2f}"

def _product_label(order) -> str:
    if order.product_type == "stars":
        return f"Stars x{order.quantity}"
    if order.product_type == "premium":
        return f"Premium {order.months} month(s)"
    if order.product_type == "ads":
        return f"Ads amount {order.amount}"
    return order.product_type

def _receipt_json_for_order(order) -> str:
    items = [
        {
            "name": _product_label(order),
            "quantity": 1,
            "sum": float(order.amount_rub),
            "tax": "vat0",
            "payment_method": "full_payment",
            "payment_object": "commodity"
        }
    ]
    receipt = {
        "items": items,
        "email": None,
        "phone": None
    }
    return json.dumps(receipt, ensure_ascii=False, separators=(",", ":"))

def _calc_signature_with_receipt(merchant_login: str, out_sum: str, inv_id: str, receipt_str: str, password1: str) -> str:
    s = f"{merchant_login}:{out_sum}:{inv_id}:{receipt_str}:{password1}"
    return hashlib.md5(s.encode("utf-8")).hexdigest()

def generate_payment_link(order, success_url: str = None, fail_url: str = None) -> str:
    out_sum = _format_amount(order.amount_rub)
    inv_id = order.order_id
    receipt_str = _receipt_json_for_order(order)
    signature = _calc_signature_with_receipt(
        ROBOKASSA_MERCHANT_LOGIN,
        out_sum,
        inv_id,
        receipt_str,
        ROBOKASSA_PASSWORD1
    )

    data = {
        "MerchantLogin": ROBOKASSA_MERCHANT_LOGIN,
        "OutSum": out_sum,
        "InvId": inv_id,
        "Description": f"Покупка {_product_label(order)}",
        "SignatureValue": signature,
        "IsTest": ROBOKASSA_IS_TEST
    }

    success = success_url or FRONTEND_ROOT
    fail = fail_url or FRONTEND_ROOT
    data["SuccessURL"] = success
    data["FailURL"] = fail

    base_qs = urlencode(data)
    receipt_encoded = quote_plus(receipt_str)
    full_qs = f"{base_qs}&Receipt={receipt_encoded}"

    return f"{ROBOKASSA_BASE_URL}?{full_qs}"

def verify_result_signature(outsum: str, inv_id: str, signature_value: str) -> bool:
    computed = hashlib.md5(f"{outsum}:{inv_id}:{ROBOKASSA_PASSWORD2}".encode("utf-8")).hexdigest()
    return computed.lower() == (signature_value or "").lower()

def verify_success_signature(outsum: str, inv_id: str, signature_value: str) -> bool:
    computed = hashlib.md5(f"{outsum}:{inv_id}:{ROBOKASSA_PASSWORD1}".encode("utf-8")).hexdigest()
    return computed.lower() == (signature_value or "").lower()
