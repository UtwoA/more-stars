import hashlib
import hmac
import json
from urllib.parse import parse_qsl, unquote_plus

from .security import constant_time_eq


def verify_telegram_init_data(init_data: str, *, bot_token: str | None) -> bool:
    if not init_data or not bot_token:
        return False
    parsed = dict(parse_qsl(init_data, keep_blank_values=True))
    hash_value = parsed.pop("hash", "")
    if not hash_value:
        return False

    data_check = "\n".join(f"{k}={parsed[k]}" for k in sorted(parsed))

    def _verify_with_secret(secret_key: bytes) -> bool:
        h = hmac.new(secret_key, data_check.encode(), hashlib.sha256).hexdigest()
        return constant_time_eq(h, hash_value)

    webapp_secret = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    if _verify_with_secret(webapp_secret):
        return True

    legacy_secret = hashlib.sha256(bot_token.encode()).digest()
    return _verify_with_secret(legacy_secret)


def extract_user_fields(init_data: str | None) -> tuple[str | None, str | None, str | None]:
    if not init_data:
        return None, None, None
    try:
        parsed = dict(parse_qsl(init_data, keep_blank_values=True))
        user_raw = parsed.get("user")
        if not user_raw:
            return None, None, None
        user = json.loads(unquote_plus(user_raw))
        username = (user.get("username") or "").strip() or None
        first = (user.get("first_name") or "").strip()
        last = (user.get("last_name") or "").strip()
        full = " ".join(part for part in [first, last] if part).strip() or None
        display = f"@{username}" if username else full
        return username, full, display
    except Exception:
        return None, None, None


def extract_user_id(init_data: str | None) -> str | None:
    if not init_data:
        return None
    try:
        parsed = dict(parse_qsl(init_data, keep_blank_values=True))
        user_raw = parsed.get("user")
        if not user_raw:
            return None
        user = json.loads(unquote_plus(user_raw))
        uid = user.get("id")
        return str(uid) if uid is not None else None
    except Exception:
        return None


def extract_referrer_id(init_data: str | None) -> str | None:
    if not init_data:
        return None
    try:
        parsed = dict(parse_qsl(init_data, keep_blank_values=True))
        start_param = (parsed.get("start_param") or "").strip()
        if not start_param:
            return None
        if start_param.startswith("ref_"):
            start_param = start_param.replace("ref_", "", 1)
        if start_param.isdigit():
            return start_param
    except Exception:
        return None
    return None


def touch_user_from_initdata(db, *, user_id: str, init_data: str | None, user_model) -> str | None:
    username, full_name, display = extract_user_fields(init_data)
    referrer_id = extract_referrer_id(init_data)
    if not username and not full_name:
        return display
    user = db.query(user_model).filter(user_model.user_id == user_id).first()
    if not user:
        user = user_model(user_id=user_id)
        db.add(user)
    if username:
        user.username = username
    if full_name:
        user.full_name = full_name
    if referrer_id and referrer_id != user_id and not user.referrer_id:
        user.referrer_id = referrer_id
    db.commit()
    return display

