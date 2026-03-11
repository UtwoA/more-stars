import secrets
from datetime import datetime, timedelta

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from .admin_notify import notify_admin
from .config import ADMIN_CHAT_IDS, ADMIN_OTP_TTL_MIN
from .schemas import AdminOtpVerify
from .utils import now_msk

_otp_code: str | None = None
_otp_expires_at: datetime | None = None
_sessions: dict[str, datetime] = {}


def session_valid(token: str | None) -> bool:
    if not token:
        return False
    expires_at = _sessions.get(token)
    if not expires_at:
        return False
    if expires_at <= now_msk():
        _sessions.pop(token, None)
        return False
    return True


def set_session() -> str:
    token = secrets.token_urlsafe(24)
    _sessions[token] = now_msk() + timedelta(hours=12)
    return token


async def send_otp() -> None:
    global _otp_code, _otp_expires_at
    _otp_code = f"{secrets.randbelow(1000000):06d}"
    _otp_expires_at = now_msk() + timedelta(minutes=ADMIN_OTP_TTL_MIN)
    await notify_admin(
        "🔐 Admin login code\n"
        f"Code: {_otp_code}\n"
        f"Valid: {ADMIN_OTP_TTL_MIN} min"
    )


def require_admin(request: Request) -> None:
    token = request.cookies.get("admin_otp")
    if not session_valid(token):
        raise HTTPException(status_code=401, detail="Admin OTP required")


async def otp_request() -> dict:
    if not ADMIN_CHAT_IDS:
        raise HTTPException(status_code=403, detail="Admins not configured")
    if _otp_expires_at and _otp_expires_at > now_msk():
        raise HTTPException(status_code=429, detail="OTP already sent")
    await send_otp()
    return {"status": "ok"}


async def otp_verify(payload: AdminOtpVerify) -> JSONResponse:
    if not _otp_code or not _otp_expires_at:
        raise HTTPException(status_code=400, detail="OTP not requested")
    if _otp_expires_at <= now_msk():
        raise HTTPException(status_code=400, detail="OTP expired")
    if payload.code.strip() != _otp_code:
        raise HTTPException(status_code=400, detail="Invalid code")

    session_token = set_session()
    response = JSONResponse({"status": "ok"})
    response.set_cookie(
        "admin_otp",
        session_token,
        httponly=True,
        secure=True,
        samesite="Lax",
        max_age=12 * 60 * 60,
    )
    return response

