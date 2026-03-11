import hashlib
import hmac
import json

from fastapi import APIRouter, Header, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import text

from ..crypto_pay import verify_signature
from ..database import engine
from ..robokassa_service import verify_result_signature


def build_webhooks_router(ctx) -> APIRouter:
    router = APIRouter()

    SessionLocal = ctx.SessionLocal
    Order = ctx.Order

    logger = ctx.logger

    PLATEGA_MERCHANT_ID = ctx.PLATEGA_MERCHANT_ID
    PLATEGA_SECRET = ctx.PLATEGA_SECRET
    PLATEGA_WEBHOOK_SIGNING_SECRET = ctx.PLATEGA_WEBHOOK_SIGNING_SECRET
    PLATEGA_WEBHOOK_IP_ALLOWLIST = ctx.PLATEGA_WEBHOOK_IP_ALLOWLIST
    PLATEGA_WEBHOOK_TOKEN = ctx.PLATEGA_WEBHOOK_TOKEN

    _constant_time_eq = ctx._constant_time_eq
    _client_ip = ctx._client_ip
    _extract_order_id = ctx._extract_order_id
    _release_promo_reservation = ctx._release_promo_reservation
    _release_bonus_reservation = ctx._release_bonus_reservation
    _fulfill_order_if_needed = ctx._fulfill_order_if_needed

    @router.post("/webhook/crypto")
    async def crypto_webhook(request: Request, crypto_pay_api_signature: str = Header(None)):
        if not crypto_pay_api_signature:
            raise HTTPException(status_code=400, detail="Missing crypto-pay-api-signature header")

        raw_body = await request.body()
        if not verify_signature(raw_body, crypto_pay_api_signature):
            raise HTTPException(status_code=403, detail="Invalid signature")

        data = await request.json()
        logger.info(f"WEBHOOK CRYPTO DATA: {json.dumps(data)}")

        order_id = _extract_order_id(data)
        if not order_id:
            return {"status": "error", "message": "No order_id found"}

        status = data.get("status") or data.get("payload", {}).get("status")

        db = SessionLocal()
        try:
            order = db.query(Order).filter(Order.order_id == order_id).first()
            if not order:
                return {"status": "error", "message": "Order not found"}

            if status == "paid" and order.status != "paid":
                order.status = "paid"
                db.commit()
                await _fulfill_order_if_needed(order, db)
            elif status in ("expired", "failed"):
                order.status = "failed"
                db.commit()
                _release_promo_reservation(order, db)
                _release_bonus_reservation(order, db)
        finally:
            db.close()

        return {"status": "ok"}

    @router.post("/webhook/platega/{token}")
    async def platega_webhook(
        token: str,
        request: Request,
        x_signature: str | None = Header(default=None, alias="X-Signature"),
    ):
        if not PLATEGA_WEBHOOK_TOKEN:
            raise HTTPException(status_code=500, detail="PLATEGA_WEBHOOK_TOKEN is not configured")
        if not _constant_time_eq(token, PLATEGA_WEBHOOK_TOKEN):
            raise HTTPException(status_code=404, detail="Not found")
        merchant_id = request.headers.get("X-MerchantId")
        secret = request.headers.get("X-Secret")
        if not merchant_id or not secret:
            raise HTTPException(status_code=400, detail="Missing X-MerchantId or X-Secret")
        if merchant_id != PLATEGA_MERCHANT_ID or not _constant_time_eq(secret, PLATEGA_SECRET or ""):
            raise HTTPException(status_code=403, detail="Invalid credentials")

        body = await request.body()
        if PLATEGA_WEBHOOK_SIGNING_SECRET:
            calc = hmac.new(PLATEGA_WEBHOOK_SIGNING_SECRET.encode(), body, hashlib.sha256).hexdigest()
            if not x_signature or not _constant_time_eq(calc, x_signature):
                raise HTTPException(status_code=403, detail="Invalid signature")
        if PLATEGA_WEBHOOK_IP_ALLOWLIST:
            ip = _client_ip(request)
            if ip not in PLATEGA_WEBHOOK_IP_ALLOWLIST:
                raise HTTPException(status_code=403, detail="IP not allowed")

        data = json.loads(body.decode("utf-8") or "{}")
        logger.info("WEBHOOK PLATEGA DATA: %s", json.dumps(data))

        transaction_id = data.get("id")
        status = (data.get("status") or "").upper()
        if not transaction_id:
            return {"status": "error", "message": "No transaction id"}

        db = SessionLocal()
        try:
            order = db.query(Order).filter(Order.payment_invoice_id == transaction_id).first()
            if not order:
                return {"status": "error", "message": "Order not found"}

            with engine.begin() as conn:
                conn.execute(
                    text(
                        """
                        INSERT INTO payment_transactions
                        (order_id, provider, provider_txn_id, status, raw_response)
                        VALUES (:order_id, :provider, :provider_txn_id, :status, :raw_response)
                        """
                    ),
                    {
                        "order_id": order.order_id,
                        "provider": "platega_webhook",
                        "provider_txn_id": transaction_id,
                        "status": status,
                        "raw_response": json.dumps(data),
                    },
                )

            if status == "CONFIRMED" and order.status != "paid":
                order.status = "paid"
                db.commit()
                await _fulfill_order_if_needed(order, db)
            elif status in ("CANCELED", "CHARGEBACKED"):
                order.status = "failed"
                db.commit()
                _release_bonus_reservation(order, db)
        finally:
            db.close()

        return {"status": "ok"}

    @router.post("/webhook/robokassa")
    async def robokassa_webhook(
        OutSum: str = Query(...),
        InvId: str = Query(...),
        SignatureValue: str = Query(...),
    ):
        if not verify_result_signature(OutSum, InvId, SignatureValue):
            raise HTTPException(status_code=403, detail="Invalid signature")

        db = SessionLocal()
        try:
            order = db.query(Order).filter(Order.order_id == InvId).first()
            if not order:
                return PlainTextResponse(content=f"Order not found: {InvId}", status_code=404)

            if order.status != "paid":
                order.status = "paid"
                db.commit()
                await _fulfill_order_if_needed(order, db)

            return PlainTextResponse(content=f"OK{InvId}", status_code=200)
        finally:
            db.close()

    return router

