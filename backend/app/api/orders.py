import secrets

import httpx
from fastapi import APIRouter, HTTPException, Query, Request

from ..schemas import CryptoOrderCreate, PlategaOrderCreate, RobokassaOrderCreate, TonConnectOrderCreate


def build_orders_router(ctx) -> APIRouter:
    router = APIRouter()

    SessionLocal = ctx.SessionLocal
    Order = ctx.Order
    PromoReservation = ctx.PromoReservation

    MSK = ctx.MSK
    PLATEGA_PAYMENT_METHOD = ctx.PLATEGA_PAYMENT_METHOD
    TONCONNECT_WALLET_ADDRESS = ctx.TONCONNECT_WALLET_ADDRESS

    logger = ctx.logger

    _stars_base_price = ctx._stars_base_price
    _get_active_reservation = ctx._get_active_reservation
    _round_money = ctx._round_money
    _touch_user_from_initdata = ctx._touch_user_from_initdata
    _create_order = ctx._create_order
    _reserve_bonus_for_order = ctx._reserve_bonus_for_order
    _create_crypto_invoice = ctx._create_crypto_invoice
    _create_platega_payment_with_method = ctx._create_platega_payment_with_method
    _sync_crypto_order_status = ctx._sync_crypto_order_status
    _sync_platega_order_status = ctx._sync_platega_order_status
    _sync_tonconnect_order_status = ctx._sync_tonconnect_order_status
    _check_order_expired = ctx._check_order_expired
    _notify_admin = ctx._notify_admin
    _to_nano = ctx._to_nano

    convert_rub_to_crypto = ctx.convert_rub_to_crypto

    @router.post("/orders/crypto")
    async def create_order_crypto(order: CryptoOrderCreate, request: Request):
        if order.product_type != "stars":
            raise HTTPException(status_code=400, detail="Only Stars are supported right now")
        db = SessionLocal()
        try:
            amount_rub = _stars_base_price(order.quantity or 0)
            promo_percent = 0
            if order.promo_code:
                reservation = _get_active_reservation(order.promo_code, order.user_id, db)
                if not reservation:
                    raise HTTPException(status_code=400, detail="Invalid or expired promo")
                promo_percent = reservation.percent
                amount_rub = amount_rub * (1 - promo_percent / 100)
            order.amount_rub = _round_money(amount_rub) or amount_rub
            amount_crypto = await convert_rub_to_crypto(amount_rub, order.currency)

            init_data = request.headers.get("x-telegram-init-data")
            user_username = _touch_user_from_initdata(db, order.user_id, init_data)
            db_order = _create_order(
                db,
                order,
                provider="crypto",
                currency=order.currency,
                payment_method="cryptobot",
                user_username=user_username,
            )
            if order.promo_code and promo_percent:
                db_order.promo_code = order.promo_code.upper()
                db_order.promo_percent = promo_percent
                db_order.amount_rub_original = _stars_base_price(order.quantity or 0)
                db_order.amount_rub = _round_money(amount_rub) or amount_rub
                db.query(PromoReservation).filter(
                    PromoReservation.code == db_order.promo_code,
                    PromoReservation.user_id == db_order.user_id,
                ).update({"order_id": db_order.order_id})
                db.commit()

            _reserve_bonus_for_order(db_order, db)

            invoice = await _create_crypto_invoice(amount_crypto, order.currency, db_order.order_id, db_order.recipient)

            db_order.payment_invoice_id = str(invoice.get("result", {}).get("invoice_id") or "")
            db.commit()

            return {
                "order_id": db_order.order_id,
                "amount_rub": _round_money(db_order.amount_rub),
                "amount_crypto": amount_crypto,
                "currency": order.currency,
                "crypto_invoice": invoice,
            }
        finally:
            db.close()

    @router.post("/orders/robokassa")
    async def create_order_robokassa(order: RobokassaOrderCreate):
        raise HTTPException(status_code=503, detail="SBP/Robokassa payment is temporarily unavailable")

    @router.post("/orders/platega")
    async def create_order_platega(order: PlategaOrderCreate, request: Request):
        if order.product_type != "stars":
            raise HTTPException(status_code=400, detail="Only Stars are supported right now")

        payment_method = order.payment_method or PLATEGA_PAYMENT_METHOD
        if payment_method not in (2, 11):
            raise HTTPException(status_code=400, detail="Unsupported payment method")

        db = SessionLocal()
        try:
            amount_rub = _stars_base_price(order.quantity or 0)
            promo_percent = 0
            if order.promo_code:
                reservation = _get_active_reservation(order.promo_code, order.user_id, db)
                if not reservation:
                    raise HTTPException(status_code=400, detail="Invalid or expired promo")
                promo_percent = reservation.percent
                amount_rub = amount_rub * (1 - promo_percent / 100)
            order.amount_rub = _round_money(amount_rub) or amount_rub

            init_data = request.headers.get("x-telegram-init-data")
            user_username = _touch_user_from_initdata(db, order.user_id, init_data)
            payment_method_label = "sbp" if payment_method == 2 else "card"
            db_order = _create_order(
                db,
                order,
                provider="platega",
                currency="RUB",
                payment_method=payment_method_label,
                user_username=user_username,
            )
            if order.promo_code and promo_percent:
                db_order.promo_code = order.promo_code.upper()
                db_order.promo_percent = promo_percent
                db_order.amount_rub_original = _stars_base_price(order.quantity or 0)
                db_order.amount_rub = _round_money(amount_rub) or amount_rub
                db.query(PromoReservation).filter(
                    PromoReservation.code == db_order.promo_code,
                    PromoReservation.user_id == db_order.user_id,
                ).update({"order_id": db_order.order_id})
                db.commit()
            _reserve_bonus_for_order(db_order, db)
            try:
                payment = await _create_platega_payment_with_method(db_order.amount_rub, db_order.order_id, payment_method)
            except httpx.HTTPStatusError as exc:
                detail = "Platega error"
                if exc.response is not None:
                    detail = exc.response.text
                logger.error("[PLATEGA] Create payment failed: %s", detail)
                await _notify_admin(
                    f"⚠️ Platega create failed\n"
                    f"order_id={db_order.order_id}\n"
                    f"user_id={db_order.user_id}\n"
                    f"detail={detail}"
                )
                try:
                    payment = await _create_platega_payment_with_method(
                        db_order.amount_rub, db_order.order_id, payment_method
                    )
                except Exception:
                    raise HTTPException(status_code=502, detail=detail) from exc
            except httpx.ReadTimeout:
                logger.error("[PLATEGA] Create payment timed out")
                await _notify_admin(f"⚠️ Platega timeout\n" f"order_id={db_order.order_id}\n" f"user_id={db_order.user_id}")
                raise HTTPException(status_code=504, detail="Platega timeout")

            transaction_id = payment.get("transactionId")
            if not transaction_id:
                raise RuntimeError("Platega did not return transactionId")

            db_order.payment_invoice_id = transaction_id
            db_order.payment_url = payment.get("redirect")
            db.commit()

            return {"order_id": db_order.order_id, "status": db_order.status, "redirect": db_order.payment_url, "platega": payment}
        finally:
            db.close()

    @router.post("/orders/tonconnect")
    async def create_order_tonconnect(order: TonConnectOrderCreate, request: Request):
        if order.product_type != "stars":
            raise HTTPException(status_code=400, detail="Only Stars are supported right now")
        if not TONCONNECT_WALLET_ADDRESS:
            raise HTTPException(status_code=503, detail="TON wallet is not configured")

        db = SessionLocal()
        try:
            amount_rub = _stars_base_price(order.quantity or 0)
            promo_percent = 0
            if order.promo_code:
                reservation = _get_active_reservation(order.promo_code, order.user_id, db)
                if not reservation:
                    raise HTTPException(status_code=400, detail="Invalid or expired promo")
                promo_percent = reservation.percent
                amount_rub = amount_rub * (1 - promo_percent / 100)
            order.amount_rub = _round_money(amount_rub) or amount_rub

            amount_ton = await convert_rub_to_crypto(order.amount_rub, "TON")
            amount_nano = _to_nano(amount_ton)
            amount_nano += secrets.randbelow(10000) + 1

            init_data = request.headers.get("x-telegram-init-data")
            user_username = _touch_user_from_initdata(db, order.user_id, init_data)
            db_order = _create_order(
                db,
                order,
                provider="tonconnect",
                currency="TON",
                payment_method="wallet",
                user_username=user_username,
            )
            if order.promo_code and promo_percent:
                db_order.promo_code = order.promo_code.upper()
                db_order.promo_percent = promo_percent
                db_order.amount_rub_original = _stars_base_price(order.quantity or 0)
                db_order.amount_rub = _round_money(amount_rub) or amount_rub
                db.query(PromoReservation).filter(
                    PromoReservation.code == db_order.promo_code,
                    PromoReservation.user_id == db_order.user_id,
                ).update({"order_id": db_order.order_id})
                db.commit()

            db_order.payment_amount = amount_nano / 1_000_000_000
            db_order.payment_amount_nano = str(amount_nano)
            db.commit()

            return {
                "order_id": db_order.order_id,
                "address": TONCONNECT_WALLET_ADDRESS,
                "amount_ton": db_order.payment_amount,
                "amount_nano": db_order.payment_amount_nano,
                "payload": db_order.order_id,
            }
        finally:
            db.close()

    @router.get("/orders/last")
    async def last_order_status(user_id: str = Query(...)):
        db = SessionLocal()
        try:
            order = db.query(Order).filter(Order.user_id == user_id).order_by(Order.timestamp.desc()).first()

            if not order:
                return {"status": "none"}

            await _sync_crypto_order_status(order, db)
            await _sync_platega_order_status(order, db)
            await _sync_tonconnect_order_status(order, db)
            await _sync_tonconnect_order_status(order, db)
            result = {
                "order_id": order.order_id,
                "status": order.status,
                "product_type": order.product_type,
                "quantity": order.quantity,
                "months": order.months,
                "amount": order.amount,
                "bonus_stars_applied": order.bonus_stars_applied,
                "amount_rub": _round_money(order.amount_rub),
                "show_success_page": False,
                "show_failure_page": False,
            }

            if order.status == "paid" and order.success_page_shown == 0:
                result["show_success_page"] = True
                order.success_page_shown = 1
                db.commit()

            elif order.status == "failed" and order.failure_page_shown == 0:
                result["show_failure_page"] = True
                order.failure_page_shown = 1
                db.commit()

            _check_order_expired(order, db)
            return result
        finally:
            db.close()

    @router.get("/orders/history")
    async def order_history(user_id: str = Query(...), limit: int = 10):
        db = SessionLocal()
        try:
            orders = db.query(Order).filter(Order.user_id == user_id).order_by(Order.timestamp.desc()).limit(limit).all()

            for order in orders:
                await _sync_crypto_order_status(order, db)
                await _sync_platega_order_status(order, db)
                await _sync_tonconnect_order_status(order, db)
                _check_order_expired(order, db)

            orders = db.query(Order).filter(Order.user_id == user_id).order_by(Order.timestamp.desc()).limit(limit).all()

            return {
                "orders": [
                    {
                        "order_id": o.order_id,
                        "recipient": o.recipient,
                        "product_type": o.product_type,
                        "quantity": o.quantity,
                        "months": o.months,
                        "amount": o.amount,
                        "amount_rub": _round_money(o.amount_rub),
                        "currency": o.currency,
                        "status": o.status,
                        "bonus_stars_applied": o.bonus_stars_applied,
                        "timestamp": o.timestamp.astimezone(MSK).isoformat(),
                    }
                    for o in orders
                ]
            }
        finally:
            db.close()

    @router.get("/orders/{order_id}")
    async def order_status(order_id: str):
        db = SessionLocal()
        try:
            order = db.query(Order).filter(Order.order_id == order_id).first()
            if not order:
                return {"error": "Order not found"}

            await _sync_crypto_order_status(order, db)
            await _sync_platega_order_status(order, db)
            _check_order_expired(order, db)
            return {
                "order_id": order.order_id,
                "status": order.status,
                "product_type": order.product_type,
                "quantity": order.quantity,
                "months": order.months,
                "amount": order.amount,
                "bonus_stars_applied": order.bonus_stars_applied,
            }
        finally:
            db.close()

    return router

