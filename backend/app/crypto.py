import httpx

BINANCE_API = "https://api.binance.com/api/v3/ticker/price"

# -------------------------
# КРИПТО → RUB
# -------------------------
async def convert_to_rub(symbol: str, amount: float) -> float:
    """
    Конвертирует сумму крипты в RUB.
    symbol: 'USDT' или 'TON'
    amount: количество криптовалюты
    """
    async with httpx.AsyncClient() as client:
        if symbol.upper() == "TON":
            r = await client.get(f"{BINANCE_API}?symbol=TONUSDT")
            ton_to_usdt = float(r.json()["price"])
            amount_usdt = amount * ton_to_usdt
        else:
            amount_usdt = amount

        r = await client.get(f"{BINANCE_API}?symbol=USDTRUB")
        usdt_to_rub = float(r.json()["price"])
        return round(amount_usdt * usdt_to_rub, 2)


# -------------------------
# RUB → КРИПТО  (НОВАЯ ФУНКЦИЯ)
# -------------------------
async def convert_rub_to_crypto(amount_rub: float, symbol: str) -> float:
    """
    Конвертация рублей в криптовалюту (USDT или TON).
    Возвращает количество криптовалюты.
    """
    symbol = symbol.upper()

    async with httpx.AsyncClient() as client:
        # RUB → USDT
        r = await client.get(f"{BINANCE_API}?symbol=USDTRUB")
        usdt_price_rub = float(r.json()["price"])   # цена 1 USDT в рублях

        amount_usdt = amount_rub / usdt_price_rub

        if symbol == "USDT":
            return round(amount_usdt, 4)

        elif symbol == "TON":
            # USDT → TON
            r = await client.get(f"{BINANCE_API}?symbol=TONUSDT")
            ton_price_usdt = float(r.json()["price"])
            return round(amount_usdt / ton_price_usdt, 4)

        else:
            raise ValueError("Unknown crypto symbol")
