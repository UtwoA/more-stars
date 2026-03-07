import httpx
import time

BINANCE_API = "https://api.binance.com/api/v3/ticker/price"
MOEX_API = "https://iss.moex.com/iss/engines/currency/markets/selt/boards/CETS/securities"

_moex_cache_rate: float | None = None
_moex_cache_ts: float | None = None

async def get_usdtrub_rate() -> float:
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{BINANCE_API}?symbol=USDTRUB")
        return float(r.json()["price"])


async def get_moex_usdrub_rate(cache_ttl: int = 300) -> float:
    global _moex_cache_rate, _moex_cache_ts
    now = time.time()
    if _moex_cache_rate is not None and _moex_cache_ts is not None:
        if now - _moex_cache_ts < cache_ttl:
            return _moex_cache_rate

    symbols = ["USD000UTSTOM", "USD000000TOD"]
    params = "iss.meta=off&iss.only=marketdata&marketdata.columns=LAST"
    async with httpx.AsyncClient() as client:
        for symbol in symbols:
            url = f"{MOEX_API}/{symbol}.json?{params}"
            r = await client.get(url, timeout=10)
            r.raise_for_status()
            data = r.json().get("marketdata", {}).get("data") or []
            if data and data[0] and data[0][0]:
                rate = float(data[0][0])
                _moex_cache_rate = rate
                _moex_cache_ts = now
                return rate

    raise ValueError("MOEX USD/RUB rate not available")

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
