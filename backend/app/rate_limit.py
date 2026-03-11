import asyncio


class RateLimiter:
    def __init__(self, limit_per_min: int):
        self.limit = limit_per_min
        self.buckets: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = asyncio.get_event_loop().time()
        window_start = now - 60
        bucket = self.buckets.get(key, [])
        bucket = [t for t in bucket if t >= window_start]
        if len(bucket) >= self.limit:
            self.buckets[key] = bucket
            return False
        bucket.append(now)
        self.buckets[key] = bucket
        return True

