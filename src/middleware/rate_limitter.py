import redis.asyncio as redis
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware

from ..core.config import settings
from ..schemas.responses import CustomHttpException


class RateLimiter:
    def __init__(
        self, redis_url: str = "redis://localhost:6379", prefix: str = "rate_limit"
    ):
        self.redis_url = redis_url
        self.prefix = prefix
        self.redis = redis.from_url(self.redis_url, decode_responses=True)

    async def is_allowed(self, client_id: str, limit: int, window: int):
        """
        Check if a client is allowed to make a request.
        Args:
        - client_id: Unique identifier for the client (e.g., IP or user ID).
        - limit: Number of allowed requests.
        - window: Time window in seconds.
        """
        key = f"{self.prefix}:{client_id}"
        async with self.redis.client() as conn:
            # Increment request count and set expiry if key is new
            current_count = await conn.incr(key)
            if current_count == 1:
                await conn.expire(key, window)

            remaining_time = await conn.ttl(key)
            remaining_requests = max(0, limit - current_count)

            # Deny access if limit exceeded
            if current_count > limit:
                headers = {
                    "Retry-After": str(remaining_time),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": str(remaining_requests),
                    "X-RateLimit-Reset": str(remaining_time),
                }
                raise CustomHttpException(
                    status_code=429,
                    message="Too Many Requests",
                    error_code="TOO_MANY_REQUESTS",
                    error_details=f"Rate limit exceeded. Try again in {remaining_time} seconds.",
                    headers=headers,
                )

        return remaining_requests, remaining_time


# Initialize the rate limiter (replace with your Redis URL)
rate_limiter = RateLimiter(redis_url=settings.REDIS_URL)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self, app: FastAPI, rate_limiter: RateLimiter, limit: int, window: int
    ):
        super().__init__(app)
        self.rate_limiter = rate_limiter
        self.limit = limit
        self.window = window

    async def dispatch(self, request: Request, call_next):
        client_id = request.client.host  # Default client identifier

        # Apply rate limiting and get remaining requests and time
        remaining_requests, remaining_time = await self.rate_limiter.is_allowed(
            client_id, self.limit, self.window
        )

        # Process the request
        response = await call_next(request)

        # Add rate-limiting headers
        response.headers["X-RateLimit-Limit"] = str(self.limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining_requests)
        response.headers["X-RateLimit-Reset"] = str(remaining_time)

        return response


async def per_route_rate_limiter(request: Request, limit: int, window: int):
    client_id = request.client.host
    remaining_requests, remaining_time = await rate_limiter.is_allowed(
        client_id, limit, window
    )
    return remaining_requests, remaining_time
