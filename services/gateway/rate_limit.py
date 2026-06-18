from time import monotonic

from fastapi import Depends, HTTPException, Request, status

from auth import get_current_user
from models import TokenPayload


RATE_LIMITS = {
    "free": {"requests_per_minute": 60, "burst": 100},
    "premium": {"requests_per_minute": 300, "burst": 500},
    "enterprise": {"requests_per_minute": 1000, "burst": 2000},
}

ROLE_TO_TIER = {
    "admin": "enterprise",
    "enterprise": "enterprise",
    "premium": "premium",
    "free": "free",
}

_buckets: dict[str, dict[str, float]] = {}


def resolve_tier(user: TokenPayload | None) -> str:
    if user is None:
        return "free"
    claimed = (user.tier or user.role or "free").lower()
    return ROLE_TO_TIER.get(claimed, claimed if claimed in RATE_LIMITS else "free")


def reset_rate_limits() -> None:
    _buckets.clear()


async def enforce_rate_limit(request: Request, user: TokenPayload = Depends(get_current_user)) -> None:
    tier = resolve_tier(user)
    config = RATE_LIMITS[tier]
    refill_rate = config["requests_per_minute"] / 60
    burst = config["burst"]
    key = f"{user.sub}:{tier}"
    now = monotonic()
    bucket = _buckets.setdefault(key, {"tokens": float(burst), "updated_at": now})
    elapsed = max(0, now - bucket["updated_at"])
    bucket["tokens"] = min(float(burst), bucket["tokens"] + elapsed * refill_rate)
    bucket["updated_at"] = now
    if bucket["tokens"] < 1:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": "RATE_LIMIT_EXCEEDED",
                "message": f"{tier.title()} tier rate limit exceeded",
                "details": {"tier": tier, "requests_per_minute": config["requests_per_minute"], "burst": burst},
            },
        )
    bucket["tokens"] -= 1
    request.state.rate_limit_tier = tier
