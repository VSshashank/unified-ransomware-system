import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from models import TokenPayload


logger = logging.getLogger("urds.gateway.auth")

# Phase 4 placeholder. Every deployment that is not one developer's laptop has
# to override JWT_SECRET: this value is committed, so a token signed with it can
# be forged by anyone holding the repo. verify_jwt_secret_configuration() warns
# on every start and refuses to boot outright once URDS_ENV says the deployment
# is not development.
DEFAULT_JWT_SECRET = "dev-only-change-me"

# URDS_ENV values that make the default secret a hard failure rather than a warning.
PROTECTED_ENVIRONMENTS = frozenset({"production", "prod", "staging"})

JWT_SECRET = os.getenv("JWT_SECRET", DEFAULT_JWT_SECRET)
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "120"))

# The least-privileged role, and the default for anything that does not prove
# otherwise. A token that carries no role claim is treated as this, never higher.
FREE_ROLE = "free"

BOOTSTRAP_SECRET_HEADER = "X-Bootstrap-Secret"

bearer_scheme = HTTPBearer(auto_error=False)


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def dev_tokens_allowed() -> bool:
    """Whether POST /auth/token issues anything at all.

    Read per call rather than at import: this is deployment posture, and a
    deployment that turns it off should not need the module reloaded to mean it.
    """
    return _truthy(os.getenv("ALLOW_DEV_TOKENS", "true"))


def bootstrap_secret() -> str:
    return (os.getenv("DEV_TOKEN_BOOTSTRAP_SECRET") or "").strip()


def requires_bootstrap_secret(role: str | None, tier: str | None) -> bool:
    """Whether this token request asks for more than the free floor.

    Tier is checked as well as role, and not as an afterthought: `resolve_tier`
    prefers the tier claim over the role, so a "free" role carrying tier
    "enterprise" is granted a 1000 rpm budget instead of 60.
    """
    return (role or FREE_ROLE).lower() != FREE_ROLE or (tier or FREE_ROLE).lower() != FREE_ROLE


def bootstrap_secret_matches(presented: str | None) -> bool:
    """Constant-time compare that fails closed when no secret is configured.

    An unset secret must not be matchable by an absent header - that would make
    "no secret configured" mean "admin for everyone", which is the bug this
    whole check exists to close.
    """
    expected = bootstrap_secret()
    if not expected:
        return False
    return secrets.compare_digest(presented or "", expected)


def verify_jwt_secret_configuration() -> None:
    """Called at gateway startup. Loud in development, fatal outside it."""
    if JWT_SECRET != DEFAULT_JWT_SECRET:
        return

    environment = (os.getenv("URDS_ENV") or "development").strip().lower()
    if environment in PROTECTED_ENVIRONMENTS:
        raise RuntimeError(
            f"JWT_SECRET is still the committed default while URDS_ENV={environment!r}. "
            "Tokens signed with it can be forged by anyone with the repository. "
            "Set JWT_SECRET to a real secret, or set URDS_ENV=development to run locally."
        )

    rule = "=" * 72
    logger.warning(
        "\n%s\n"
        "JWT_SECRET is the committed default (%r). Every token this gateway\n"
        "issues can be forged by anyone holding the repository. This is fine for\n"
        "local development and nowhere else - set JWT_SECRET before deploying.\n"
        "URDS_ENV=%s\n"
        "%s",
        rule,
        DEFAULT_JWT_SECRET,
        environment,
        rule,
    )


def create_access_token(sub: str, role: str = FREE_ROLE, tier: str = FREE_ROLE) -> str:
    # Defaults are the least-privileged role deliberately. This used to default
    # to admin/enterprise, which meant every caller that omitted the argument -
    # including an empty POST to /auth/token - minted a full-privilege token.
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": sub,
        "role": role,
        "tier": tier,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> TokenPayload:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return TokenPayload(**payload)
    except (JWTError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "UNAUTHORIZED", "message": "Invalid or expired bearer token", "details": {"reason": str(exc)}},
        ) from exc


async def get_current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme)) -> TokenPayload:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "UNAUTHORIZED", "message": "Missing bearer token", "details": {}},
        )
    return decode_token(credentials.credentials)


def require_role(*allowed: str):
    """Dependency factory: 403 unless the token's role is one of `allowed`.

    Authentication and authorization stay separate. `get_current_user` still
    decides whether the caller is anyone at all (401); this decides whether that
    someone may do this (403). A route that only needs a valid token keeps
    depending on `get_current_user` alone.
    """
    allowed_roles = frozenset(role.lower() for role in allowed)

    async def dependency(user: TokenPayload = Depends(get_current_user)) -> TokenPayload:
        if (user.role or FREE_ROLE).lower() not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "FORBIDDEN",
                    "message": "This role is not permitted to perform this action",
                    "details": {"role": user.role, "required_roles": sorted(allowed_roles)},
                },
            )
        return user

    return dependency
