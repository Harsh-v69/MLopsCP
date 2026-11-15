"""M3: validate OIDC access tokens issued by an external identity provider
(Keycloak). Signature is checked against the provider's published keys (JWKS);
issuer, audience and expiry are all required. Fails closed on every error."""
import os
from typing import Optional

import jwt
from jwt import PyJWKClient

# Asymmetric only. Never HS256 here: that would let anyone who knows the (public)
# key forge tokens, and "none" must never be accepted.
ALLOWED_ALGORITHMS = ["RS256", "ES256"]

_client: Optional[PyJWKClient] = None


def oidc_configured() -> bool:
    return bool(os.environ.get("MLSHIELD_OIDC_ISSUER") and os.environ.get("MLSHIELD_OIDC_AUDIENCE"))


def _jwks_client() -> PyJWKClient:
    global _client
    if _client is None:
        issuer = os.environ["MLSHIELD_OIDC_ISSUER"].rstrip("/")
        url = os.environ.get("MLSHIELD_OIDC_JWKS_URL", f"{issuer}/protocol/openid-connect/certs")
        _client = PyJWKClient(url, cache_keys=True, lifespan=300, timeout=5)
    return _client


def verify_oidc_token(token: str) -> dict:
    """Return the verified claims, or raise jwt.PyJWTError (including key-fetch failures)."""
    key = _jwks_client().get_signing_key_from_jwt(token).key
    return jwt.decode(
        token, key,
        algorithms=ALLOWED_ALGORITHMS,
        issuer=os.environ["MLSHIELD_OIDC_ISSUER"].rstrip("/"),
        audience=os.environ["MLSHIELD_OIDC_AUDIENCE"],
        options={"require": ["exp", "iss", "aud", "sub"]},
    )


def roles_from_claims(claims: dict) -> list[str]:
    """Keycloak puts realm roles in realm_access.roles."""
    roles = (claims.get("realm_access") or {}).get("roles") or []
    return [r for r in roles if isinstance(r, str)]
