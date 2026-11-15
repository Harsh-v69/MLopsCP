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


def build_client(url: str, lifespan: float = 300, cooldown: float = 30) -> PyJWKClient:
    """Key handling that survives rotation and honours revocation:
    - the key set is cached for `lifespan` seconds, so a key the provider removes stops
      being trusted within that window (and the provider being briefly down is tolerated);
    - an unknown key id forces at most one refetch per `cooldown` seconds, so forged key
      ids cannot turn into a request flood against the provider;
    - no per-key cache: PyJWT's cache_keys=True never expires, which would keep trusting a
      revoked key until the process restarts."""
    return PyJWKClient(url, cache_keys=False, lifespan=lifespan, cooldown_duration=cooldown, timeout=5)


def _jwks_client() -> PyJWKClient:
    global _client
    if _client is None:
        issuer = os.environ["MLSHIELD_OIDC_ISSUER"].rstrip("/")
        url = os.environ.get("MLSHIELD_OIDC_JWKS_URL", f"{issuer}/protocol/openid-connect/certs")
        _client = build_client(url)
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
