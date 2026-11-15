from typing import Optional

from fastapi import Header, HTTPException

from src.governance.auth import authorize


def requires(action: str):
    """Route dependency: 401 without a Bearer header, 403 unless the token's role
    is permitted `action` (permission matrix in src/governance/auth.py)."""
    def check(authorization: Optional[str] = Header(default=None)):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing or malformed Authorization header")
        result = authorize(authorization.removeprefix("Bearer ").strip(), action)
        if not result.allowed:
            raise HTTPException(status_code=403, detail=result.reason)
        return result
    return check
