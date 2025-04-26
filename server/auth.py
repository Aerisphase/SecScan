from fastapi.security import APIKeyHeader
from fastapi import Security, HTTPException, status
import os

API_KEY = os.getenv("SECSCAN_API_KEY", "default-secret-key-123")
api_key_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)

async def api_key_auth(api_key: str = Security(api_key_scheme)):
    if api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
            headers={"WWW-Authenticate": "API-Key"}
        )
    return api_key