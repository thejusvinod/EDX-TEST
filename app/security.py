import base64
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from jose import jwt, JWTError
from passlib.context import CryptContext

from app.config import settings


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def hash_secret(secret: str) -> str:
    return pwd_context.hash(secret)


def verify_secret(plain_secret: str, secret_hash: Optional[str]) -> bool:
    if secret_hash is None:
        return False
    return pwd_context.verify(plain_secret, secret_hash)


ALGORITHM = "HS256"


def create_access_token(*, subject: str, username: str, scopes: str = "", client_id: Optional[str] = None) -> Tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expire = now + settings.access_token_expires
    to_encode = {
        "sub": subject,
        "username": username,
        "scopes": scopes,
        "iss": settings.TOKEN_ISSUER,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "type": "access",
    }
    if client_id:
        to_encode["client_id"] = client_id
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt, expire


def create_refresh_token() -> str:
    # Create a strong random token (not a JWT) to hash and store
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def parse_basic_auth(header: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not header or not header.lower().startswith("basic "):
        return None, None
    try:
        b64 = header.split(" ", 1)[1]
        decoded = base64.b64decode(b64).decode()
        client_id, client_secret = decoded.split(":", 1)
        return client_id, client_secret
    except Exception:
        return None, None

