from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class SignupRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=150)
    email: EmailStr
    password: str = Field(..., min_length=6)


class LoginRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    scope: Optional[str] = None


class UserInfo(BaseModel):
    sub: str
    username: str
    email: EmailStr
    issued_at: datetime


class ClientCreate(BaseModel):
    name: str
    redirect_uris: str
    is_confidential: bool = True


class ClientOut(BaseModel):
    client_id: str
    client_secret: Optional[str] = None
    name: str
    redirect_uris: str
    is_confidential: bool

