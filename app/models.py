from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(150), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    # For Open edX users, password_hash can be NULL (we do not store external passwords)
    password_hash = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    auth_codes = relationship("AuthorizationCode", back_populates="user")
    refresh_tokens = relationship("RefreshToken", back_populates="user")


class OAuthClient(Base):
    __tablename__ = "oauth_clients"
    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(String(100), unique=True, index=True, nullable=False)
    client_secret_hash = Column(String(255), nullable=True)  # null for public clients
    name = Column(String(200), nullable=False)
    redirect_uris = Column(Text, nullable=False)  # space or newline separated
    scopes = Column(String(255), default="openid profile email")
    is_confidential = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    auth_codes = relationship("AuthorizationCode", back_populates="client")
    refresh_tokens = relationship("RefreshToken", back_populates="client")


class AuthorizationCode(Base):
    __tablename__ = "authorization_codes"
    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(200), unique=True, index=True, nullable=False)
    client_id = Column(Integer, ForeignKey("oauth_clients.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    redirect_uri = Column(Text, nullable=False)
    scope = Column(String(255), default="openid profile email")
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("OAuthClient", back_populates="auth_codes")
    user = relationship("User", back_populates="auth_codes")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    token_hash = Column(String(255), unique=True, index=True, nullable=False)
    client_id = Column(Integer, ForeignKey("oauth_clients.id"), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    scope = Column(String(255), default="openid profile email")
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("OAuthClient", back_populates="refresh_tokens")
    user = relationship("User", back_populates="refresh_tokens")
