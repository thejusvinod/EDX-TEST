from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status, Form
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.config import settings
from app.database import Base, engine, get_db
from app.models import User, OAuthClient, AuthorizationCode, RefreshToken
from app.schemas import SignupRequest, LoginRequest, TokenResponse, UserInfo, ClientCreate, ClientOut
from app.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
    hash_secret,
    verify_secret,
    parse_basic_auth,
)
import secrets
import httpx
from urllib.parse import urlencode


app = FastAPI(title="OAuth2 Auth Service", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.ALLOWED_CORS_ORIGINS == "*" else settings.ALLOWED_CORS_ORIGINS.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(SessionMiddleware, secret_key=settings.SESSION_SECRET)

templates = Jinja2Templates(directory="app/templates")


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)


def get_user_by_identifier(db: Session, identifier: str) -> Optional[User]:
    if "@" in identifier:
        return db.query(User).filter(User.email == identifier).first()
    return db.query(User).filter(User.username == identifier).first()


def issue_tokens(db: Session, user: User, scope: str = "openid profile email", client: Optional[OAuthClient] = None) -> TokenResponse:
    access_jwt, exp = create_access_token(
        subject=str(user.id), username=user.username, scopes=scope, client_id=client.client_id if client else None
    )
    refresh_raw = create_refresh_token()
    refresh_hash = hash_secret(refresh_raw)
    rt = RefreshToken(
        token_hash=refresh_hash,
        user_id=user.id,
        client_id=client.id if client else None,
        scope=scope,
        expires_at=datetime.now(timezone.utc) + settings.refresh_token_expires,
    )
    db.add(rt)
    db.commit()
    return TokenResponse(
        access_token=access_jwt,
        expires_in=int(settings.access_token_expires.total_seconds()),
        refresh_token=refresh_raw,
        scope=scope,
    )


@app.post("/signup", response_model=UserInfo)
def signup(payload: SignupRequest, db: Session = Depends(get_db)):
    if db.query(User).filter((User.username == payload.username) | (User.email == payload.email)).first():
        raise HTTPException(status_code=400, detail="User already exists")
    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return UserInfo(sub=str(user.id), username=user.username, email=user.email, issued_at=datetime.now(timezone.utc))


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: Optional[str] = None):
    return templates.TemplateResponse("login.html", {"request": request, "next": next or ""})


@app.post("/login")
async def login(
    request: Request,
    db: Session = Depends(get_db),
    identifier: Optional[str] = Form(default=None),
    password: Optional[str] = Form(default=None),
):
    # Support JSON API login as well
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        body = await request.json()
        try:
            data = LoginRequest(**body)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid payload")
        ident = data.email or data.username
        if not ident:
            raise HTTPException(status_code=400, detail="username or email required")
        user = get_user_by_identifier(db, ident)
        if not user or not verify_password(data.password, user.password_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        tokens = issue_tokens(db, user)
        return JSONResponse(tokens.model_dump())

    # Form login for browser-based session (Authorization Code flow)
    ident = identifier
    next_url = (await request.form()).get("next") if ident is None else request.query_params.get("next")
    if ident is None:
        form = await request.form()
        ident = form.get("identifier")
        password = form.get("password")
        next_url = form.get("next")
    if not ident or not password:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Missing credentials", "next": next_url or ""})
    user = get_user_by_identifier(db, ident)
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials", "next": next_url or ""})
    request.session["user_id"] = user.id
    if next_url:
        return RedirectResponse(next_url, status_code=302)
    return JSONResponse({"detail": "Logged in", "user_id": user.id})


@app.get("/sso/openedx/login")
def openedx_login(request: Request, next: Optional[str] = None):
    if not settings.OPENEDX_ENABLED:
        raise HTTPException(status_code=400, detail="Open edX SSO not enabled")
    if not (settings.openedx_authorize_url and settings.OPENEDX_CLIENT_ID and settings.OPENEDX_REDIRECT_URI):
        raise HTTPException(status_code=500, detail="Open edX SSO not configured")
    state = secrets.token_urlsafe(16)
    request.session["openedx_state"] = state
    if next:
        request.session["openedx_next"] = next
    params = {
        "response_type": "code",
        "client_id": settings.OPENEDX_CLIENT_ID,
        "redirect_uri": settings.OPENEDX_REDIRECT_URI,
        "scope": settings.OPENEDX_SCOPES,
        "state": state,
    }
    url = settings.openedx_authorize_url + "?" + urlencode(params)
    return RedirectResponse(url, status_code=302)


@app.get("/sso/openedx/callback")
async def openedx_callback(request: Request, code: Optional[str] = None, state: Optional[str] = None, db: Session = Depends(get_db)):
    if not settings.OPENEDX_ENABLED:
        raise HTTPException(status_code=400, detail="Open edX SSO not enabled")
    expected_state = request.session.get("openedx_state")
    if not code or not state or state != expected_state:
        raise HTTPException(status_code=400, detail="Invalid state or code")
    # Clear state to prevent reuse
    request.session.pop("openedx_state", None)

    if not (settings.openedx_token_url and settings.OPENEDX_CLIENT_ID and settings.OPENEDX_CLIENT_SECRET and settings.OPENEDX_REDIRECT_URI):
        raise HTTPException(status_code=500, detail="Open edX token configuration missing")

    async with httpx.AsyncClient(timeout=15.0) as client:
        token_resp = await client.post(
            settings.openedx_token_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.OPENEDX_REDIRECT_URI,
                "client_id": settings.OPENEDX_CLIENT_ID,
                "client_secret": settings.OPENEDX_CLIENT_SECRET,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if token_resp.status_code != 200:
            raise HTTPException(status_code=401, detail=f"Open edX token exchange failed: {token_resp.text}")
        token_json = token_resp.json()
        access_token = token_json.get("access_token")
        if not access_token:
            raise HTTPException(status_code=401, detail="No access_token from Open edX")

        # Fetch user info from Open edX
        if not settings.openedx_userinfo_url:
            raise HTTPException(status_code=500, detail="Open edX userinfo URL not configured")
        uinfo_resp = await client.get(
            settings.openedx_userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if uinfo_resp.status_code != 200:
            raise HTTPException(status_code=401, detail=f"Open edX userinfo failed: {uinfo_resp.text}")
        info = uinfo_resp.json()

    # Map typical OIDC fields
    sub = str(info.get("sub") or info.get("id") or "")
    username = info.get("preferred_username") or info.get("username") or sub
    email = info.get("email") or f"{username or sub}@example.invalid"
    if not username:
        username = email.split("@")[0]

    # Ensure user exists locally (no password stored)
    user = db.query(User).filter((User.email == email) | (User.username == username)).first()
    if not user:
        user = User(username=username, email=email, password_hash=None)
        db.add(user)
        db.commit()
        db.refresh(user)

    request.session["user_id"] = user.id
    next_url = request.session.pop("openedx_next", None)
    if next_url:
        return RedirectResponse(next_url, status_code=302)
    return RedirectResponse("/", status_code=302)


def require_bearer_token(request: Request, db: Session) -> User:
    auth = request.headers.get("authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth.split(" ", 1)[1]
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token")
    if payload.get("iss") != settings.TOKEN_ISSUER:
        raise HTTPException(status_code=401, detail="Invalid token issuer")
    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Inactive or missing user")
    return user


@app.get("/userinfo", response_model=UserInfo)
def userinfo(request: Request, db: Session = Depends(get_db)):
    user = require_bearer_token(request, db)
    return UserInfo(sub=str(user.id), username=user.username, email=user.email, issued_at=datetime.now(timezone.utc))


@app.get("/authorize")
def authorize(
    request: Request,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: Optional[str] = "openid profile email",
    state: Optional[str] = None,
    db: Session = Depends(get_db),
):
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Unsupported response_type")

    client = db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client_id")
    allowed_redirects = [u.strip() for u in client.redirect_uris.replace("\n", " ").split(" ") if u.strip()]
    if redirect_uri not in allowed_redirects:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    user_id = request.session.get("user_id")
    if not user_id:
        # redirect to login and come back
        next_url = str(request.url)
        return RedirectResponse(url=f"/login?next={next_url}", status_code=302)

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not active")

    # Auto-consent for now (future: show consent page)
    code_value = secrets.token_urlsafe(32)
    auth_code = AuthorizationCode(
        code=code_value,
        client_id=client.id,
        user_id=user.id,
        redirect_uri=redirect_uri,
        scope=scope or client.scopes,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    db.add(auth_code)
    db.commit()

    sep = "&" if ("?" in redirect_uri) else "?"
    redirect = f"{redirect_uri}{sep}code={code_value}"
    if state:
        redirect += f"&state={state}"
    return RedirectResponse(url=redirect, status_code=302)


@app.post("/token")
async def token(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    grant_type = form.get("grant_type")
    auth_header = request.headers.get("authorization")
    basic_id, basic_secret = parse_basic_auth(auth_header)

    client_id = form.get("client_id") or basic_id
    client_secret = form.get("client_secret") or basic_secret
    if not client_id:
        raise HTTPException(status_code=401, detail="Missing client authentication")

    client = db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()
    if not client:
        raise HTTPException(status_code=401, detail="Invalid client")
    if client.is_confidential:
        if not client_secret or not verify_secret(client_secret, client.client_secret_hash):
            raise HTTPException(status_code=401, detail="Invalid client credentials")

    if grant_type == "authorization_code":
        code_value = form.get("code")
        redirect_uri = form.get("redirect_uri")
        if not code_value or not redirect_uri:
            raise HTTPException(status_code=400, detail="Missing code or redirect_uri")
        auth_code = db.query(AuthorizationCode).filter(AuthorizationCode.code == code_value).first()
        if not auth_code:
            raise HTTPException(status_code=400, detail="Invalid code")
        if auth_code.client_id != client.id:
            raise HTTPException(status_code=400, detail="Code-client mismatch")
        if auth_code.redirect_uri != redirect_uri:
            raise HTTPException(status_code=400, detail="Invalid redirect_uri")
        if datetime.now(timezone.utc) > auth_code.expires_at:
            raise HTTPException(status_code=400, detail="Code expired")

        user = db.query(User).filter(User.id == auth_code.user_id).first()
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not active")

        tokens = issue_tokens(db, user, scope=auth_code.scope, client=client)

        # Invalidate one-time code
        db.delete(auth_code)
        db.commit()

        return JSONResponse({
            "access_token": tokens.access_token,
            "token_type": tokens.token_type,
            "expires_in": tokens.expires_in,
            "refresh_token": tokens.refresh_token,
            "scope": tokens.scope,
        })

    elif grant_type == "refresh_token":
        refresh_token = form.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=400, detail="Missing refresh_token")
        # find hashed match
        # We cannot verify without re-hashing with salt; use verify_secret
        rts = db.query(RefreshToken).filter(RefreshToken.revoked == False).all()
        matched: Optional[RefreshToken] = None
        for rt in rts:
            if verify_secret(refresh_token, rt.token_hash):
                matched = rt
                break
        if not matched:
            raise HTTPException(status_code=400, detail="Invalid refresh_token")
        if matched.client_id and matched.client_id != client.id:
            raise HTTPException(status_code=400, detail="Token-client mismatch")
        if datetime.now(timezone.utc) > matched.expires_at:
            raise HTTPException(status_code=400, detail="Refresh token expired")

        user = db.query(User).filter(User.id == matched.user_id).first()
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not active")

        # Rotate refresh token
        matched.revoked = True
        db.add(matched)
        db.commit()

        tokens = issue_tokens(db, user, scope=matched.scope, client=client)
        return JSONResponse({
            "access_token": tokens.access_token,
            "token_type": tokens.token_type,
            "expires_in": tokens.expires_in,
            "refresh_token": tokens.refresh_token,
            "scope": tokens.scope,
        })

    else:
        raise HTTPException(status_code=400, detail="Unsupported grant_type")


@app.post("/clients", response_model=ClientOut)
def create_client(payload: ClientCreate, db: Session = Depends(get_db)):
    client_id = secrets.token_urlsafe(16)
    client_secret_plain: Optional[str] = None
    client_secret_hash: Optional[str] = None
    if payload.is_confidential:
        client_secret_plain = secrets.token_urlsafe(32)
        client_secret_hash = hash_secret(client_secret_plain)

    client = OAuthClient(
        client_id=client_id,
        client_secret_hash=client_secret_hash,
        name=payload.name,
        redirect_uris=payload.redirect_uris,
        is_confidential=payload.is_confidential,
    )
    db.add(client)
    db.commit()

    return ClientOut(
        client_id=client_id,
        client_secret=client_secret_plain,
        name=payload.name,
        redirect_uris=payload.redirect_uris,
        is_confidential=payload.is_confidential,
    )


@app.get("/")
def root():
    return {"status": "ok", "service": "oauth2-auth-service"}


# Simple UI to verify Open edX credentials directly via password grant
@app.get("/sso/openedx/check", response_class=HTMLResponse)
def openedx_check_form(request: Request):
    if not settings.OPENEDX_ENABLED:
        return HTMLResponse("<h3>Open edX SSO not enabled</h3>", status_code=400)
    return templates.TemplateResponse(
        "openedx_check.html",
        {"request": request, "error": None, "success": None},
    )


@app.post("/sso/openedx/check", response_class=HTMLResponse)
async def openedx_check_submit(request: Request):
    if not settings.OPENEDX_ENABLED:
        return HTMLResponse("<h3>Open edX SSO not enabled</h3>", status_code=400)
    form = await request.form()
    identifier = (form.get("identifier") or "").strip()
    password = form.get("password") or ""
    if not identifier or not password:
        return templates.TemplateResponse(
            "openedx_check.html",
            {"request": request, "error": "Please enter username/email and password.", "success": None},
            status_code=400,
        )

    if not settings.openedx_token_url or not settings.OPENEDX_CLIENT_ID:
        return templates.TemplateResponse(
            "openedx_check.html",
            {"request": request, "error": "Open edX token endpoint or client not configured.", "success": None},
            status_code=500,
        )

    # Try Resource Owner Password Credentials grant against Open edX
    payload = {
        "grant_type": "password",
        "username": identifier,
        "password": password,
        "client_id": settings.OPENEDX_CLIENT_ID,
    }
    if settings.OPENEDX_CLIENT_SECRET:
        payload["client_secret"] = settings.OPENEDX_CLIENT_SECRET
    if settings.OPENEDX_SCOPES:
        payload["scope"] = settings.OPENEDX_SCOPES

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                settings.openedx_token_url,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
    except httpx.HTTPError as e:
        return templates.TemplateResponse(
            "openedx_check.html",
            {"request": request, "error": f"Network error contacting Open edX: {e}", "success": None},
            status_code=502,
        )

    if resp.status_code == 200 and resp.json().get("access_token"):
        return templates.TemplateResponse(
            "openedx_check.html",
            {
                "request": request,
                "error": None,
                "success": f"Credentials valid for '{identifier}'. User exists on Open edX.",
            },
        )

    # Common failure reasons on Open edX: invalid_grant, unsupported_grant_type, unauthorized_client
    try:
        detail = resp.json()
    except Exception:
        detail = {"error": resp.text}
    message = detail.get("error_description") or detail.get("error") or "Login failed"
    return templates.TemplateResponse(
        "openedx_check.html",
        {
            "request": request,
            "error": f"Open edX rejected credentials: {message} (status {resp.status_code})",
            "success": None,
        },
        status_code=401 if resp.status_code in (400, 401) else 500,
    )


# Placeholder for future Open edX integration
@app.get("/health/openedx")
def openedx_healthcheck():
    # Future: Validate connectivity/introspection with Open edX OAuth2
    return {"openedx_integration_ready": True}
