OAuth2 Authentication Service (FastAPI)

Overview

- Simple, lightweight OAuth2 authorization server suitable for central auth across apps.
- Implements Authorization Code grant, JWT access tokens, and refresh tokens.
- Secure password hashing (bcrypt), secure client secret storage, and session-based login for the authorize flow.
- Ready for future Open edX integration and deployable on Render.

Key Endpoints

- POST `/signup` → Create a user (testing only)
- POST `/login` → Authenticate user
  - JSON (API) → returns access/refresh tokens
  - Form (browser) → sets session for `/authorize` flow
- GET `/authorize` → Authorization Code endpoint
- POST `/token` → Exchange code or refresh token for access token
- GET `/userinfo` → Returns user info (protected by bearer token)
- POST `/clients` → Create OAuth client (returns `client_id` and `client_secret` for confidential apps)

Tech Stack

- FastAPI, SQLAlchemy, SQLite (dev), JWT (python-jose), passlib[bcrypt]

Local Setup

1) Python 3.10+
2) Create a virtual environment and install packages

   pip install -r requirements.txt

3) Set environment variables (optional; defaults are fine for dev):

   - `SECRET_KEY` → JWT signing key (default: dev value)
   - `SESSION_SECRET` → Cookie session secret (default: dev value)
   - `DATABASE_URL` → e.g. `sqlite:///./data.db`
   - `ACCESS_TOKEN_EXPIRE_MINUTES` → default: 30
   - `REFRESH_TOKEN_EXPIRE_DAYS` → default: 30
   - `TOKEN_ISSUER` → default: oauth2-auth-service

4) Run the app

   uvicorn app.main:app --reload

5) Create a user (testing)

   curl -X POST http://localhost:8000/signup \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","email":"alice@example.com","password":"secret123"}'

6) Create a client

   curl -X POST http://localhost:8000/clients \
     -H "Content-Type: application/json" \
     -d '{"name":"My App","redirect_uris":"http://localhost:3000/callback","is_confidential":true}'

   Save the returned `client_id` and `client_secret`.

7) OAuth2 Authorization Code flow (manual test)

- In a browser, visit:
  http://localhost:8000/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=http://localhost:3000/callback&scope=openid%20profile%20email&state=xyz
- Login with the form (if not already logged in). You will be redirected to the `redirect_uri` with `?code=...&state=xyz`.
- Exchange the code for tokens:

  curl -X POST http://localhost:8000/token \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Authorization: Basic BASE64(client_id:client_secret)" \
    -d "grant_type=authorization_code&code=PASTE_CODE&redirect_uri=http://localhost:3000/callback"

8) Use access token

   curl -H "Authorization: Bearer ACCESS_TOKEN" http://localhost:8000/userinfo

Security Notes

- Use HTTPS in production. On Render, TLS is handled by the platform.
- Access tokens are short-lived JWTs; refresh tokens are long-lived and hashed at rest.
- Client secrets for confidential clients are hashed; store the plaintext client secret securely on creation.

Open edX Integration (Future)

Open edX SSO (Enabled)

- Configure env vars to enable SSO against your Open edX instance:
  - `OPENEDX_ENABLED=true`
  - `OPENEDX_BASE_URL=https://youredx.example.com` (or set the explicit URLs below)
  - Optional overrides: `OPENEDX_AUTH_URL`, `OPENEDX_TOKEN_URL`, `OPENEDX_USERINFO_URL`
  - `OPENEDX_CLIENT_ID`, `OPENEDX_CLIENT_SECRET` (from Open edX OAuth app)
  - `OPENEDX_REDIRECT_URI` → e.g., `https://your-auth-service.onrender.com/sso/openedx/callback`
  - `OPENEDX_SCOPES` → default: `openid profile email`

- Flow:
  - Client calls this service’s `/authorize`.
  - If not logged in, user sees `/login` and can choose “Continue with Open edX”.
  - `/sso/openedx/login` redirects to Open edX authorize.
  - `/sso/openedx/callback` exchanges code at Open edX, fetches user info, creates/links a local user without a password, sets session, and returns to `/authorize` via the `next` parameter.
  - Our service then issues its own tokens to the requesting client.

- No Open edX passwords are stored in this service. Local users created via Open edX have `password_hash = NULL`.

Render Deployment

- This repo includes `render.yaml` and `Procfile`.
- Create a new Web Service in Render, connect your repo, and deploy.
- Ensure `SECRET_KEY` and `SESSION_SECRET` are auto-generated (already configured) or set your own.
- For production, prefer PostgreSQL; update `DATABASE_URL` accordingly (e.g., `postgresql+psycopg://...`).

To use Open edX SSO on Render, set the env vars above in the service’s settings. Ensure the Open edX OAuth application allows the redirect URI `.../sso/openedx/callback`.

Notes

- The `/signup` endpoint is for testing only and should be disabled when integrating with Open edX SSO.
- Consider adding a proper consent page; current implementation auto-consents for simplicity.
