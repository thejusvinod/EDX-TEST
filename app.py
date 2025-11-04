import base64
import hashlib
import os
import secrets
import time
from urllib.parse import urlencode, quote_plus, urlparse
 
import requests
from flask import Flask, redirect, request, session, jsonify, send_from_directory, make_response
from werkzeug.middleware.proxy_fix import ProxyFix
 
# ===== Flask setup =====
app = Flask(__name__, static_url_path="/static", static_folder="static")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # In prod behind HTTPS on Render:
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
)
 
# Respect reverse proxy headers (e.g., Render) for scheme/host so we can
# generate correct external URLs like https://<app>/callback
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
 
# ===== Config (ENV) =====
OPENEDX_BASE_URL = os.environ.get("OPENEDX_BASE_URL", "").rstrip("/")
OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "")
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "")  # optional if Public+PKCE
REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:5000/callback")
OAUTH_SCOPES = os.environ.get("OAUTH_SCOPES", "read profile").strip()
OAUTH_USE_PKCE_ENV = os.environ.get("OAUTH_USE_PKCE", "auto").lower()  # auto|1|0
 
# Open edX typical endpoints:
AUTHZ_URL = f"{OPENEDX_BASE_URL}/oauth2/authorize"
TOKEN_URL = f"{OPENEDX_BASE_URL}/oauth2/access_token"
ME_URL = f"{OPENEDX_BASE_URL}/api/user/v1/me"
 
# Weather (server-side proxy)
OPENWEATHER_API_KEY = os.environ.get("OPENWEATHER_API_KEY", "")
 
# ===== Helpers: PKCE =====
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
 
def create_pkce():
    code_verifier = _b64url(os.urandom(40))  # 43-128 chars
    code_challenge = _b64url(hashlib.sha256(code_verifier.encode()).digest())
    return code_verifier, code_challenge
 
# ===== Auth helpers =====
def is_authenticated():
    tok = session.get("oauth", {})
    if not tok or "access_token" not in tok:
        return False
    # Expiry check
    if tok.get("expires_at") and time.time() > tok["expires_at"]:
        return try_refresh()
    return True
 
def try_refresh():
    tok = session.get("oauth", {})
    refresh_token = tok.get("refresh_token")
    if not refresh_token:
        session.pop("oauth", None)
        return False
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": OAUTH_CLIENT_ID,
    }
    if OAUTH_CLIENT_SECRET:
        data["client_secret"] = OAUTH_CLIENT_SECRET
    r = requests.post(TOKEN_URL, data=data, timeout=20)
    if r.status_code != 200:
        session.pop("oauth", None)
        return False
    payload = r.json()
    expires_in = int(payload.get("expires_in", 3600))
    session["oauth"] = {
        "access_token": payload["access_token"],
        "refresh_token": payload.get("refresh_token", refresh_token),
        "token_type": payload.get("token_type", "Bearer"),
        "expires_at": time.time() + expires_in - 30,
    }
    return True

def get_access_token():
    """Get current valid access token"""
    if not is_authenticated():
        return None
    return session["oauth"]["access_token"]

def get_user_info():
    """Get cached user info from session, or fetch if needed"""
    # Check if we have cached user info
    if "user_info" in session:
        return session["user_info"]
    
    # Fetch from API
    token = get_access_token()
    if not token:
        return None
    
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(ME_URL, headers=headers, timeout=20)
        if r.status_code == 200:
            user_info = r.json()
            session["user_info"] = user_info  # Cache it
            return user_info
    except Exception as e:
        print(f"Error fetching user info: {e}")
    
    return None
 
# ===== URL helpers =====
def _external_base_url() -> str:
    # request.url_root already respects ProxyFix
    return (request.url_root or "").rstrip("/")
 
def _redirect_uri_effective() -> str:
    # If REDIRECT_URI is set to "auto" or empty, or its host differs from the
    # current request host, compute it dynamically so OAuth returns to this app.
    if not REDIRECT_URI or REDIRECT_URI.lower() == "auto":
        return f"{_external_base_url()}/callback"
    try:
        parsed = urlparse(REDIRECT_URI)
        env_netloc = parsed.netloc
        env_path = parsed.path or ""
    except Exception:
        env_netloc = ""
        env_path = ""
    if env_netloc and env_netloc != request.host:
        return f"{_external_base_url()}/callback"
    # Enforce our app's callback path if none or root was provided
    if env_path in ("", "/"):
        return f"{_external_base_url()}/callback"
    return REDIRECT_URI
 
def use_pkce() -> bool:
    # If explicitly configured, honor it. Otherwise: use PKCE only when no secret provided.
    if OAUTH_USE_PKCE_ENV in ("1", "true", "yes", "on"):
        return True
    if OAUTH_USE_PKCE_ENV in ("0", "false", "no", "off"):
        return False
    return not bool(OAUTH_CLIENT_SECRET)
 
# ===== Routes =====
 
@app.route("/")
def index():
    """Main dashboard - shows courses"""
    return send_from_directory("static", "index.html")

@app.route("/weather")
def weather_page():
    """Weather app page"""
    return send_from_directory("static", "weather.html")
 
@app.route("/auth/status")
def auth_status():
    return jsonify({"authenticated": is_authenticated()})
 
@app.route("/login")
def login():
    if not OPENEDX_BASE_URL or not OAUTH_CLIENT_ID:
        return make_response("Server not configured for OAuth. Set environment variables.", 500)
 
    state = _b64url(os.urandom(24))
    session["oauth_state"] = state
    redirect_uri = _redirect_uri_effective()
    params = {
        "client_id": OAUTH_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": OAUTH_SCOPES,
        "state": state,
    }
    if use_pkce():
        code_verifier, code_challenge = create_pkce()
        session["pkce_verifier"] = code_verifier
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    return redirect(f"{AUTHZ_URL}?{urlencode(params)}", code=302)
 
@app.route("/callback")
def callback():
    error = request.args.get("error")
    if error:
        return make_response(f"OAuth error: {error}", 400)
 
    code = request.args.get("code")
    state = request.args.get("state")
    saved_state = session.get("oauth_state")
    if not code or not saved_state or state != saved_state:
        return make_response("Invalid OAuth state", 400)
 
    redirect_uri = _redirect_uri_effective()
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": OAUTH_CLIENT_ID,
    }
    if use_pkce():
        code_verifier = session.get("pkce_verifier")
        if not code_verifier:
            return make_response("Missing PKCE verifier in session", 400)
        data["code_verifier"] = code_verifier
    if OAUTH_CLIENT_SECRET:
        data["client_secret"] = OAUTH_CLIENT_SECRET
 
    r = requests.post(TOKEN_URL, data=data, timeout=20)
    if r.status_code != 200:
        return make_response(f"Token exchange failed: {r.text}", 400)
 
    payload = r.json()
    expires_in = int(payload.get("expires_in", 3600))
    session["oauth"] = {
        "access_token": payload["access_token"],
        "refresh_token": payload.get("refresh_token"),
        "token_type": payload.get("token_type", "Bearer"),
        "expires_at": time.time() + expires_in - 30,
    }
    session.pop("pkce_verifier", None)
    session.pop("oauth_state", None)
    
    # Fetch and cache user info right after login
    get_user_info()
    
    return redirect("/", code=302)
 
@app.route("/me")
def me():
    if not is_authenticated():
        return make_response("Unauthorized", 401)
    
    user_info = get_user_info()
    if user_info:
        return jsonify(user_info)
    
    return make_response("Failed to fetch profile from Open edX", 502)

# ===== NEW: Course Progress Endpoints =====

@app.route("/api/courses")
def get_courses():
    """Get all enrolled courses for the authenticated user"""
    if not is_authenticated():
        return make_response("Unauthorized", 401)
    
    user_info = get_user_info()
    if not user_info:
        return make_response("Unable to get user information", 400)
    
    username = user_info.get("username")
    if not username:
        return make_response("Username not found", 400)
    
    token = get_access_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        # Get enrollments
        enrollment_url = f"{OPENEDX_BASE_URL}/api/enrollment/v1/enrollment"
        r = requests.get(enrollment_url, headers=headers, params={"user": username}, timeout=20)
        
        if r.status_code != 200:
            return make_response(f"Failed to fetch enrollments: {r.text}", r.status_code)
        
        enrollments = r.json()
        
        # Format response
        courses = []
        for enrollment in enrollments:
            course_details = enrollment.get("course_details", {})
            courses.append({
                "course_id": course_details.get("course_id"),
                "course_name": course_details.get("course_name"),
                "enrollment_mode": enrollment.get("mode"),
                "is_active": enrollment.get("is_active"),
                "created": enrollment.get("created"),
            })
        
        return jsonify({"courses": courses, "username": username})
    
    except Exception as e:
        return make_response(f"Error: {str(e)}", 500)


@app.route("/api/course/<path:course_id>/progress")
def get_course_progress(course_id):
    """Get detailed progress for a specific course"""
    if not is_authenticated():
        return make_response("Unauthorized", 401)
    
    user_info = get_user_info()
    if not user_info:
        return make_response("Unable to get user information", 400)
    
    username = user_info.get("username")
    if not username:
        return make_response("Username not found", 400)
    
    token = get_access_token()
    headers = {"Authorization": f"Bearer {token}"}
    encoded_course_id = quote_plus(course_id)
    
    progress_data = {
        "course_id": course_id,
        "username": username
    }
    
    try:
        # 1. Get completion data
        completion_url = f"{OPENEDX_BASE_URL}/api/completion/v1/course/{encoded_course_id}/"
        try:
            r = requests.get(completion_url, headers=headers, params={"username": username}, timeout=20)
            if r.status_code == 200:
                progress_data["completion"] = r.json()
        except Exception as e:
            progress_data["completion_error"] = str(e)
        
        # 2. Get grades
        grades_url = f"{OPENEDX_BASE_URL}/api/grades/v1/courses/{encoded_course_id}/"
        try:
            r = requests.get(grades_url, headers=headers, params={"username": username}, timeout=20)
            if r.status_code == 200:
                progress_data["grades"] = r.json()
        except Exception as e:
            progress_data["grades_error"] = str(e)
        
        # 3. Get course blocks (structure with completion status)
        blocks_url = f"{OPENEDX_BASE_URL}/api/courses/v2/blocks/"
        try:
            r = requests.get(
                blocks_url,
                headers=headers,
                params={
                    "course_id": course_id,
                    "username": username,
                    "depth": "all",
                    "requested_fields": "completion,graded"
                },
                timeout=20
            )
            if r.status_code == 200:
                progress_data["blocks"] = r.json()
        except Exception as e:
            progress_data["blocks_error"] = str(e)
        
        return jsonify(progress_data)
    
    except Exception as e:
        return make_response(f"Error: {str(e)}", 500)


@app.route("/api/courses/progress")
def get_all_courses_progress():
    """Get progress for all enrolled courses"""
    if not is_authenticated():
        return make_response("Unauthorized", 401)
    
    user_info = get_user_info()
    if not user_info:
        return make_response("Unable to get user information", 400)
    
    username = user_info.get("username")
    if not username:
        return make_response("Username not found", 400)
    
    token = get_access_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        # Get enrollments
        enrollment_url = f"{OPENEDX_BASE_URL}/api/enrollment/v1/enrollment"
        r = requests.get(enrollment_url, headers=headers, params={"user": username}, timeout=20)
        
        if r.status_code != 200:
            return make_response(f"Failed to fetch enrollments: {r.text}", r.status_code)
        
        enrollments = r.json()
        
        # Fetch progress for each course
        courses_with_progress = []
        for enrollment in enrollments:
            course_details = enrollment.get("course_details", {})
            course_id = course_details.get("course_id")
            
            if not course_id:
                continue
            
            course_data = {
                "course_id": course_id,
                "course_name": course_details.get("course_name"),
                "enrollment_mode": enrollment.get("mode"),
                "is_active": enrollment.get("is_active"),
            }
            
            # Get completion
            encoded_course_id = quote_plus(course_id)
            try:
                completion_url = f"{OPENEDX_BASE_URL}/api/completion/v1/course/{encoded_course_id}/"
                comp_r = requests.get(
                    completion_url, 
                    headers=headers, 
                    params={"username": username}, 
                    timeout=10
                )
                if comp_r.status_code == 200:
                    course_data["completion"] = comp_r.json()
            except Exception:
                pass
            
            # Get grades
            try:
                grades_url = f"{OPENEDX_BASE_URL}/api/grades/v1/courses/{encoded_course_id}/"
                grade_r = requests.get(
                    grades_url,
                    headers=headers,
                    params={"username": username},
                    timeout=10
                )
                if grade_r.status_code == 200:
                    course_data["grades"] = grade_r.json()
            except Exception:
                pass
            
            courses_with_progress.append(course_data)
        
        return jsonify({
            "username": username,
            "courses": courses_with_progress
        })
    
    except Exception as e:
        return make_response(f"Error: {str(e)}", 500)

# ===== End Course Progress Endpoints =====
 
@app.route("/logout")
def logout():
    session.clear()  # Clear all session data including user_info
    # If you want to also end the LMS session, redirect through LMS logout:
    edx_logout = f"{OPENEDX_BASE_URL}/logout"
    return redirect(edx_logout, code=302)
 
# ===== Weather proxy (hides your OpenWeather key) =====
@app.route("/weather")
def weather_proxy():
    """GET /weather?city=Kollam"""
    if not is_authenticated():
        return make_response("Unauthorized", 401)
 
    if not OPENWEATHER_API_KEY:
        return make_response("Server missing OPENWEATHER_API_KEY", 500)
 
    city = (request.args.get("city") or "").strip()
    if not city:
        return make_response("Missing 'city' parameter", 400)
 
    url = f"https://api.openweathermap.org/data/2.5/weather?units=metric&q={quote_plus(city)}&appid={OPENWEATHER_API_KEY}"
    rr = requests.get(url, timeout=20)
    return (rr.text, rr.status_code, {"Content-Type": "application/json"})
 
# Health check for Render
@app.route("/healthz")
def health():
    return "ok", 200
 
if __name__ == "__main__":
    # Local dev only (Render uses gunicorn)
    app.run(host="0.0.0.0", port=5000, debug=True)