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
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
)
 
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
 
# ===== Config (ENV) =====
OPENEDX_BASE_URL = os.environ.get("OPENEDX_BASE_URL", "").rstrip("/")
OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "")
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:5000/callback")
OAUTH_SCOPES = os.environ.get("OAUTH_SCOPES", "read profile").strip()
OAUTH_USE_PKCE_ENV = os.environ.get("OAUTH_USE_PKCE", "auto").lower()
 
AUTHZ_URL = f"{OPENEDX_BASE_URL}/oauth2/authorize"
TOKEN_URL = f"{OPENEDX_BASE_URL}/oauth2/access_token"
ME_URL = f"{OPENEDX_BASE_URL}/api/user/v1/me"
 
OPENWEATHER_API_KEY = os.environ.get("OPENWEATHER_API_KEY", "")
 
# ===== Helpers: PKCE =====
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
 
def create_pkce():
    code_verifier = _b64url(os.urandom(40))
    code_challenge = _b64url(hashlib.sha256(code_verifier.encode()).digest())
    return code_verifier, code_challenge
 
# ===== Auth helpers =====
def is_authenticated():
    tok = session.get("oauth", {})
    if not tok or "access_token" not in tok:
        return False
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
    if not is_authenticated():
        return None
    return session["oauth"]["access_token"]

def get_user_info():
    if "user_info" in session:
        return session["user_info"]
    
    token = get_access_token()
    if not token:
        return None
    
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(ME_URL, headers=headers, timeout=20)
        if r.status_code == 200:
            user_info = r.json()
            session["user_info"] = user_info
            return user_info
    except Exception as e:
        print(f"Error fetching user info: {e}")
    
    return None
 
# ===== URL helpers =====
def _external_base_url() -> str:
    return (request.url_root or "").rstrip("/")
 
def _redirect_uri_effective() -> str:
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
    if env_path in ("", "/"):
        return f"{_external_base_url()}/callback"
    return REDIRECT_URI
 
def use_pkce() -> bool:
    if OAUTH_USE_PKCE_ENV in ("1", "true", "yes", "on"):
        return True
    if OAUTH_USE_PKCE_ENV in ("0", "false", "no", "off"):
        return False
    return not bool(OAUTH_CLIENT_SECRET)

# ===== NEW: Helper function to parse block structure =====
def parse_course_structure(blocks_data, username):
    """
    Parse course blocks into a hierarchical structure with completion data
    Returns: chapters -> sections -> units -> components with completion status
    """
    blocks = blocks_data.get("blocks", {})
    root_id = blocks_data.get("root", "")
    
    if not root_id or not blocks:
        return None
    
    structure = {
        "course_id": root_id,
        "chapters": []
    }
    
    root_block = blocks.get(root_id, {})
    
    # Get all chapters (top-level sections)
    for chapter_id in root_block.get("children", []):
        chapter = blocks.get(chapter_id, {})
        if chapter.get("type") != "chapter":
            continue
        
        chapter_data = {
            "id": chapter_id,
            "display_name": chapter.get("display_name", "Untitled Chapter"),
            "type": chapter.get("type"),
            "completion": chapter.get("completion", 0),
            "sections": []
        }
        
        # Get all sections (sequentials) in this chapter
        for section_id in chapter.get("children", []):
            section = blocks.get(section_id, {})
            if section.get("type") != "sequential":
                continue
            
            section_data = {
                "id": section_id,
                "display_name": section.get("display_name", "Untitled Section"),
                "type": section.get("type"),
                "completion": section.get("completion", 0),
                "graded": section.get("graded", False),
                "units": []
            }
            
            # Get all units (verticals) in this section
            for unit_id in section.get("children", []):
                unit = blocks.get(unit_id, {})
                if unit.get("type") != "vertical":
                    continue
                
                unit_data = {
                    "id": unit_id,
                    "display_name": unit.get("display_name", "Untitled Unit"),
                    "type": unit.get("type"),
                    "completion": unit.get("completion", 0),
                    "components": []
                }
                
                # Get all components (actual content) in this unit
                for component_id in unit.get("children", []):
                    component = blocks.get(component_id, {})
                    component_type = component.get("type", "unknown")
                    
                    component_data = {
                        "id": component_id,
                        "display_name": component.get("display_name", "Untitled Component"),
                        "type": component_type,
                        "completion": component.get("completion", 0),
                        "graded": component.get("graded", False),
                        "block_type": component_type  # video, problem, html, discussion, etc.
                    }
                    
                    unit_data["components"].append(component_data)
                
                # Calculate unit completion percentage
                if unit_data["components"]:
                    completed = sum(1 for c in unit_data["components"] if c["completion"] == 1)
                    total = len(unit_data["components"])
                    unit_data["completion_percentage"] = (completed / total * 100) if total > 0 else 0
                    unit_data["completed_count"] = completed
                    unit_data["total_count"] = total
                else:
                    unit_data["completion_percentage"] = 0
                    unit_data["completed_count"] = 0
                    unit_data["total_count"] = 0
                
                section_data["units"].append(unit_data)
            
            # Calculate section completion percentage
            if section_data["units"]:
                total_components = sum(u["total_count"] for u in section_data["units"])
                completed_components = sum(u["completed_count"] for u in section_data["units"])
                section_data["completion_percentage"] = (completed_components / total_components * 100) if total_components > 0 else 0
                section_data["completed_count"] = completed_components
                section_data["total_count"] = total_components
            else:
                section_data["completion_percentage"] = 0
                section_data["completed_count"] = 0
                section_data["total_count"] = 0
            
            chapter_data["sections"].append(section_data)
        
        # Calculate chapter completion percentage
        if chapter_data["sections"]:
            total_components = sum(s["total_count"] for s in chapter_data["sections"])
            completed_components = sum(s["completed_count"] for s in chapter_data["sections"])
            chapter_data["completion_percentage"] = (completed_components / total_components * 100) if total_components > 0 else 0
            chapter_data["completed_count"] = completed_components
            chapter_data["total_count"] = total_components
        else:
            chapter_data["completion_percentage"] = 0
            chapter_data["completed_count"] = 0
            chapter_data["total_count"] = 0
        
        structure["chapters"].append(chapter_data)
    
    # Calculate overall course completion
    if structure["chapters"]:
        total_components = sum(c["total_count"] for c in structure["chapters"])
        completed_components = sum(c["completed_count"] for c in structure["chapters"])
        structure["overall_completion_percentage"] = (completed_components / total_components * 100) if total_components > 0 else 0
        structure["overall_completed_count"] = completed_components
        structure["overall_total_count"] = total_components
    else:
        structure["overall_completion_percentage"] = 0
        structure["overall_completed_count"] = 0
        structure["overall_total_count"] = 0
    
    return structure
 
# ===== Routes =====
 
@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/weather")
def weather_page():
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

# ===== Course Progress Endpoints =====

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
        enrollment_url = f"{OPENEDX_BASE_URL}/api/enrollment/v1/enrollment"
        r = requests.get(enrollment_url, headers=headers, params={"user": username}, timeout=20)
        
        if r.status_code != 200:
            return make_response(f"Failed to fetch enrollments: {r.text}", r.status_code)
        
        enrollments = r.json()
        
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
    """
    Get DETAILED unit-wise and topic-wise progress for a specific course
    Returns hierarchical structure: Chapters -> Sections -> Units -> Components
    """
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
        "username": username,
        "timestamp": time.time()
    }
    
    try:
        # 1. Get overall completion summary
        completion_url = f"{OPENEDX_BASE_URL}/api/completion/v1/course/{encoded_course_id}/"
        try:
            r = requests.get(completion_url, headers=headers, params={"username": username}, timeout=20)
            if r.status_code == 200:
                completion_data = r.json()
                progress_data["completion_summary"] = completion_data
        except Exception as e:
            progress_data["completion_error"] = str(e)
        
        # 2. Get grades
        grades_url = f"{OPENEDX_BASE_URL}/api/grades/v1/courses/{encoded_course_id}/"
        try:
            r = requests.get(grades_url, headers=headers, params={"username": username}, timeout=20)
            if r.status_code == 200:
                grades_data = r.json()
                progress_data["grades"] = grades_data
        except Exception as e:
            progress_data["grades_error"] = str(e)
        
        # 3. Get DETAILED course blocks with completion status for EVERY component
        blocks_url = f"{OPENEDX_BASE_URL}/api/courses/v2/blocks/"
        try:
            r = requests.get(
                blocks_url,
                headers=headers,
                params={
                    "course_id": course_id,
                    "username": username,
                    "depth": "all",  # Get ALL levels
                    "all_blocks": "true",  # Include all block types
                    "requested_fields": "completion,graded,children,display_name,type"
                },
                timeout=30
            )
            if r.status_code == 200:
                blocks_data = r.json()
                
                # Parse into hierarchical structure
                structured_progress = parse_course_structure(blocks_data, username)
                
                if structured_progress:
                    progress_data["detailed_progress"] = structured_progress
                
                # Also include raw blocks for debugging/advanced use
                progress_data["raw_blocks"] = blocks_data
                
        except Exception as e:
            progress_data["blocks_error"] = str(e)
        
        return jsonify(progress_data)
    
    except Exception as e:
        return make_response(f"Error: {str(e)}", 500)


@app.route("/api/course/<path:course_id>/progress/summary")
def get_course_progress_summary(course_id):
    """
    Get a simplified summary of course progress
    Good for dashboard/overview displays
    """
    if not is_authenticated():
        return make_response("Unauthorized", 401)
    
    user_info = get_user_info()
    if not user_info:
        return make_response("Unable to get user information", 400)
    
    username = user_info.get("username")
    token = get_access_token()
    headers = {"Authorization": f"Bearer {token}"}
    encoded_course_id = quote_plus(course_id)
    
    summary = {
        "course_id": course_id,
        "username": username
    }
    
    try:
        # Get completion
        completion_url = f"{OPENEDX_BASE_URL}/api/completion/v1/course/{encoded_course_id}/"
        r = requests.get(completion_url, headers=headers, params={"username": username}, timeout=20)
        if r.status_code == 200:
            comp_data = r.json()
            summary["completion_percentage"] = comp_data.get("completion_percentage", 0)
            summary["completion_summary"] = comp_data.get("completion_summary", {})
        
        # Get grades
        grades_url = f"{OPENEDX_BASE_URL}/api/grades/v1/courses/{encoded_course_id}/"
        r = requests.get(grades_url, headers=headers, params={"username": username}, timeout=20)
        if r.status_code == 200:
            grade_data = r.json()
            summary["grade_percent"] = grade_data.get("percent", 0)
            summary["passed"] = grade_data.get("passed", False)
            summary["letter_grade"] = grade_data.get("letter_grade", "N/A")
        
        return jsonify(summary)
    
    except Exception as e:
        return make_response(f"Error: {str(e)}", 500)


@app.route("/api/courses/progress")
def get_all_courses_progress():
    """
    Get progress summary for ALL enrolled courses
    """
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
        enrollment_url = f"{OPENEDX_BASE_URL}/api/enrollment/v1/enrollment"
        r = requests.get(enrollment_url, headers=headers, params={"user": username}, timeout=20)
        
        if r.status_code != 200:
            return make_response(f"Failed to fetch enrollments: {r.text}", r.status_code)
        
        enrollments = r.json()
        
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
            
            encoded_course_id = quote_plus(course_id)
            
            # Get completion
            try:
                completion_url = f"{OPENEDX_BASE_URL}/api/completion/v1/course/{encoded_course_id}/"
                comp_r = requests.get(
                    completion_url, 
                    headers=headers, 
                    params={"username": username}, 
                    timeout=10
                )
                if comp_r.status_code == 200:
                    comp_data = comp_r.json()
                    course_data["completion_percentage"] = comp_data.get("completion_percentage", 0)
                    course_data["completion_summary"] = comp_data.get("completion_summary", {})
            except Exception:
                course_data["completion_percentage"] = 0
            
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
                    grade_data = grade_r.json()
                    course_data["grade_percent"] = grade_data.get("percent", 0)
                    course_data["passed"] = grade_data.get("passed", False)
                    course_data["letter_grade"] = grade_data.get("letter_grade", "N/A")
            except Exception:
                course_data["grade_percent"] = 0
            
            courses_with_progress.append(course_data)
        
        return jsonify({
            "username": username,
            "total_courses": len(courses_with_progress),
            "courses": courses_with_progress
        })
    
    except Exception as e:
        return make_response(f"Error: {str(e)}", 500)


@app.route("/api/course/<path:course_id>/units/completed")
def get_completed_units(course_id):
    """
    Get list of completed units/topics only
    Useful for displaying "what the user has finished"
    """
    if not is_authenticated():
        return make_response("Unauthorized", 401)
    
    user_info = get_user_info()
    if not user_info:
        return make_response("Unable to get user information", 400)
    
    username = user_info.get("username")
    token = get_access_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        blocks_url = f"{OPENEDX_BASE_URL}/api/courses/v2/blocks/"
        r = requests.get(
            blocks_url,
            headers=headers,
            params={
                "course_id": course_id,
                "username": username,
                "depth": "all",
                "requested_fields": "completion,display_name,type"
            },
            timeout=20
        )
        
        if r.status_code != 200:
            return make_response("Failed to fetch blocks", r.status_code)
        
        blocks_data = r.json()
        blocks = blocks_data.get("blocks", {})
        
        completed_items = []
        
        for block_id, block in blocks.items():
            if block.get("completion") == 1:  # Completed
                completed_items.append({
                    "id": block_id,
                    "display_name": block.get("display_name", "Untitled"),
                    "type": block.get("type"),
                    "block_type": block.get("type")
                })
        
        return jsonify({
            "course_id": course_id,
            "username": username,
            "completed_count": len(completed_items),
            "completed_items": completed_items
        })
    
    except Exception as e:
        return make_response(f"Error: {str(e)}", 500)

# ===== End Course Progress Endpoints =====
 
@app.route("/logout")
def logout():
    session.clear()
    edx_logout = f"{OPENEDX_BASE_URL}/logout"
    return redirect(edx_logout, code=302)
 
@app.route("/weather")
def weather_proxy():
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
 
@app.route("/healthz")
def health():
    return "ok", 200
 
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)