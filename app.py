"""Flask dashboard for authorized scans, with required authentication in production."""
from __future__ import annotations
import json, logging
import hmac
import os
import secrets
import threading
from pathlib import Path
from flask import Flask, abort, flash, make_response, render_template, request, send_file, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
from security import UnsafeTarget
from scanner import run_scan
from report_generator import save_reports

app = Flask(__name__)
IS_PRODUCTION = os.environ.get("SCANNER_ENV", "development").lower() == "production"
SECRET_KEY = os.environ.get("SCANNER_SECRET_KEY")
AUTH_USERNAME = os.environ.get("SCANNER_AUTH_USERNAME")
AUTH_PASSWORD = os.environ.get("SCANNER_AUTH_PASSWORD")
allowed_hosts = [host.strip() for host in os.environ.get("SCANNER_ALLOWED_HOSTS", "").split(",") if host.strip()]
if IS_PRODUCTION:
    missing = [name for name, value in (("SCANNER_SECRET_KEY", SECRET_KEY), ("SCANNER_AUTH_USERNAME", AUTH_USERNAME),
                                         ("SCANNER_AUTH_PASSWORD", AUTH_PASSWORD), ("SCANNER_ALLOWED_HOSTS", allowed_hosts)) if not value]
    if missing:
        raise RuntimeError("Production configuration missing: " + ", ".join(missing))
    if len(SECRET_KEY or "") < 32 or len(AUTH_PASSWORD or "") < 20:
        raise RuntimeError("Production secret key must be at least 32 characters and password at least 20 characters")
    app.config["TRUSTED_HOSTS"] = allowed_hosts
app.secret_key = SECRET_KEY or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 4096
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=IS_PRODUCTION)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
REPORT_DIR = Path(os.environ.get("SCANNER_REPORT_DIR", "reports"))
HISTORY_PATH = REPORT_DIR / "scan_history.json"
scan_lock = threading.BoundedSemaphore(1)
limiter = Limiter(get_remote_address, app=app, default_limits=["120 per hour"],
                  storage_uri=os.environ.get("SCANNER_RATE_LIMIT_STORAGE", "memory://"),
                  headers_enabled=True)

@app.before_request
def require_deployment_auth_and_csrf():
    """Protect the public dashboard and its scan action when deployed."""
    if IS_PRODUCTION and request.endpoint != "healthz":
        auth = request.authorization
        username_ok = bool(auth and hmac.compare_digest(auth.username or "", AUTH_USERNAME or ""))
        password_ok = bool(auth and hmac.compare_digest(auth.password or "", AUTH_PASSWORD or ""))
        if not (username_ok and password_ok):
            response = make_response("Authentication required", 401)
            response.headers["WWW-Authenticate"] = 'Basic realm="Authorized Scanner", charset="UTF-8"'
            return response
    if request.method == "GET" and request.endpoint != "healthz":
        session.setdefault("csrf_token", secrets.token_urlsafe(32))
    if request.endpoint == "scan" and request.method == "POST":
        submitted = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(submitted, expected):
            abort(400, description="Invalid or expired form token. Reload the dashboard and try again.")

@app.after_request
def set_response_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'self'")
    response.headers.setdefault("Cache-Control", "no-store")
    return response

@app.get("/")
def index(): return render_template("index.html", result=None)

@app.get("/healthz")
def healthz():
    return {"status": "ok"}, 200

def _scan_error_message(exc: Exception) -> str:
    """Return a useful, non-sensitive dashboard error for common network failures."""
    if isinstance(exc, UnsafeTarget):
        return str(exc)
    if isinstance(exc, requests.exceptions.SSLError):
        return "TLS certificate verification failed. Check that the site has a valid HTTPS certificate, or try its HTTPS URL."
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "Connection timed out. Check the URL and whether the website is reachable from this computer."
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return "The website took too long to respond. Try again later or check with the site administrator."
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "Could not connect to the website. Check the URL, DNS, firewall, and network connection."
    if isinstance(exc, requests.exceptions.RequestException):
        return f"HTTP request failed ({type(exc).__name__}). Check the URL and network connection."
    return f"The scan failed ({type(exc).__name__}). Check the URL and network, then try again."

@app.post("/scan")
@limiter.limit("3 per minute")
def scan():
    target = request.form.get("url", "")
    if not scan_lock.acquire(blocking=False):
        return "A scan is already running. Try again shortly.", 429
    try:
        result = run_scan(target)
        jp, hp = save_reports(result, REPORT_DIR)
        result["json_name"], result["html_name"] = jp.name, hp.name
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        history_path = HISTORY_PATH
        history = json.loads(history_path.read_text("utf-8")) if history_path.exists() else []
        history.insert(0, {"target_url": result["target_url"], "scan_timestamp": result["scan_timestamp"],
                           "status_code": result["status_code"], "overall_assessment": result["summary"]["overall_assessment"],
                           "json_name": jp.name, "html_name": hp.name})
        history_path.write_text(json.dumps(history[:50], indent=2), encoding="utf-8")
        return render_template("index.html", result=result)
    except Exception as exc:
        app.logger.warning("Scan request rejected or failed: %s", type(exc).__name__)
        flash(_scan_error_message(exc), "error")
        return render_template("index.html", result=None), 400
    finally:
        scan_lock.release()

@app.get("/history")
def history():
    p = HISTORY_PATH
    rows = json.loads(p.read_text("utf-8")) if p.exists() else []
    return render_template("index.html", result=None, history=rows)

@app.get("/reports/<path:filename>")
def download(filename):
    safe_name = Path(filename).name
    if safe_name != filename or not safe_name.startswith("scan_") or Path(safe_name).suffix not in {".json", ".html"}:
        return "Not found", 404
    path = REPORT_DIR / safe_name
    if not path.is_file(): return "Not found", 404
    return send_file(path, as_attachment=True, download_name=safe_name)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
