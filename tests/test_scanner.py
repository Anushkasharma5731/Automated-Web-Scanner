from types import SimpleNamespace
import json
import pytest
import security
import requests
import urllib3.util.connection
from security import _PinnedHTTPConnection
from security import UnsafeTarget, validate_url
from header_checks import analyze_headers
from cors_checks import analyze_cors, TEST_ORIGIN
from report_generator import render_html, save_reports

def test_private_and_localhost_rejected():
    for value in ("http://127.0.0.1", "http://localhost", "http://10.1.2.3", "http://169.254.169.254"):
        with pytest.raises(UnsafeTarget): validate_url(value)

def test_malformed_url_rejected():
    for value in ("ftp://example.com", "https://user:pass@example.com", "not a URL", "https://"):
        with pytest.raises(UnsafeTarget): validate_url(value)

def test_dns_rejects_mixed_public_and_private(monkeypatch):
    monkeypatch.setattr(security.socket, "getaddrinfo", lambda *a, **k: [(None,None,None,None,("8.8.8.8",0)),(None,None,None,None,("10.0.0.1",0))])
    with pytest.raises(UnsafeTarget): security.resolve_public("example.test",443)

def test_connection_uses_pinned_ip(monkeypatch):
    seen = {}
    class Sock:
        def settimeout(self, value): pass
        def close(self): pass
    def fake_connect(address, timeout=None, source_address=None, socket_options=None):
        seen["address"] = address
        return Sock()
    monkeypatch.setattr(urllib3.util.connection, "create_connection", fake_connect)
    connection = _PinnedHTTPConnection("original.example", port=80, pinned_ip="8.8.8.8", timeout=1)
    connection._new_conn()
    assert seen["address"] == ("8.8.8.8", 80)

def test_safe_request_timeout_and_connection_errors(monkeypatch):
    monkeypatch.setattr(security, "validate_url", lambda u: "https://example.test/")
    monkeypatch.setattr(security, "resolve_public", lambda *a: ["8.8.8.8"])
    calls = {}
    class Session:
        trust_env = True
        cookies = SimpleNamespace(clear=lambda: None)
        def mount(self, *args): pass
        def request(self, *args, **kwargs):
            calls.update(kwargs)
            raise requests.ConnectTimeout("mock timeout")
        def close(self): pass
    monkeypatch.setattr(security.requests, "Session", Session)
    with pytest.raises(requests.ConnectTimeout): security.safe_get("https://example.test")
    assert calls["timeout"] == security.TIMEOUT
    assert calls["allow_redirects"] is False and calls["verify"] is True and calls["stream"] is True

def test_oversized_response_is_capped(monkeypatch):
    monkeypatch.setattr(security, "validate_url", lambda u: "https://example.test/")
    monkeypatch.setattr(security, "resolve_public", lambda *a: ["8.8.8.8"])
    class Raw:
        def read(self, count, decode_content=True):
            assert count == security.MAX_BODY_BYTES + 1
            return b"x" * count
    response = SimpleNamespace(raw=Raw(), headers={}, status_code=200, url="https://example.test/",
                               close=lambda: None, _content=None, _content_consumed=False)
    class Session:
        trust_env = True
        cookies = SimpleNamespace(clear=lambda: None)
        def mount(self, *args): pass
        def request(self, *args, **kwargs): return response
        def close(self): pass
    monkeypatch.setattr(security.requests, "Session", Session)
    result = security.safe_get("https://example.test")
    assert len(result._content) == security.MAX_BODY_BYTES
    assert result.headers["X-Scanner-Body-Truncated"] == "true"

def test_redirect_validation(monkeypatch):
    monkeypatch.setattr(security, "validate_url", lambda u: u if u.startswith("http") else (_ for _ in ()).throw(UnsafeTarget("blocked")))
    monkeypatch.setattr(security, "safe_get", lambda *a, **k: SimpleNamespace(status_code=302, headers={"Location":"http://127.0.0.1"}))
    with pytest.raises(UnsafeTarget): security.request_with_redirects("https://example.test")

def test_header_presence_and_malformed_values():
    results = analyze_headers({"X-Content-Type-Options":"wrong", "X-Frame-Options":"ALLOWALL"}, "https://example.test")
    names = {x.name for x in results}
    assert "Invalid X-Content-Type-Options" in names
    assert "Unrecognized X-Frame-Options" in names
    assert "Strict-Transport-Security missing on HTTPS" in names
    assert "Content-Security-Policy missing" in names

def test_csp_frame_ancestors_alternative():
    results = analyze_headers({"Content-Security-Policy":"default-src 'self'; frame-ancestors 'none'"},"https://example.test")
    assert "Framing protection not observed" not in {x.name for x in results}
    assert "X-Frame-Options missing" not in {x.name for x in results}

def test_wildcard_cors_is_informational_and_preflight():
    base = SimpleNamespace(headers={})
    origin = SimpleNamespace(headers={"Access-Control-Allow-Origin":"*"})
    null = SimpleNamespace(headers={})
    preflight = SimpleNamespace(status_code=204, headers={"Access-Control-Allow-Methods":"GET"})
    results = analyze_cors(base,origin,null,preflight)
    assert next(x for x in results if x.name == "Wildcard CORS origin").severity == "Informational"
    assert any("preflight" in x.name.lower() for x in results)

def test_reflection_credentials_and_vary():
    base = SimpleNamespace(headers={})
    origin = SimpleNamespace(headers={"Access-Control-Allow-Origin":TEST_ORIGIN,"Access-Control-Allow-Credentials":"true"})
    null = SimpleNamespace(headers={"Access-Control-Allow-Origin":"null"})
    results = analyze_cors(base,origin,null,SimpleNamespace(status_code=200,headers={}))
    assert next(x for x in results if x.name == "Untrusted Origin accepted").severity == "Medium"
    assert any(x.name == "Null Origin allowed" for x in results)
    assert any(x.name == "Vary: Origin may be missing" for x in results)

def test_reports_json_and_html_escape(tmp_path):
    report={"target_url":"https://example.test/?x=<script>","findings":[{"name":"<img>","severity":"Low","confidence":"High","evidence":"<script>alert(1)</script>","impact":"impact","remediation":"fix"}],"summary":{},"checks_performed":[],"errors":[]}
    assert "&lt;script&gt;" in render_html(report) and "<script>alert" not in render_html(report)
    jp,hp=save_reports(report,tmp_path)
    assert json.loads(jp.read_text())["target_url"] == report["target_url"]
    assert hp.exists()

def test_dashboard_shows_actionable_connection_error(monkeypatch):
    import app as dashboard
    import re
    monkeypatch.setattr(dashboard, "run_scan", lambda target: (_ for _ in ()).throw(requests.ConnectTimeout("private query must not appear")))
    client = dashboard.app.test_client()
    page = client.get("/")
    token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
    response = client.post("/scan", data={"url":"https://example.test", "csrf_token":token})
    assert response.status_code == 400
    assert b"Connection timed out" in response.data
    assert b"private query" not in response.data
