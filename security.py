"""URL and connection safety controls. Only public Internet destinations are eligible."""
from __future__ import annotations
import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit
import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.poolmanager import PoolManager

MAX_REDIRECTS = 3
MAX_REQUESTS = 16  # Four probe sequences, each with at most three redirect hops.
MAX_BODY_BYTES = 65536
TIMEOUT = (3.05, 5)

class UnsafeTarget(ValueError):
    """Raised when a target could reach a prohibited destination."""

def _public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value.split("%", 1)[0])
    return ip.is_global and not (ip.is_multicast or ip.is_reserved)

def resolve_public(host: str, port: int) -> list[str]:
    """Resolve host and reject the entire answer set if any address is non-public."""
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError) as exc:
        raise UnsafeTarget(f"DNS resolution failed for {host}") from exc
    addresses = sorted({item[4][0] for item in answers})
    if not addresses or any(not _public_ip(address) for address in addresses):
        raise UnsafeTarget(f"{host} resolves to a prohibited or non-public address")
    return addresses

def validate_url(url: str) -> str:
    """Normalize an HTTP(S) URL and verify its current DNS destinations."""
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 32 for c in url):
        raise UnsafeTarget("Enter a valid HTTP or HTTPS URL (maximum 2048 characters).")
    try:
        parts = urlsplit(url.strip())
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
            raise ValueError
        port = parts.port or (443 if scheme == "https" else 80)
        if not (1 <= port <= 65535):
            raise ValueError
        host = parts.hostname.rstrip(".")
        resolve_public(host, port)
        netloc = parts.netloc
        path = parts.path or "/"
        return urlunsplit((scheme, netloc, path, parts.query, ""))
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, UnsafeTarget):
            raise
        raise UnsafeTarget("Malformed URL. Enter a valid HTTP or HTTPS URL without credentials.") from exc

class _PinnedHTTPConnection(HTTPConnection):
    """Connect to the validated IP while retaining the URL host for the Host header."""
    def __init__(self, *args, pinned_ip: str | None = None, **kwargs):
        self.pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)
    def _new_conn(self):
        if self.pinned_ip:
            original = self.host
            self.host = self.pinned_ip
            try:
                return super()._new_conn()
            finally:
                self.host = original
        return super()._new_conn()

class _PinnedHTTPSConnection(HTTPSConnection):
    """Connect to validated IP, keeping hostname-based SNI and certificate checks."""
    def __init__(self, *args, pinned_ip: str | None = None, **kwargs):
        self.pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)
    def _new_conn(self):
        if self.pinned_ip:
            original = self.host
            self.host = self.pinned_ip
            try:
                return super()._new_conn()
            finally:
                self.host = original
        return super()._new_conn()

class PinnedAdapter(HTTPAdapter):
    """Requests adapter that pins each new connection to a freshly validated DNS IP."""
    def __init__(self, pinned_ip: str, *args, **kwargs):
        self.pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)
    def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize, block=block,
            **kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            "http": type("PinnedHTTPPool", (HTTPConnectionPool,), {"ConnectionCls": _PinnedHTTPConnection}),
            "https": type("PinnedHTTPSPool", (HTTPSConnectionPool,), {"ConnectionCls": _PinnedHTTPSConnection}),
        }
    def get_connection(self, url, proxies=None):
        pool = super().get_connection(url, proxies)
        pool.conn_kw["pinned_ip"] = self.pinned_ip
        return pool

def safe_get(url: str, *, origin: str | None = None, method: str = "GET") -> requests.Response:
    """Send one bounded request with redirects disabled and DNS pinned per request."""
    normalized = validate_url(url)
    parts = urlsplit(normalized)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    ip = resolve_public(parts.hostname or "", port)[0]
    headers = {"User-Agent": "AuthorizedSecurityHeaderScanner/1.0", "Accept": "*/*", "Range": f"bytes=0-{MAX_BODY_BYTES-1}"}
    if origin:
        headers["Origin"] = origin
    session = requests.Session()
    session.trust_env = False
    session.cookies.clear()
    session.mount(f"{parts.scheme}://", PinnedAdapter(ip))
    try:
        response = session.request(method, normalized, headers=headers, timeout=TIMEOUT,
                                   allow_redirects=False, verify=True, stream=True)
        # Consume at most limit+1 bytes to enforce a hard cap, then close the connection.
        response._content = response.raw.read(MAX_BODY_BYTES + 1, decode_content=True)
        if len(response._content) > MAX_BODY_BYTES:
            response._content = response._content[:MAX_BODY_BYTES]
            response.headers["X-Scanner-Body-Truncated"] = "true"
        response._content_consumed = True
        response.close()
        return response
    finally:
        session.close()

def request_with_redirects(url: str, *, origin: str | None = None, method: str = "GET") -> tuple[requests.Response, list[str]]:
    """Follow a small number of redirects manually; validate and pin every hop."""
    current = validate_url(url)
    trail = []
    for _ in range(MAX_REDIRECTS + 1):
        trail.append(current)
        response = safe_get(current, origin=origin, method=method)
        if response.status_code not in {301, 302, 303, 307, 308} or not response.headers.get("Location"):
            return response, trail
        if method == "OPTIONS" and response.status_code == 303:
            method = "GET"
        from urllib.parse import urljoin
        nxt = validate_url(urljoin(current, response.headers["Location"]))
        if len(trail) > 1 and nxt in trail:
            raise UnsafeTarget("Redirect loop detected")
        current = nxt
    raise UnsafeTarget("Redirect limit exceeded")
