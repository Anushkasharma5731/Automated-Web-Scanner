# Automated Web Security Scanner

A beginner-friendly Python 3.11+ tool for auditing HTTP security headers and CORS behavior on one explicitly authorized public website. It provides a command-line interface, JSON and escaped HTML reports, and a Flask dashboard. The scanner does not crawl or authenticate to the target website.

## Features

- Checks CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy.
- Sends baseline, test Origin, null Origin, and OPTIONS requests; records evidence without attempting to read private data.
- Reports severity, confidence, impact, remediation, summary, status, duration, and incomplete checks.
- Rejects prohibited address ranges, resolves and rechecks DNS before every hop, pins new HTTP connections to a resolved public IP, checks redirects manually, and retains TLS certificate verification.
- Uses short timeouts, at most three redirects per request sequence (16 total requests maximum), a 64 KiB response cap per response, four request sequences, no cookies, no proxy environment configuration, and one sequential scan at a time.
- Writes reports under unique names and keeps up to 50 minimal local history entries.

## Structure

```text
app.py                 Flask dashboard (localhost in development; authenticated in production)
scanner.py             Scan orchestration
security.py            URL, DNS, redirect, connection, and response safeguards
header_checks.py       Security header analysis
cors_checks.py         CORS analysis
severity.py            Finding records and severity types
report_generator.py    JSON and escaped HTML reports
templates/index.html  Dashboard
static/style.css       Dashboard styling
tests/                 Mocked unit tests
requirements.txt       Dependencies
Dockerfile             Non-root production container
compose.yaml            Hardened single-host Compose deployment
.env.example            Required production configuration template
```

## Install

Python 3.11 or newer is required. From this directory:

```bash
python3 -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run a scan

Only scan a site you own or have explicit permission to test.

```bash
python scanner.py https://example.com
```

Reports are written to `reports/`. Each has a timestamp and random suffix. Exit status is nonzero for input, network, or safety errors.

## Local dashboard

```bash
python app.py
```

Open `http://127.0.0.1:5000`. The development server binds to loopback. The page includes a URL form, progress indicator, findings table, report downloads, and local scan history.

## Container deployment

Production mode requires an administrator login, a strong Flask signing secret, and an allowed host list. Serve it behind a TLS reverse proxy; do not publish the container port directly to the Internet. Basic authentication is used, so TLS is mandatory. Compose binds port 8000 to loopback for a local reverse proxy, runs one non-root Gunicorn worker, limits scan concurrency, enables rate limiting, drops Linux capabilities, mounts persistent report storage, and runs the container read-only.

1. Install Docker Engine and the Compose plugin on a supported Linux server.
2. Copy `.env.example` to `.env`; replace all placeholders. Generate a signing secret with `python3 -c 'import secrets; print(secrets.token_urlsafe(48))'`. Set `SCANNER_ALLOWED_HOSTS` to the exact public hostname plus `localhost,127.0.0.1` for the included container health check (comma-separated). Use a unique password of at least 20 characters.
3. Configure a TLS reverse proxy for that hostname and proxy to `127.0.0.1:8000`. Restrict access to the proxy; do not make port 8000 public.
4. Build and start the service:

   ```bash
   docker compose up --build -d
   docker compose ps
   docker compose logs -f scanner
   ```

5. Visit the HTTPS hostname and sign in with the configured username and password. Keep `.env` private and back up the `scanner-reports` volume according to your retention policy.

`SCANNER_RATE_LIMIT_STORAGE=memory://` is suitable for the provided single-container, single-worker setup. For multiple replicas, configure a shared Redis-compatible rate-limit store and update the environment value. This is an active outbound request service: keep authentication enabled, restrict who can reach it, and monitor scan volume. Operators must configure TLS and network controls correctly.

Production configuration fails at startup if credentials, the session secret, or allowed hostnames are missing or too weak. The dashboard applies CSRF checks, Host validation, security response headers, secure production cookies, per-IP rate limits, and a one-scan-at-a-time process lock. `/healthz` is an unauthenticated liveness endpoint and reveals only a generic status.

## Example report finding

```json
{
  "name": "Strict-Transport-Security missing on HTTPS",
  "severity": "Low",
  "confidence": "Medium",
  "evidence": "No Strict-Transport-Security header on the HTTPS response.",
  "impact": "Browsers may use HTTP on a later visit, allowing downgrade or network interception risks.",
  "remediation": "Set a suitable max-age after confirming HTTPS is available across the domain."
}
```

The scanner distinguishes configuration advice from confirmed vulnerabilities. A wildcard CORS policy is informational for public, non-credentialed resources; browsers do not permit credentialed access with wildcard ACAO. Origin reflection, including `null`, is a risk signal whose impact depends on endpoint sensitivity. No sensitive data is requested or accessed.

## Severity levels

- **Critical / High:** Reserved for evidence of severe, likely impact. The current passive checks do not claim these from header absence alone.
- **Medium:** Riskier observed policy such as an untrusted Origin accepted together with credentials.
- **Low:** Weak or absent defense-in-depth settings or possible policy concerns.
- **Informational:** Observed behavior or a recommendation without evidence of exploitable impact.

Confidence indicates confidence in the observation, not confidence that exploitation is possible.

## Tests

```bash
pytest -q
```

Tests use mocked HTTP-related behavior and deterministic local fixtures; they do not scan external sites.

## Safety limitations and responsible use

This is a narrow header and CORS configuration audit, not a penetration test, vulnerability scanner, or proof that an application is safe. It does not crawl paths, inspect JavaScript, authenticate, or determine whether response content is sensitive. Responses vary by path, user, cache, and CDN; a scan of `/` cannot establish the policy of every endpoint. CORS findings need application-owner review.

The safeguards prevent requests to non-public IP ranges and re-resolve/pin the connection address for each request. Proxies are disabled and redirects are validated individually. DNS changes after validation cannot redirect the pinned socket to another address. Some complex DNS, proxy, CDN, or network environments may cause safe scans to be rejected. Do not weaken these controls to reach internal or metadata services.

Use only with explicit authorization and within the approved scope. The scanner makes four small request sequences per scan and does not follow page links. It sends no authentication cookies or credentials. Do not use it to test third-party systems without permission.
