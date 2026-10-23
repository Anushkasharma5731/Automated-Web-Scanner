"""Evidence-based checks for common browser security response headers."""
from __future__ import annotations
from severity import Finding, finding

def analyze_headers(headers, url: str) -> list[Finding]:
    h = {k.lower(): v.strip() for k, v in headers.items()}
    out: list[Finding] = []
    def add(name, severity, evidence, impact, fix, confidence="High"):
        out.append(finding(name, severity, evidence, impact, fix, confidence))
    csp = h.get("content-security-policy")
    if not csp:
        add("Content-Security-Policy missing", "Low", "No Content-Security-Policy response header.",
            "A CSP can reduce the impact of some injection flaws, but its absence alone does not prove an exploitable issue.",
            "Define a policy suited to the application, beginning with default-src 'self'; avoid unsafe-inline and unsafe-eval where practical.", "Medium")
    else:
        lower = csp.lower()
        weak = "*" in lower or "'unsafe-inline'" in lower or "'unsafe-eval'" in lower
        if weak:
            add("Potentially permissive Content-Security-Policy", "Low", csp[:300], "Broad sources or unsafe script directives weaken CSP's defense in depth.",
                "Restrict sources to required origins and remove unsafe directives using nonces or hashes where feasible.", "Medium")
        if "frame-ancestors" not in lower and "x-frame-options" not in h:
            add("Framing protection not observed", "Low", "CSP has no frame-ancestors directive and X-Frame-Options is absent.",
                "The site may be more susceptible to clickjacking if sensitive pages can be framed.",
                "Set frame-ancestors 'none' or an explicit trusted list; X-Frame-Options may support older browsers.", "Medium")
    hsts = h.get("strict-transport-security")
    if url.lower().startswith("https://"):
        if not hsts:
            add("Strict-Transport-Security missing on HTTPS", "Low", "No Strict-Transport-Security header on the HTTPS response.",
                "Browsers may use HTTP on a later visit, allowing downgrade or network interception risks.",
                "Set a suitable max-age after confirming HTTPS is available across the domain; includeSubDomains only when all subdomains are ready.", "Medium")
        else:
            import re
            m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
            if not m or int(m.group(1)) < 15552000:
                add("Weak HSTS policy", "Low", hsts[:250], "Missing or short max-age provides limited durable HTTPS enforcement.",
                    "Use a long max-age (commonly at least six months) after validating HTTPS coverage.", "Medium")
    elif hsts:
        add("HSTS observed over HTTP", "Informational", hsts[:250], "Browsers ignore HSTS received over insecure HTTP.",
            "Serve HSTS on the HTTPS endpoint; redirect HTTP to HTTPS.", "High")
    checks = [
        ("x-content-type-options", "X-Content-Type-Options missing", "Low", "nosniff"),
        ("x-frame-options", "X-Frame-Options missing", "Low", "DENY or SAMEORIGIN (or CSP frame-ancestors)"),
        ("referrer-policy", "Referrer-Policy missing", "Informational", "strict-origin-when-cross-origin or a more restrictive policy"),
        ("permissions-policy", "Permissions-Policy missing", "Informational", "explicitly disable or limit browser features the application does not need"),
    ]
    for key, title, sev, recommendation in checks:
        if key not in h:
            if key == "x-frame-options" and csp and "frame-ancestors" in csp.lower():
                continue
            add(title, sev, f"No {key} response header.", "This removes a browser defense-in-depth control; the header absence alone is not proof of a vulnerability.", f"Configure {recommendation}.", "Medium")
        elif key == "x-content-type-options" and h[key].lower() != "nosniff":
            add("Invalid X-Content-Type-Options", "Low", h[key][:150], "Browsers may not apply MIME sniffing protection.", "Set the value to nosniff.")
        elif key == "x-frame-options" and h[key].upper() not in {"DENY", "SAMEORIGIN"}:
            add("Unrecognized X-Frame-Options", "Low", h[key][:150], "The browser may not apply the intended framing restriction.", "Use DENY or SAMEORIGIN, or configure CSP frame-ancestors.")
    return out
