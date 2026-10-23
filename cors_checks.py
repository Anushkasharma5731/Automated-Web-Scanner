"""Conservative CORS checks. Findings describe observed policy, not data exposure."""
from __future__ import annotations
from severity import Finding, finding

TEST_ORIGIN = "https://cors-audit.invalid"
NULL_ORIGIN = "null"

def analyze_cors(baseline, origin_response, null_response, preflight) -> list[Finding]:
    out: list[Finding] = []
    def add(*args, **kwargs): out.append(finding(*args, **kwargs))
    base = baseline.headers
    h = origin_response.headers
    allow = h.get("Access-Control-Allow-Origin", "")
    credentials = h.get("Access-Control-Allow-Credentials", "").lower() == "true"
    if allow == "*":
        add("Wildcard CORS origin", "Informational", "Access-Control-Allow-Origin: *", "Any website can read responses that the browser treats as public and non-credentialed; this is often intentional for public resources.", "Use an explicit origin allowlist for non-public data. Browsers reject wildcard origin with credentialed requests.", "High")
    elif allow == TEST_ORIGIN:
        sev = "Medium" if credentials else "Low"
        add("Untrusted Origin accepted", sev, f"Test Origin reflected/allowed with Access-Control-Allow-Credentials: {str(credentials).lower()}.",
            "An attacker-controlled website may be able to read cross-origin responses. Exploitability depends on endpoint sensitivity and browser credentials; no data access was attempted.",
            "Allow only trusted origins and enable credentials only for those origins.", "High")
    if null_response.headers.get("Access-Control-Allow-Origin") == "null":
        null_creds = null_response.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        add("Null Origin allowed", "Medium" if null_creds else "Low", f"Origin: null received Access-Control-Allow-Origin: null; credentials={str(null_creds).lower()}.",
            "Documents with opaque origins can receive this permission; credentials raise risk, but impact depends on the resource.",
            "Avoid allowing null unless a documented use case exists; never pair it with sensitive credentialed endpoints.", "High")
    if allow == TEST_ORIGIN and base.get("Access-Control-Allow-Origin") != allow and "origin" not in h.get("Vary", "").lower():
        add("Vary: Origin may be missing", "Low", "CORS response changed for the test Origin but Vary does not include Origin.",
            "Shared caches may serve a response variant across origins if cache behavior permits.", "Add Vary: Origin when the response varies by Origin.", "Medium")
    if preflight.status_code >= 400:
        add("CORS preflight not accepted", "Informational", f"OPTIONS returned HTTP {preflight.status_code}.", "The tested cross-origin method may not be available to browsers.", "Review intended methods and configure preflight only for required origins and methods.", "High")
    else:
        methods = preflight.headers.get("Access-Control-Allow-Methods", "")
        headers = preflight.headers.get("Access-Control-Allow-Headers", "")
        add("CORS preflight behavior", "Informational", f"OPTIONS {preflight.status_code}; methods={methods or '(not supplied)'}; headers={headers or '(not supplied)'}.",
            "This reports browser preflight policy; allowed methods alone do not establish a vulnerability.", "Limit methods and request headers to those the application needs.", "High")
    return out
