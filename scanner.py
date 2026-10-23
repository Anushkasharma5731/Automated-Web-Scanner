"""Scan orchestration for an explicitly authorized single URL; no crawling."""
from __future__ import annotations
import logging, time
from datetime import datetime, timezone
from dataclasses import asdict
from urllib.parse import urlsplit
from security import request_with_redirects, validate_url
from header_checks import analyze_headers
from cors_checks import analyze_cors, TEST_ORIGIN, NULL_ORIGIN

logger = logging.getLogger("web_scanner")

def run_scan(target_url: str) -> dict:
    """Scan one target using at most four request sequences, with validated redirects."""
    target = validate_url(target_url)
    started = time.monotonic()
    timestamp = datetime.now(timezone.utc).isoformat()
    errors = []
    checks = ["six security response headers", "CORS Origin policy", "null Origin policy", "OPTIONS preflight"]
    try:
        baseline, _ = request_with_redirects(target)
        origin, origin_chain = request_with_redirects(target, origin=TEST_ORIGIN)
        null, _ = request_with_redirects(target, origin=NULL_ORIGIN)
        preflight, _ = request_with_redirects(target, origin=TEST_ORIGIN, method="OPTIONS")
        findings = analyze_headers(baseline.headers, baseline.url) + analyze_cors(baseline, origin, null, preflight)
        result = {
            "target_url": target, "scan_timestamp": timestamp, "final_url": baseline.url,
            "status_code": baseline.status_code, "duration_seconds": round(time.monotonic()-started, 3),
            "checks_performed": checks, "findings": [asdict(item) for item in findings], "errors": errors,
            "response_headers": {k: v[:300] for k,v in baseline.headers.items() if k.lower() in {
                "content-security-policy", "strict-transport-security", "x-content-type-options", "x-frame-options",
                "referrer-policy", "permissions-policy", "access-control-allow-origin", "vary"}},
            "redirect_chain": origin_chain,
        }
        result["summary"] = summarize(findings)
        logger.info("Scan complete target=%s status=%s findings=%s", target, baseline.status_code, len(findings))
        return result
    except Exception as exc:
        # Error text is deliberately bounded; requests exceptions may contain URLs but no credentials are accepted.
        logger.warning("Scan failed target=%s error=%s", target, type(exc).__name__)
        raise

def summarize(findings: list) -> dict:
    counts = {s: 0 for s in ("Critical", "High", "Medium", "Low", "Informational")}
    for item in findings:
        severity = item.severity if hasattr(item, "severity") else item.get("severity", "Informational")
        counts[severity] = counts.get(severity, 0) + 1
    if counts["Critical"] or counts["High"]: assessment = "Immediate review recommended"
    elif counts["Medium"]: assessment = "Review prioritized configuration findings"
    else: assessment = "No high-impact issue was confirmed by these checks"
    return {"by_severity": counts, "overall_assessment": assessment, "total_findings": len(findings)}

def main() -> int:
    """CLI entry point: scan one explicitly authorized URL and save both reports."""
    import argparse
    from report_generator import save_reports
    from security import UnsafeTarget
    parser = argparse.ArgumentParser(description="Audit security headers and CORS on an authorized URL.")
    parser.add_argument("url", help="One HTTP(S) URL you own or are authorized to test")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        result = run_scan(args.url)
        json_path, html_path = save_reports(result)
    except (UnsafeTarget, Exception) as exc:
        print(f"Scan failed: {exc}")
        return 2
    print(result["summary"]["overall_assessment"])
    print(f"Findings: {result['summary']['total_findings']}")
    print(f"JSON report: {json_path}\nHTML report: {html_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
