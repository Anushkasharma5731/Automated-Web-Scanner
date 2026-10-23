"""Unique JSON and escaped HTML audit reports."""
from __future__ import annotations
import html, json
from pathlib import Path
from datetime import datetime, timezone
from uuid import uuid4

def save_reports(report: dict, directory: str | Path = "reports") -> tuple[Path, Path]:
    """Write each scan to unique report filenames and return both paths."""
    folder = Path(directory); folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid4().hex[:8]
    jp = folder / f"scan_{stamp}.json"; hp = folder / f"scan_{stamp}.html"
    jp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    hp.write_text(render_html(report), encoding="utf-8")
    return jp, hp

def render_html(report: dict) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    rows = "".join(f"<tr><td>{esc(f.get('severity'))}</td><td>{esc(f.get('name'))}</td><td>{esc(f.get('confidence'))}</td><td>{esc(f.get('evidence'))}</td><td>{esc(f.get('impact'))}</td><td>{esc(f.get('remediation'))}</td></tr>" for f in report.get("findings", []))
    summary = report.get("summary", {})
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Security audit report</title><style>body{{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#182230}}table{{border-collapse:collapse;width:100%;margin-top:1rem}}th,td{{border:1px solid #ccd3dc;padding:.6rem;text-align:left;vertical-align:top}}th{{background:#edf2f7}}code{{overflow-wrap:anywhere}}</style><h1>Web security audit</h1><p>Authorized single URL scan. No crawling or authentication credentials used.</p><dl><dt>Target</dt><dd><code>{esc(report.get('target_url'))}</code></dd><dt>Final URL / status</dt><dd><code>{esc(report.get('final_url'))}</code> / {esc(report.get('status_code'))}</dd><dt>Timestamp</dt><dd>{esc(report.get('scan_timestamp'))}</dd><dt>Duration</dt><dd>{esc(report.get('duration_seconds'))} seconds</dd><dt>Assessment</dt><dd>{esc(summary.get('overall_assessment',''))}</dd></dl><h2>Findings ({esc(summary.get('total_findings',0))})</h2><table><thead><tr><th>Severity</th><th>Finding</th><th>Confidence</th><th>Evidence</th><th>Impact</th><th>Remediation</th></tr></thead><tbody>{rows}</tbody></table><h2>Checks performed</h2><ul>{''.join('<li>'+esc(c)+'</li>' for c in report.get('checks_performed',[]))}</ul><h2>Errors / incomplete checks</h2><ul>{''.join('<li>'+esc(e)+'</li>' for e in report.get('errors',[]))}</ul></html>'''
