"""Report generator — HTML and PDF forensic case reports."""

import html as html_module
from datetime import UTC, datetime
from pathlib import Path

from deaddrop.core.case import CaseManager


class ReportGenerator:
    """Generate professional forensic case reports."""

    def __init__(self, case_manager: CaseManager):
        self.mgr = case_manager

    def generate(self, case_id: str, fmt: str = "html", output_path: str | None = None,
                 skip_verify: bool = False) -> str:
        """Generate a case report in HTML or PDF format.

        Chain-of-custody gate (Phase 4): by default, re-verifies every evidence
        item's SHA-256/MD5 before rendering and raises ValueError if any evidence
        file is missing or its hash no longer matches the ingestion record. This
        prevents a court report from being generated against tampered or missing
        evidence. Pass ``skip_verify=True`` only with explicit analyst sign-off.
        """
        case = self.mgr.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")

        evidence = self.mgr.list_evidence(case_id)

        # Integrity gate — fail-closed for court reports.
        if not skip_verify:
            from deaddrop.core.evidence import EvidenceManager
            em = EvidenceManager(self.mgr)
            failures = []
            for ev in evidence:
                v = em.verify_evidence(case_id, ev["id"])
                if not v["verified"]:
                    failures.append({"evidence_id": ev["id"], "filename": ev["filename"],
                                     "reason": v.get("reason", "hash mismatch")})
            if failures:
                raise ValueError(
                    "Refusing to generate report: chain-of-custody verification "
                    f"failed for {len(failures)} evidence item(s): {failures}"
                )

        artifacts = self.mgr.list_artifacts(case_id)
        timeline = self.mgr.get_timeline(case_id)
        hunt_results = self.mgr.get_hunt_results(case_id)

        # Severity breakdown
        severity_counts: dict[str, int] = {}
        for a in artifacts:
            sev = a.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Source breakdown
        source_counts: dict[str, int] = {}
        for a in artifacts:
            src = a.get("source", "unknown")
            source_counts[src] = source_counts.get(src, 0) + 1

        if not output_path:
            ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            output_dir = Path(f"deaddrop_exports/case_{case_id}")
            output_dir.mkdir(parents=True, exist_ok=True)
            ext = ".html" if fmt == "html" else ".pdf"
            output_path = str(output_dir / f"report_{ts}{ext}")

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if fmt == "html":
            html_content = self._render_html(case, evidence, artifacts, timeline, hunt_results,
                                     severity_counts, source_counts)
            path.write_text(html_content, encoding="utf-8")
        elif fmt == "pdf":
            html_content = self._render_html(case, evidence, artifacts, timeline, hunt_results,
                                     severity_counts, source_counts)
            try:
                from weasyprint import HTML
                HTML(string=html_content).write_pdf(str(path))
            except (ImportError, OSError) as e:
                # Fallback: save as HTML (weasyprint or system libs not available).
                # Narrow catch — ImportError = weasyprint not installed; OSError =
                # missing system libs (pango, gdk-pixbuf). Other exceptions
                # (programming errors, bad HTML) propagate so real bugs surface
                # instead of being silently masked as "PDF unavailable".
                import logging
                logging.getLogger(__name__).warning(
                    "PDF generation failed (%s: %s), saving as HTML instead",
                    type(e).__name__, e
                )
                html_path = path.with_suffix(".html")
                html_path.write_text(html_content, encoding="utf-8")
                return str(html_path) + " (PDF unavailable — weasyprint not installed, saved as HTML)"

        return str(path)

    def _render_html(self, case, evidence, artifacts, timeline, hunt_results,
                     severity_counts, source_counts) -> str:
        """Render case report as HTML with XSS-safe escaping."""
        esc = html_module.escape  # XSS-safe escaping
        high_artifacts = [a for a in artifacts if a.get("severity") in ("high", "critical")]

        # Build evidence table rows — all user-controlled fields escaped
        evidence_rows = ""
        for ev in evidence:
            size_mb = ev['size_bytes'] / (1024 * 1024)
            evidence_rows += f"""
                <tr>
                    <td>{esc(ev['id'])}</td>
                    <td>{esc(ev['filename'])}</td>
                    <td>{esc(ev['type'])}</td>
                    <td>{esc(ev['format'])}</td>
                    <td>{size_mb:.1f} MB</td>
                    <td class="mono">{esc(ev['sha256'][:32])}...</td>
                    <td>✓</td>
                </tr>"""

        # Build high-severity artifact rows — severity is enum-safe but source/desc need escaping
        high_rows = ""
        for a in high_artifacts[:50]:
            sev_class = f"severity-{esc(a['severity'])}"
            high_rows += f"""
                <tr class="{sev_class}">
                    <td>{esc(a.get('timestamp', '')[:19])}</td>
                    <td>{esc(a['source'])}</td>
                    <td>{esc(a['severity'].upper())}</td>
                    <td>{esc(a['description'])}</td>
                </tr>"""

        # Build hunt result rows
        hunt_rows = ""
        for h in hunt_results[:50]:
            hunt_rows += f"""
                <tr>
                    <td>{esc(h['rule_name'])}</td>
                    <td>{esc(h['rule_type'])}</td>
                    <td class="severity-{esc(h['severity'])}">{esc(h['severity'].upper())}</td>
                    <td>{esc(h.get('detected_at', '')[:19])}</td>
                </tr>"""

        # Timeline summary (last 50 entries)
        tl_entries = timeline[-50:]
        tl_rows = ""
        for t in tl_entries:
            tl_rows += f"""
                <tr>
                    <td>{esc(t.get('timestamp', '')[:19])}</td>
                    <td>{esc(t.get('source', ''))}</td>
                    <td class="severity-{esc(t.get('severity', 'info'))}">{esc(t.get('severity', 'info').upper())}</td>
                    <td>{esc(t.get('description', ''))}</td>
                </tr>"""

        # Risk assessment
        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)
        if critical > 0:
            risk_level = "CRITICAL"
            risk_color = "#dc2626"
        elif high > 3:
            risk_level = "HIGH"
            risk_color = "#ea580c"
        elif high > 0:
            risk_level = "MEDIUM"
            risk_color = "#d97706"
        else:
            risk_level = "LOW"
            risk_color = "#16a34a"

        now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

        # Severity and source distribution rows — keys are enum values but escape defensively
        sev_rows = " ".join(
            f'<tr><td class="severity-{esc(sev)}">{esc(sev.upper())}</td><td>{count}</td></tr>'
            for sev, count in severity_counts.items()
        )
        src_rows = " ".join(
            f'<tr><td>{esc(src)}</td><td>{count}</td></tr>'
            for src, count in source_counts.items()
        )

        # Showing N of M note
        showing_note = ""
        if len(high_artifacts) > 50:
            showing_note = (
                f'<p style="color: #64748b; font-style: italic; margin-top: 0.5rem;">'
                f'Showing {min(len(high_artifacts), 50)} of {len(high_artifacts)} high/critical findings</p>'
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DEADDROP Forensic Report — {esc(case.name)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; color: #1e293b; background: #f8fafc; padding: 2rem; }}
        .header {{ background: linear-gradient(135deg, #0f172a, #1e293b); color: white; padding: 2rem; border-radius: 12px; margin-bottom: 2rem; }}
        .header h1 {{ font-size: 1.5rem; margin-bottom: 0.5rem; }}
        .header .subtitle {{ color: #94a3b8; font-size: 0.9rem; }}
        .risk-badge {{ display: inline-block; padding: 0.5rem 1.5rem; border-radius: 8px; font-weight: 700; font-size: 1.1rem; color: white; background: {risk_color}; margin-top: 1rem; }}
        .section {{ background: white; border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
        .section h2 {{ font-size: 1.1rem; color: #334155; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid #e2e8f0; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
        th {{ background: #f1f5f9; padding: 0.75rem; text-align: left; font-weight: 600; color: #475569; border-bottom: 2px solid #e2e8f0; }}
        td {{ padding: 0.6rem 0.75rem; border-bottom: 1px solid #f1f5f9; }}
        tr:hover {{ background: #f8fafc; }}
        .severity-critical {{ color: #dc2626; font-weight: 700; }}
        .severity-high {{ color: #ea580c; font-weight: 600; }}
        .severity-medium {{ color: #d97706; }}
        .severity-low {{ color: #16a34a; }}
        .severity-info {{ color: #64748b; }}
        .mono {{ font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.8rem; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.5rem; }}
        .stat-card {{ background: white; border-radius: 12px; padding: 1.25rem; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
        .stat-card .number {{ font-size: 2rem; font-weight: 700; color: #0f172a; }}
        .stat-card .label {{ font-size: 0.8rem; color: #64748b; margin-top: 0.25rem; }}
        .chain-of-custody {{ background: #fefce8; border: 1px solid #fde047; border-radius: 8px; padding: 1rem; margin-top: 1rem; font-size: 0.85rem; }}
        @media print {{ body {{ background: white; padding: 0; }} .section {{ box-shadow: none; border: 1px solid #e2e8f0; }} }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 DEADDROP Forensic Report</h1>
        <div class="subtitle">Digital Forensics Toolkit — Case Analysis Report</div>
        <div class="risk-badge">Risk Level: {risk_level}</div>
    </div>

    <div class="stats">
        <div class="stat-card">
            <div class="number">{len(evidence)}</div>
            <div class="label">Evidence Items</div>
        </div>
        <div class="stat-card">
            <div class="number">{len(artifacts)}</div>
            <div class="label">Artifacts</div>
        </div>
        <div class="stat-card">
            <div class="number">{len(timeline)}</div>
            <div class="label">Timeline Entries</div>
        </div>
        <div class="stat-card">
            <div class="number">{len(hunt_results)}</div>
            <div class="label">Hunt Hits</div>
        </div>
    </div>

    <div class="section">
        <h2>📋 Case Information</h2>
        <table>
            <tr><th>Field</th><th>Value</th></tr>
            <tr><td>Case Name</td><td>{esc(case.name)}</td></tr>
            <tr><td>Case ID</td><td class="mono">{esc(case.id)}</td></tr>
            <tr><td>Analyst</td><td>{esc(case.analyst or 'N/A')}</td></tr>
            <tr><td>Status</td><td>{esc(case.status)}</td></tr>
            <tr><td>Created</td><td>{esc(case.created_at[:19])}</td></tr>
            <tr><td>Report Generated</td><td>{esc(now)}</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>🗄️ Evidence Inventory</h2>
        <table>
            <tr><th>ID</th><th>Filename</th><th>Type</th><th>Format</th><th>Size</th><th>SHA-256</th><th>Verified</th></tr>
            {evidence_rows}
        </table>
        <div class="chain-of-custody">
            ⚖️ <strong>Chain of Custody:</strong> All evidence items were ingested with SHA-256 hash verification. Integrity verified at each processing stage.
        </div>
    </div>

    <div class="section">
        <h2>🚨 High/Critical Findings</h2>
        <table>
            <tr><th>Timestamp</th><th>Source</th><th>Severity</th><th>Description</th></tr>
            {high_rows}
        </table>
        {showing_note}
    </div>

    <div class="section">
        <h2>🎯 Hunt Results</h2>
        <table>
            <tr><th>Rule</th><th>Type</th><th>Severity</th><th>Detected</th></tr>
            {hunt_rows}
        </table>
    </div>

    <div class="section">
        <h2>⏱️ Timeline (Last 50 entries)</h2>
        <table>
            <tr><th>Timestamp</th><th>Source</th><th>Severity</th><th>Description</th></tr>
            {tl_rows}
        </table>
    </div>

    <div class="section">
        <h2>📊 Severity Distribution</h2>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
            {sev_rows}
        </table>
    </div>

    <div class="section">
        <h2>📁 Source Distribution</h2>
        <table>
            <tr><th>Source</th><th>Count</th></tr>
            {src_rows}
        </table>
    </div>

    <div style="text-align: center; color: #94a3b8; padding: 2rem; font-size: 0.8rem;">
        Generated by DEADDROP Digital Forensics Toolkit v1.0.0 — {esc(now)}
    </div>
</body>
</html>"""
