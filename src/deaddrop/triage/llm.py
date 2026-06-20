"""LLM summarizer — generate case summaries using Ollama."""


import logging

from deaddrop.core.case import CaseManager

log = logging.getLogger(__name__)


class LLMSummarizer:
    """Generate natural language case summaries using local LLM (Ollama)."""

    def __init__(self, case_manager: CaseManager, ollama_url: str = "http://localhost:11434",
                 model: str = "llama3"):
        self.mgr = case_manager
        self.ollama_url = ollama_url
        self.model = model

    def summarize(self, case_id: str) -> str:
        """Generate a natural language summary of the case."""
        case = self.mgr.get_case(case_id)
        if not case:
            return "Case not found."

        # Collect case data
        evidence = self.mgr.list_evidence(case_id)
        artifacts = self.mgr.list_artifacts(case_id)
        timeline = self.mgr.get_timeline(case_id)
        hunt_results = self.mgr.get_hunt_results(case_id)

        # Build context
        context = self._build_context(case, evidence, artifacts, timeline, hunt_results)

        # Try Ollama; log the failure reason before falling back (H-2: was silent)
        try:
            return self._call_ollama(context)
        except Exception as e:
            log.warning(
                "Ollama LLM summary failed (%s: %s); falling back to rule-based summary",
                type(e).__name__, e,
            )
            return self._generate_rule_summary(case, evidence, artifacts, timeline, hunt_results)

    def _build_context(self, case, evidence, artifacts, timeline, hunt_results) -> str:
        """Build context string for LLM."""
        parts = [
            f"Case: {case.name} (ID: {case.id})",
            f"Analyst: {case.analyst}",
            f"Status: {case.status}",
            f"Created: {case.created_at}",
            "",
            f"Evidence items: {len(evidence)}",
        ]

        for ev in evidence[:10]:
            parts.append(f"  - {ev['filename']} ({ev['type']}/{ev['format']}, {ev['size_bytes']:,} bytes)")

        parts.extend([
            "",
            f"Total artifacts: {len(artifacts)}",
            f"Timeline entries: {len(timeline)}",
            f"Hunt results: {len(hunt_results)}",
        ])

        # Severity breakdown
        severity_counts: dict[str, int] = {}
        for a in artifacts:
            sev = a.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        parts.append(f"Severity breakdown: {severity_counts}")

        # Top high-severity artifacts
        high_artifacts = [a for a in artifacts if a.get("severity") in ("high", "critical")][:10]
        if high_artifacts:
            parts.append("\nHigh/Critical artifacts:")
            for a in high_artifacts:
                parts.append(f"  - [{a['severity'].upper()}] {a['description']}")

        # Hunt hits
        if hunt_results:
            parts.append("\nHunt results:")
            for h in hunt_results[:5]:
                parts.append(f"  - {h['rule_name']} ({h['rule_type']}, {h['severity']})")

        return "\n".join(parts)

    def _call_ollama(self, context: str) -> str:
        """Call Ollama API for summary generation."""
        try:
            import httpx
        except ImportError:
            raise RuntimeError("httpx not installed") from None

        prompt = f"""You are a digital forensics analyst. Based on the following case data, provide a concise professional summary including:
1. Case overview
2. Key findings
3. Risk assessment
4. Recommended next steps

Case Data:
{context}

Provide a clear, professional summary:"""

        response = httpx.post(
            f"{self.ollama_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
            },
            timeout=120,
        )

        if response.status_code == 200:
            data = response.json()
            return str(data.get("response", "No summary generated."))

        return f"Ollama error: {response.status_code}"

    def _generate_rule_summary(self, case, evidence, artifacts, timeline, hunt_results) -> str:
        """Fallback: generate summary using rules (no LLM)."""
        parts = [
            "═══ DEADDROP Case Summary ═══",
            "",
            f"Case: {case.name} ({case.id})",
            f"Analyst: {case.analyst or 'N/A'}",
            f"Created: {case.created_at[:19]}",
            "",
            f"── Evidence: {len(evidence)} items ──",
        ]

        for ev in evidence:
            size_mb = ev['size_bytes'] / (1024 * 1024)
            parts.append(f"  • {ev['filename']} ({ev['format']}, {size_mb:.1f} MB)")

        severity_counts: dict[str, int] = {}
        source_counts: dict[str, int] = {}
        for a in artifacts:
            severity_counts[a.get("severity", "info")] = severity_counts.get(a.get("severity", "info"), 0) + 1
            source_counts[a.get("source", "unknown")] = source_counts.get(a.get("source", "unknown"), 0) + 1

        parts.extend([
            "",
            f"── Artifacts: {len(artifacts)} total ──",
            f"  Severity: {dict(severity_counts)}",
            f"  Sources: {dict(source_counts)}",
            "",
            f"── Timeline: {len(timeline)} entries ──",
            "",
            f"── Hunt Results: {len(hunt_results)} hits ──",
        ])

        for h in hunt_results[:5]:
            parts.append(f"  • {h['rule_name']} [{h['severity'].upper()}]")

        # Risk assessment
        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)
        if critical > 0:
            risk = "CRITICAL — Immediate investigation required"
        elif high > 3:
            risk = "HIGH — Significant indicators of compromise"
        elif high > 0:
            risk = "MEDIUM — Some suspicious activity detected"
        else:
            risk = "LOW — No high-severity findings"

        parts.extend([
            "",
            f"── Risk Assessment: {risk} ──",
            "",
            "── Recommended Actions ──",
        ])

        if critical > 0:
            parts.append("  1. Investigate all critical findings immediately")
            parts.append("  2. Isolate affected systems")
            parts.append("  3. Preserve additional evidence")
        elif high > 0:
            parts.append("  1. Review high-severity artifacts in detail")
            parts.append("  2. Cross-reference with threat intelligence")
            parts.append("  3. Expand timeline analysis")
        else:
            parts.append("  1. Continue standard analysis workflow")
            parts.append("  2. Consider additional evidence sources")

        return "\n".join(parts)
