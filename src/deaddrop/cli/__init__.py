"""DEADDROP CLI — Digital Forensics Toolkit."""

from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from deaddrop.core.config import Config
from deaddrop.core.case import CaseManager

console = Console()


def get_case_manager(config: Config | None = None) -> CaseManager:
    cfg = config or Config.load()
    cfg.ensure_dirs()
    return CaseManager(cfg.db_path)


@click.group()
@click.version_option(version="1.0.0", prog_name="deaddrop")
def cli():
    """DEADDROP — Digital Forensics Toolkit with AI-assisted triage."""
    pass


# ── Case commands ──────────────────────────────────────────────

@cli.group()
def case():
    """Case management."""
    pass


@case.command("create")
@click.option("--name", "-n", required=True, help="Case name")
@click.option("--analyst", "-a", default="", help="Analyst name")
@click.option("--notes", default="", help="Case notes")
def case_create(name: str, analyst: str, notes: str):
    """Create a new forensic case."""
    mgr = get_case_manager()
    c = mgr.create_case(name=name, analyst=analyst, notes=notes)
    console.print(f"[bold green]✓ Case created:[/bold green] {c.id} — {c.name}")
    console.print(f"  Analyst: {c.analyst or '—'}")
    console.print(f"  Created: {c.created_at}")


@case.command("list")
@click.option("--status", "-s", type=click.Choice(["open", "closed", "archived"]), default=None)
def case_list(status: str | None):
    """List all cases."""
    mgr = get_case_manager()
    cases = mgr.list_cases(status)
    if not cases:
        console.print("[yellow]No cases found.[/yellow]")
        return
    table = Table(title="DEADDROP Cases", show_lines=True)
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Analyst")
    table.add_column("Status")
    table.add_column("Created")
    for c in cases:
        table.add_row(c.id, c.name, c.analyst or "—", c.status, c.created_at[:19])
    console.print(table)


@case.command("info")
@click.argument("case_id")
def case_info(case_id: str):
    """Show case details."""
    mgr = get_case_manager()
    c = mgr.get_case(case_id)
    if not c:
        console.print(f"[red]Case {case_id} not found.[/red]")
        return
    evidence = mgr.list_evidence(case_id)
    console.print(f"[bold]Case:[/bold] {c.id} — {c.name}")
    console.print(f"  Analyst:  {c.analyst or '—'}")
    console.print(f"  Status:   {c.status}")
    console.print(f"  Created:  {c.created_at}")
    console.print(f"  Updated:  {c.updated_at}")
    console.print(f"  Notes:    {c.notes or '—'}")
    console.print(f"  Evidence: {len(evidence)} items")
    for ev in evidence:
        console.print(f"    [{ev['id']}] {ev['filename']} ({ev['type']}/{ev['format']}) — {ev['sha256'][:16]}...")


@case.command("close")
@click.argument("case_id")
def case_close(case_id: str):
    """Close a case."""
    mgr = get_case_manager()
    if mgr.close_case(case_id):
        console.print(f"[green]✓ Case {case_id} closed.[/green]")
    else:
        console.print(f"[red]Case {case_id} not found.[/red]")


# ── Ingest commands ────────────────────────────────────────────

@cli.group()
def ingest():
    """Evidence ingestion."""
    pass


@ingest.command("disk")
@click.option("--image", "-i", required=True, help="Path to disk image")
@click.option("--case", "-c", "case_id", required=True, help="Case ID")
def ingest_disk(image: str, case_id: str):
    """Ingest a disk image into a case."""
    from deaddrop.core.evidence import EvidenceManager
    mgr = get_case_manager()
    if not mgr.get_case(case_id):
        console.print(f"[red]Case {case_id} not found.[/red]")
        return
    em = EvidenceManager(mgr)
    try:
        result = em.ingest_disk(case_id, image)
        console.print("[bold green]✓ Disk image ingested[/bold green]")
        console.print(f"  Evidence ID: {result['id']}")
        console.print(f"  File:        {result['filename']}")
        console.print(f"  Format:      {result['format']}")
        console.print(f"  Size:        {result['size_bytes']:,} bytes")
        console.print(f"  SHA-256:     {result['sha256']}")
        console.print(f"  MD5:         {result['md5']}")
        console.print("  Verified:    ✓")
    except FileNotFoundError as e:
        console.print(f"[red]{e}[/red]")


@ingest.command("memory")
@click.option("--dump", "-d", required=True, help="Path to memory dump")
@click.option("--case", "-c", "case_id", required=True, help="Case ID")
def ingest_memory(dump: str, case_id: str):
    """Ingest a memory dump into a case."""
    from deaddrop.core.evidence import EvidenceManager
    mgr = get_case_manager()
    if not mgr.get_case(case_id):
        console.print(f"[red]Case {case_id} not found.[/red]")
        return
    em = EvidenceManager(mgr)
    try:
        result = em.ingest_memory(case_id, dump)
        console.print("[bold green]✓ Memory dump ingested[/bold green]")
        console.print(f"  Evidence ID: {result['id']}")
        console.print(f"  File:        {result['filename']}")
        console.print(f"  Format:      {result['format']}")
        console.print(f"  Size:        {result['size_bytes']:,} bytes")
        console.print(f"  SHA-256:     {result['sha256']}")
        console.print(f"  MD5:         {result['md5']}")
        console.print("  Verified:    ✓")
    except FileNotFoundError as e:
        console.print(f"[red]{e}[/red]")


# ── Analyze commands ───────────────────────────────────────────

@cli.group()
def analyze():
    """Analyze evidence."""
    pass


@analyze.command("filesystem")
@click.option("--case", "-c", "case_id", required=True, help="Case ID")
@click.option("--evidence", "-e", default=None, help="Specific evidence ID")
def analyze_filesystem(case_id: str, evidence: str | None):
    """Analyze filesystem from disk images."""
    from deaddrop.disk.filesystem import FilesystemAnalyzer
    mgr = get_case_manager()
    analyzer = FilesystemAnalyzer(mgr)
    results = analyzer.analyze(case_id, evidence)
    console.print("[bold green]✓ Filesystem analysis complete[/bold green]")
    console.print(f"  Files found:  {results['total_files']}")
    console.print(f"  Deleted:      {results['deleted_files']}")
    console.print(f"  Carved:       {results['carved_files']}")


@analyze.command("registry")
@click.option("--case", "-c", "case_id", required=True, help="Case ID")
@click.option("--evidence", "-e", default=None, help="Specific evidence ID")
def analyze_registry(case_id: str, evidence: str | None):
    """Analyze Windows registry hives."""
    from deaddrop.disk.registry import RegistryAnalyzer
    mgr = get_case_manager()
    analyzer = RegistryAnalyzer(mgr)
    results = analyzer.analyze(case_id, evidence)
    console.print("[bold green]✓ Registry analysis complete[/bold green]")
    console.print(f"  Keys parsed:  {results['keys_parsed']}")
    console.print(f"  Artifacts:    {results['artifacts']}")


@analyze.command("prefetch")
@click.option("--case", "-c", "case_id", required=True, help="Case ID")
@click.option("--evidence", "-e", default=None, help="Specific evidence ID")
def analyze_prefetch(case_id: str, evidence: str | None):
    """Analyze Windows prefetch files."""
    from deaddrop.disk.prefetch import PrefetchAnalyzer
    mgr = get_case_manager()
    analyzer = PrefetchAnalyzer(mgr)
    results = analyzer.analyze(case_id, evidence)
    console.print("[bold green]✓ Prefetch analysis complete[/bold green]")
    console.print(f"  Prefetch files: {results['prefetch_count']}")
    console.print(f"  Executables:    {results['executables']}")


@analyze.command("events")
@click.option("--case", "-c", "case_id", required=True, help="Case ID")
@click.option("--evidence", "-e", default=None, help="Specific evidence ID")
@click.option("--source", "-s", default=None, help="Event source filter")
def analyze_events(case_id: str, evidence: str | None, source: str | None):
    """Analyze Windows event logs."""
    from deaddrop.disk.events import EventLogAnalyzer
    mgr = get_case_manager()
    analyzer = EventLogAnalyzer(mgr)
    results = analyzer.analyze(case_id, evidence, source)
    console.print("[bold green]✓ Event log analysis complete[/bold green]")
    console.print(f"  Events parsed: {results['events_parsed']}")
    console.print(f"  Security:      {results['security_events']}")
    console.print(f"  High severity: {results['high_severity']}")


@analyze.command("memory")
@click.option("--case", "-c", "case_id", required=True, help="Case ID")
@click.option("--evidence", "-e", default=None, help="Specific evidence ID")
@click.option("--plugin", "-p", default="windows.pslist", help="Volatility3 plugin")
def analyze_memory(case_id: str, evidence: str | None, plugin: str):
    """Analyze memory dump via Volatility3."""
    from deaddrop.memory.volatility import VolatilityWrapper
    mgr = get_case_manager()
    wrapper = VolatilityWrapper(mgr)
    results = wrapper.run_plugin(case_id, evidence, plugin)
    console.print("[bold green]✓ Memory analysis complete[/bold green]")
    console.print(f"  Plugin:    {plugin}")
    console.print(f"  Findings:  {results['findings_count']}")


# ── Hunt commands ──────────────────────────────────────────────

@cli.group()
def hunt():
    """Artifact hunting (YARA, IOC)."""
    pass


@hunt.command("run")
@click.option("--case", "-c", "case_id", required=True, help="Case ID")
@click.option("--yara", "-y", "yara_rules", default=None, help="Path to YARA rules file/dir")
@click.option("--ioc", default=None, help="Path to IOC JSON file")
@click.option("--pack", "-p", type=click.Choice(["persistence", "lateral_movement", "exfiltration"]), default=None)
def hunt_run(case_id: str, yara_rules: str | None, ioc: str | None, pack: str | None):
    """Run artifact hunt across evidence."""
    from deaddrop.hunt.yara_scanner import YARAScanner
    from deaddrop.hunt.ioc_matcher import IOCMatcher
    mgr = get_case_manager()
    results = {"yara_hits": 0, "ioc_hits": 0}
    if yara_rules:
        scanner = YARAScanner(mgr)
        r = scanner.scan(case_id, yara_rules)
        results["yara_hits"] = r["hits"]
    if ioc:
        matcher = IOCMatcher(mgr)
        r = matcher.match(case_id, ioc)
        results["ioc_hits"] = r["hits"]
    if pack:
        scanner = YARAScanner(mgr)
        r = scanner.scan_pack(case_id, pack)
        results["yara_hits"] += r["hits"]
    console.print("[bold green]✓ Hunt complete[/bold green]")
    console.print(f"  YARA hits: {results['yara_hits']}")
    console.print(f"  IOC hits:  {results['ioc_hits']}")


# ── Timeline commands ─────────────────────────────────────────

@cli.group()
def timeline():
    """Timeline generation and export."""
    pass


@timeline.command("generate")
@click.option("--case", "-c", "case_id", required=True, help="Case ID")
def timeline_generate(case_id: str):
    """Generate super-timeline from all artifacts."""
    from deaddrop.timeline.engine import TimelineEngine
    mgr = get_case_manager()
    engine = TimelineEngine(mgr)
    results = engine.generate(case_id)
    console.print("[bold green]✓ Timeline generated[/bold green]")
    console.print(f"  Entries: {results['total_entries']}")
    console.print(f"  Sources: {', '.join(results['sources'])}")


@timeline.command("export")
@click.option("--case", "-c", "case_id", required=True, help="Case ID")
@click.option("--format", "-f", "fmt", type=click.Choice(["csv", "json", "body"]), default="csv")
@click.option("--output", "-o", default=None, help="Output file path")
def timeline_export(case_id: str, fmt: str, output: str | None):
    """Export timeline in specified format."""
    from deaddrop.timeline.export import TimelineExporter
    mgr = get_case_manager()
    exporter = TimelineExporter(mgr)
    path = exporter.export(case_id, fmt, output)
    console.print("[bold green]✓ Timeline exported[/bold green]")
    console.print(f"  Format: {fmt}")
    console.print(f"  Path:   {path}")


@timeline.command("filter")
@click.option("--case", "-c", "case_id", required=True, help="Case ID")
@click.option("--from", "from_ts", default=None, help="Start timestamp")
@click.option("--to", "to_ts", default=None, help="End timestamp")
@click.option("--source", "-s", default=None, help="Filter by source")
def timeline_filter(case_id: str, from_ts: str | None, to_ts: str | None, source: str | None):
    """Filter timeline entries."""
    from deaddrop.timeline.engine import TimelineEngine
    mgr = get_case_manager()
    engine = TimelineEngine(mgr)
    entries = engine.filter_entries(case_id, from_ts, to_ts, source)
    console.print(f"[bold]Timeline entries:[/bold] {len(entries)}")
    for entry in entries[:50]:
        console.print(f"  {entry['timestamp']} [{entry['source']}] {entry['description']}")
    if len(entries) > 50:
        console.print(f"  ... and {len(entries) - 50} more")


# ── Triage commands ────────────────────────────────────────────

@cli.group()
def triage():
    """AI-assisted triage."""
    pass


@triage.command("run")
@click.option("--case", "-c", "case_id", required=True, help="Case ID")
def triage_run(case_id: str):
    """Run AI-assisted anomaly scoring."""
    from deaddrop.triage.scorer import TriageScorer
    mgr = get_case_manager()
    scorer = TriageScorer(mgr)
    results = scorer.score(case_id)
    console.print("[bold green]✓ Triage complete[/bold green]")
    console.print(f"  Anomalies: {results['anomalies']}")
    console.print(f"  High:      {results['high']}")
    console.print(f"  Critical:  {results['critical']}")


@triage.command("summary")
@click.option("--case", "-c", "case_id", required=True, help="Case ID")
def triage_summary(case_id: str):
    """Generate LLM case summary."""
    from deaddrop.triage.llm import LLMSummarizer
    mgr = get_case_manager()
    summarizer = LLMSummarizer(mgr)
    summary = summarizer.summarize(case_id)
    console.print("[bold green]✓ Case Summary[/bold green]")
    console.print(summary)


# ── Report commands ────────────────────────────────────────────

@cli.group()
def report():
    """Report generation."""
    pass


@report.command("generate")
@click.option("--case", "-c", "case_id", required=True, help="Case ID")
@click.option("--format", "-f", "fmt", type=click.Choice(["html", "pdf"]), default="html")
@click.option("--output", "-o", default=None, help="Output path")
def report_generate(case_id: str, fmt: str, output: str | None):
    """Generate case report."""
    from deaddrop.report.generator import ReportGenerator
    mgr = get_case_manager()
    gen = ReportGenerator(mgr)
    path = gen.generate(case_id, fmt, output)
    console.print("[bold green]✓ Report generated[/bold green]")
    console.print(f"  Format: {fmt}")
    console.print(f"  Path:   {path}")


# ── Dashboard command ─────────────────────────────────────────

@cli.command("dashboard")
@click.option("--port", "-p", default=8080, help="Port number")
@click.option("--host", "-h", default="0.0.0.0", help="Host")
def dashboard(port: int, host: str):
    """Launch the web dashboard (Fastify API server)."""
    import subprocess
    import os as _os
    server_dir = Path(__file__).parent.parent.parent.parent / "server"
    if not server_dir.exists():
        console.print("[red]Server directory not found. Install the server dependencies first:[/red]")
        console.print("  cd server && npm install")
        return
    # Check if npm is available
    try:
        subprocess.run(["npm", "--version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        console.print("[red]npm not found. Install Node.js to run the dashboard.[/red]")
        return
    # Install deps if needed
    if not (server_dir / "node_modules").exists():
        console.print("[bold]Installing server dependencies...[/bold]")
        subprocess.run(["npm", "install"], cwd=str(server_dir), check=True)
    # Start the server
    console.print(f"[bold]Launching DEADDROP dashboard on {host}:{port}...[/bold]")
    console.print(f"  API:     http://{host}:{port}")
    console.print("  Dashboard: http://localhost:3000 (start separately: cd dashboard && npm run dev)")
    env = {**_os.environ, "HOST": host, "PORT": str(port)}
    subprocess.run(["npx", "tsx", "src/index.ts"], cwd=str(server_dir), env=env)


# ── Plugin commands ───────────────────────────────────────────

@cli.group()
def plugin():
    """Plugin management."""
    pass


@plugin.command("list")
def plugin_list():
    """List available plugins."""
    from deaddrop.plugins.manager import PluginManager
    pm = PluginManager()
    plugins = pm.list_plugins()
    if not plugins:
        console.print("[yellow]No plugins found.[/yellow]")
        return
    table = Table(title="DEADDROP Plugins")
    table.add_column("Name", style="cyan")
    table.add_column("Version")
    table.add_column("Description")
    table.add_column("Hooks")
    for p in plugins:
        table.add_row(p["name"], p.get("version", "—"), p.get("description", "—"), ", ".join(p.get("hooks", [])))
    console.print(table)


@plugin.command("run")
@click.argument("name")
@click.option("--case", "-c", "case_id", required=True, help="Case ID")
def plugin_run(name: str, case_id: str):
    """Run a specific plugin."""
    from deaddrop.plugins.manager import PluginManager
    pm = PluginManager()
    result = pm.run_plugin(name, case_id)
    console.print(f"[bold green]✓ Plugin {name} complete[/bold green]")
    console.print(f"  Result: {result}")


if __name__ == "__main__":
    cli()