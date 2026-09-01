"""sentinel CLI — Code review that proves it's right."""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from sentinel import __version__, scan_directory, scan_file

app = typer.Typer(
    name="sentinel",
    help="Code review that proves it's right — verify-first analysis with evidence",
    add_completion=False,
)
console = Console()


@app.command()
def scan(
    target: Path = typer.Argument(..., help="Directory or file to scan"),
    output: Path = typer.Option(None, "--output", "-o", help="Output JSON file"),
    format: str = typer.Option(
        "terminal", "--format", "-f",
        help="Output format: terminal, json, html, sarif",
    ),
    framework: str = typer.Option(
        None, "--framework", help="Compliance framework: hipaa, soc2, gdpr, pci, sox"
    ),
    fail_on: str = typer.Option(
        None, "--fail-on", help="Exit with error if findings at this severity: error, warning, info"
    ),
    ai: bool = typer.Option(
        False, "--ai", help="Enable AI-powered fix suggestions (requires SENTINEL_LLM_API_KEY)"
    ),
    deep: bool = typer.Option(
        False, "--deep", help="Enable attacker-first forward analysis (5 hard gates)"
    ),
    sweep: bool = typer.Option(
        False, "--sweep", help="Enable sweep verification (find all instances of patterns)"
    ),
    verify: bool = typer.Option(
        False, "--verify", help="Enable fix verification with 5-gate check"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Scan Python code for bugs, security issues, and compliance violations."""
    if not target.exists():
        console.print(f"[red]Error:[/red] {target} does not exist")
        raise typer.Exit(1)

    if format == "terminal":
        console.print(f"[bold blue]Sentinel[/bold blue] scanning {target}")

    report = scan_directory(str(target)) if target.is_dir() else scan_file(
        str(target), target.read_text(encoding="utf-8", errors="replace")
    )

    # Collect additional findings to add (PyO3 Vec returns copies on access)
    additional_findings: dict[str, list] = {}  # filepath -> list of findings

    # AI-powered fix suggestions
    if ai:
        from sentinel.llm_fix import get_fix_engine

        engine = get_fix_engine()

        for fr in report.file_reports:
            try:
                source = Path(fr.path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for finding in fr.findings:
                finding_dict = {
                    "rule": finding.rule,
                    "message": finding.message,
                    "line": finding.line,
                    "suggestion": finding.suggestion,
                }
                ai_fix = engine.generate_fix(source, finding_dict)
                if ai_fix:
                    if fr.path not in additional_findings:
                        additional_findings[fr.path] = []
                    additional_findings[fr.path].append({
                        "id": finding.id,
                        "rule": finding.rule,
                        "severity": finding.severity,
                        "category": finding.category,
                        "file": finding.file,
                        "line": finding.line,
                        "column": finding.column,
                        "message": finding.message,
                        "suggestion": f"[AI] {ai_fix}",
                        "confidence": finding.confidence,
                    })

    # Attacker-first forward analysis (VulnHunter pattern)
    if deep:
        from sentinel.forward_analysis import analyze_source

        for fr in report.file_reports:
            try:
                source = Path(fr.path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            candidates = analyze_source(fr.path, source)
            for c in candidates:
                if c.passed_all_gates and c.confidence >= 0.6:
                    from sentinel._core import Category, Severity

                    sev = {"error": Severity.Error, "warning": Severity.Warning}.get(
                        c.severity, Severity.Info
                    )
                    if fr.path not in additional_findings:
                        additional_findings[fr.path] = []
                    additional_findings[fr.path].append({
                        "id": f"deep-{c.entry.name}-{c.sink.name}",
                        "rule": f"deep-{c.sink.sink_type.value}",
                        "severity": sev,
                        "category": Category.Security,
                        "file": c.entry.file,
                        "line": c.entry.line,
                        "column": 0,
                        "message": (
                            f"Attacker-controlled input '{c.entry.name}' "
                            f"({c.entry.entry_type.value}) flows to dangerous sink "
                            f"({c.sink.sink_type.value}) [confidence: {c.confidence:.0%}]"
                        ),
                        "suggestion": c.sink.description or "Review and sanitize input",
                        "confidence": c.confidence,
                    })

    # Sweep verification (VulnHunter Phase 3d)
    if sweep:
        from sentinel.sweep import generate_sweep_summary, sweep_all_patterns

        for fr in report.file_reports:
            try:
                source = Path(fr.path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            reports = sweep_all_patterns(source, fr.path)
            summary = generate_sweep_summary(reports)

            for pattern_key, info in summary.get("patterns_found", {}).items():
                if info["count"] > 0:
                    if fr.path not in additional_findings:
                        additional_findings[fr.path] = []
                    from sentinel._core import Category, Severity
                    additional_findings[fr.path].append({
                        "id": f"sweep-{pattern_key}-{fr.path}",
                        "rule": f"sweep-{pattern_key}",
                        "severity": Severity.Warning,
                        "category": Category.Security,
                        "file": fr.path,
                        "line": 0,
                        "column": 0,
                        "message": (
                            f"Sweep found {info['count']} instance(s) of "
                            f"{info['description']}"
                        ),
                        "suggestion": info.get("fix", "Review and fix"),
                        "confidence": 0.8,
                    })

    # Print additional findings (deep/sweep/AI) if any
    if additional_findings and format == "terminal":
        from rich.table import Table as RichTable

        table = RichTable(
            title="Additional Findings (Deep/Sweep Analysis)",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("File", max_width=40)
        table.add_column("Rule", width=25)
        table.add_column("Message", max_width=55)
        for filepath, findings in additional_findings.items():
            for f in findings:
                table.add_row(
                    filepath.split("/")[-1],
                    f["rule"],
                    f["message"][:55],
                )
        console.print(table)

    # Fix verification with counterevidence (Strix pattern)
    if verify and format == "terminal":
        from rich.table import Table as RichTable

        from sentinel.counterevidence import (
            generate_counterevidence,
            should_adjust_finding,
        )
        from sentinel.fix_verification import generate_fix_suggestion, verify_fix

        verify_table = RichTable(
            title="Fix Verification (5-Gate Check)",
            show_header=True,
            header_style="bold green",
        )
        verify_table.add_column("Rule", width=20)
        verify_table.add_column("Line", width=6)
        verify_table.add_column("Gates", width=10)
        verify_table.add_column("Confidence", width=10)
        verify_table.add_column("Counterevidence", max_width=40)

        for fr in report.file_reports:
            try:
                source = Path(fr.path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for finding in fr.findings:
                if not finding.line:
                    continue

                fix = generate_fix_suggestion(source, finding.rule, finding.line)
                if not fix:
                    continue

                # Create fixed source
                lines = source.splitlines()
                if finding.line <= len(lines):
                    lines[finding.line - 1] = fix["fix_after"]
                fixed_source = "\n".join(lines)

                verification = verify_fix(
                    source, fixed_source, finding.rule, finding.line
                )

                ce = generate_counterevidence(
                    source, finding.rule, finding.line, finding.confidence
                )
                new_conf, _ = should_adjust_finding(ce, finding.confidence)

                passed = verification.overall_passed
                gates_str = f"{sum(1 for g in verification.gates if g.passed)}/5"

                verify_table.add_row(
                    finding.rule,
                    str(finding.line),
                    f"[green]{gates_str}[/green]" if passed else f"[red]{gates_str}[/red]",
                    f"{new_conf:.0%}",
                    ce.argument[:40],
                )

        console.print(verify_table)

    if format == "json":
        _output_json(report, output)
    elif format == "html":
        _output_html(report, output)
    elif format == "sarif":
        _output_sarif(report, output)
    else:
        _output_terminal(report)

        if report.summary.total_findings == 0:
            console.print("\n[green]No issues found![/green]")
        else:
            errs = report.summary.by_severity.get("error", 0)
            warns = report.summary.by_severity.get("warning", 0)
            infos = report.summary.by_severity.get("info", 0)
            console.print(
                f"\n[bold]Summary:[/bold] {errs} errors, {warns} warnings, {infos} info"
            )
            console.print(
                f"[bold]Compliance score:[/bold] {report.summary.compliance_score}%"
            )

    # Exit with error if findings exceed threshold
    if fail_on:
        severity_levels = {"error": 3, "warning": 2, "info": 1}
        threshold = severity_levels.get(fail_on.lower(), 0)
        if threshold > 0:
            for sev, count in report.summary.by_severity.items():
                if severity_levels.get(sev, 0) >= threshold and count > 0:
                    raise typer.Exit(1)


@app.command()
def rules() -> None:
    """List all available analysis rules."""
    table = Table(title="Sentinel Rules", show_header=True, header_style="bold cyan")
    table.add_column("Rule", style="bold")
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("Description")

    all_rules = [
        ("sql-injection", "Security", "Error", "SQL query built with f-string (CWE-89)"),
        ("subprocess-shell-true", "Security", "Error", "subprocess with shell=True (CWE-78)"),
        ("use-of-eval", "Security", "Error", "Use of eval() (CWE-95)"),
        ("use-of-exec", "Security", "Error", "Use of exec() (CWE-95)"),
        ("hardcoded-secret", "Security", "Error", "Hardcoded secret (CWE-798)"),
        ("unsafe-deserialization", "Security", "Error", "pickle.load() (CWE-502)"),
        ("jwt-none-algorithm", "Security", "Error", "JWT none algorithm (CWE-347)"),
        ("jwt-verification-disabled", "Security", "Error", "JWT verification disabled (CWE-345)"),
        ("insecure-random", "Security", "Warning", "random for security values (CWE-330)"),
        ("path-traversal", "Security", "Warning", "User-controlled file path (CWE-22)"),
        ("debug-statement", "Security", "Warning", "Debug statement left in code"),
        ("unsafe-yaml-load", "Security", "Warning", "yaml.load() without SafeLoader"),
        ("potential-ssrf", "Security", "Warning", "HTTP request with user URL (OWASP A10)"),
        ("nosql-injection", "Security", "Warning", "NoSQL operator in user input (OWASP API8)"),
        ("unclosed-resource", "Correctness", "Warning", "File without context manager"),
        ("mutable-default-argument", "Correctness", "Warning", "Mutable default argument"),
        ("bare-except", "Correctness", "Warning", "Bare except: clause"),
        ("except-pass", "Correctness", "Warning", "Silent exception swallowing"),
        ("return-in-init", "Correctness", "Error", "Return value in __init__"),
        ("comparison-to-none", "Correctness", "Info", "== None instead of is None"),
        ("unreachable-code", "Correctness", "Warning", "Code after return/raise"),
        ("hipaa-*", "Compliance", "Warning", "HIPAA data access concerns (45 CFR 164)"),
        ("soc2-*", "Compliance", "Warning", "SOC2 audit logging gaps (CC1-CC9)"),
        ("gdpr-*", "Compliance", "Warning", "GDPR PII exposure (EU 2016/679)"),
        ("pci-*", "Compliance", "Error", "PCI DSS violations (Req 1-12)"),
        ("sox-*", "Compliance", "Error", "SOX financial control gaps (Sec 404)"),
        ("excessive-noqa", "Anti-Cheat", "Warning", "Excessive noqa comments"),
        ("excessive-type-ignore", "Anti-Cheat", "Info", "Excessive type:ignore"),
        ("dynamic-import", "Anti-Cheat", "Info", "Dynamic import detection"),
        ("string-concat-obfuscation", "Anti-Cheat", "Info", "String obfuscation"),
        ("conditional-linter-suppression", "Anti-Cheat", "Warning", "Platform-conditional suppression"),
        ("prompt-injection", "AI/ML Security", "Error", "User input in LLM prompt (OWASP LLM01)"),
        ("llm-output-eval", "AI/ML Security", "Error", "eval/exec on LLM output (OWASP LLM05)"),
        ("llm-output-subprocess", "AI/ML Security", "Error", "subprocess with LLM output (OWASP LLM05)"),
        ("mcp-tool-injection", "AI/ML Security", "Error", "MCP tool description injection"),
        ("mcp-dynamic-modification", "AI/ML Security", "Warning", "Dynamic tool modification"),
        ("trust-remote-code", "AI/ML Security", "Error", "trust_remote_code=True (OWASP LLM03)"),
        ("insecure-model-loading", "AI/ML Security", "Error", "Pickle model loading (OWASP LLM03)"),
    ]

    for rule, cat, sev, desc in all_rules:
        color = {"Error": "red", "Warning": "yellow", "Info": "blue"}.get(sev, "white")
        table.add_row(rule, cat, f"[{color}]{sev}[/{color}]", desc)

    console.print(table)


@app.command()
def verify(
    report_path: Path = typer.Argument(..., help="Path to report.json"),
) -> None:
    """Verify a report's integrity."""
    import hashlib
    import json

    if not report_path.exists():
        console.print(f"[red]Error:[/red] {report_path} not found")
        raise typer.Exit(1)

    try:
        data = json.loads(report_path.read_text())
    except json.JSONDecodeError as e:
        console.print(f"[red]Invalid JSON:[/red] {e}")
        raise typer.Exit(1)

    # Check required fields
    required = ["target", "timestamp", "file_reports", "summary"]
    missing = [f for f in required if f not in data]
    if missing:
        console.print(f"[red]Missing fields:[/red] {missing}")
        raise typer.Exit(1)

    # Check finding IDs are unique
    ids = set()
    for fr in data.get("file_reports", []):
        for f in fr.get("findings", []):
            fid = f.get("id", "")
            if fid in ids:
                console.print(f"[red]Duplicate ID:[/red] {fid}")
                raise typer.Exit(1)
            ids.add(fid)

    # Check file hashes
    hash_mismatches = 0
    for fr in data.get("file_reports", []):
        path = Path(fr["path"])
        if path.exists():
            content = path.read_bytes()
            current_hash = hashlib.sha256(content).hexdigest()
            stored_hash = fr.get("source_hash", "")
            if stored_hash and stored_hash != current_hash:
                hash_mismatches += 1

    if hash_mismatches:
        console.print(f"[yellow]Warning:[/yellow] {hash_mismatches} file hash mismatches")

    console.print("[green]PASS[/green] Report integrity verified")


def _output_json(report: Any, output: Path | None) -> None:
    import json

    data = json.loads(report.to_json())
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(data, indent=2))
        console.print(f"[green]JSON report[/green] written to {output}")
    else:
        console.print_json(json.dumps(data))


def _output_html(report: Any, output: Path | None) -> None:
    data = __import__("json").loads(report.to_json())
    html = _build_html(report.target, data)
    out_path = output or Path("sentinel-report.html")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html)
    console.print(f"[green]HTML report[/green] written to {out_path}")


def _output_sarif(report: Any, output: Path | None) -> None:
    """Output in SARIF format for GitHub Security tab integration."""
    import json

    data = json.loads(report.to_json())

    rules = []
    results = []
    rule_ids_seen = set()

    for fr in data.get("file_reports", []):
        for f in fr.get("findings", []):
            rule_id = f.get("rule", "unknown")

            # Add rule definition (only once per rule)
            if rule_id not in rule_ids_seen:
                rule_ids_seen.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": f.get("message", rule_id)},
                    "fullDescription": {"text": f.get("message", rule_id)},
                    "helpUri": f"https://github.com/sentinel/sentinel/blob/main/docs/rules/{rule_id}.md",
                    "properties": {
                        "category": f.get("category", "general"),
                    },
                })

            # Map severity to SARIF level
            severity = f.get("severity", "warning")
            sarif_level = {
                "error": "error",
                "warning": "warning",
                "info": "note",
            }.get(severity, "warning")

            result = {
                "ruleId": rule_id,
                "level": sarif_level,
                "message": {"text": f.get("message", "")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": fr.get("path", "")},
                            "region": {
                                "startLine": max(1, f.get("line", 1)),
                                "startColumn": max(1, f.get("column", 1)),
                            },
                        }
                    }
                ],
                "fingerprints": {"sentinel/id": f.get("id", "")},
            }

            # Add evidence as a codeflow if present
            if f.get("evidence"):
                ev = f["evidence"]
                result["properties"] = {
                    "evidence_type": ev.get("proof_type", ""),
                    "reproduction": ev.get("reproduction_code", "")[:500],
                }

            results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sentinel",
                        "version": data.get("tool_version", "0.1.0"),
                        "semanticVersion": data.get("tool_version", "0.1.0"),
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    out_path = output or Path("sentinel-report.sarif")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(sarif, indent=2))
    console.print(f"[green]SARIF report[/green] written to {out_path}")


@app.command()
def init(
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing config"),
) -> None:
    """Initialize sentinel configuration in current directory."""
    config_path = Path("sentinel.toml")
    ignore_path = Path(".sentinelignore")

    if config_path.exists() and not force:
        console.print("[yellow]sentinel.toml already exists[/yellow] (use --force to overwrite)")
        raise typer.Exit(1)

    # Write sentinel.toml
    config_content = """# Sentinel Configuration
# See https://github.com/sentinel/sentinel for documentation

[scan]
exclude_dirs = ["tests", "migrations", ".venv", "__pycache__"]
max_file_size_kb = 500

[severity]
fail_on = "warning"

[compliance]
frameworks = []

[rules]
disabled = []
confidence_threshold = 0.3

[evidence]
enabled = true
"""
    config_path.write_text(config_content)
    console.print("[green]Created[/green] sentinel.toml")

    # Write .sentinelignore
    if not ignore_path.exists():
        ignore_content = """# Sentinel ignore file
__pycache__/
*.py[cod]
.venv/
venv/
.pytest_cache/
.mypy_cache/
.ruff_cache/
"""
        ignore_path.write_text(ignore_content)
        console.print("[green]Created[/green] .sentinelignore")


@app.command()
def version() -> None:
    """Show sentinel version information."""

    console.print(f"[bold]sentinel[/bold] v{__version__}")
    console.print("Rust core: sentinel-core v0.1.0")
    console.print(f"Python: {sys.version.split()[0]}")


def _build_html(target: str, data: dict) -> str:
    """Build premium HTML report following taste-skill design rules."""
    summary = data.get("summary", {})
    file_reports = data.get("file_reports", [])

    findings_html = ""
    for fr in file_reports:
        if not fr.get("findings"):
            continue
        finding_rows = ""
        for f in fr["findings"]:
            evidence_block = ""
            if f.get("evidence"):
                ev = f["evidence"]
                evidence_block = f"""
                <div class="evidence">
                    <div class="evidence-header">Proof ({ev.get('proof_type', 'N/A')})</div>
                    <pre class="evidence-code">{ev.get('reproduction_code', '')}</pre>
                    <div class="evidence-row"><span class="evidence-label">Expected:</span> {ev.get('expected_behavior', '')}</div>
                    <div class="evidence-row"><span class="evidence-label">Actual:</span> {ev.get('actual_behavior', '')}</div>
                </div>"""
            finding_rows += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="badge badge-{f.get('severity', 'info')}">{f.get('severity', 'info').upper()}</span>
                    <span class="finding-rule">{f.get('rule', '')}</span>
                    <span class="finding-line">Line {f.get('line', '-')}</span>
                </div>
                <div class="finding-message">{f.get('message', '')}</div>
                <div class="finding-suggestion">{f.get('suggestion', '')}</div>
                {evidence_block}
            </div>"""

        findings_html += f"""
        <div class="file-section">
            <div class="file-header">
                <span class="file-path">{fr['path']}</span>
                <span class="file-count">{len(fr['findings'])} issue{"s" if len(fr['findings']) != 1 else ""}</span>
            </div>
            {finding_rows}
        </div>"""

    total_errors = summary.get('by_severity', {}).get('error', 0)
    total_warnings = summary.get('by_severity', {}).get('warning', 0)
    total_info = summary.get('by_severity', {}).get('info', 0)
    compliance = summary.get('compliance_score', 100)
    total = summary.get('total_findings', 0)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel — {target}</title>
<style>
  :root {{
    --canvas: #F9FAFB;
    --surface: #FFFFFF;
    --ink: #18181B;
    --secondary: #71717A;
    --muted: #94A3B8;
    --border: rgba(226,232,240,0.5);
    --shadow: rgba(0,0,0,0.05);
    --error: #DC2626;
    --error-bg: #FEF2F2;
    --error-border: rgba(220,38,38,0.15);
    --warning: #D97706;
    --warning-bg: #FFFBEB;
    --warning-border: rgba(217,119,6,0.15);
    --info: #2563EB;
    --info-bg: #EFF6FF;
    --info-border: rgba(37,99,235,0.15);
    --success: #059669;
    --success-bg: #ECFDF5;
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--canvas);
    color: var(--ink);
    line-height: 1.6;
    padding: 3rem 2rem;
    max-width: 1200px;
    margin: 0 auto;
  }}

  .header {{
    margin-bottom: 3rem;
  }}

  .header h1 {{
    font-size: 2.25rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    color: var(--ink);
    margin-bottom: 0.5rem;
  }}

  .header .subtitle {{
    color: var(--secondary);
    font-size: 0.9375rem;
  }}

  .header .meta {{
    display: flex;
    gap: 1.5rem;
    margin-top: 1rem;
    font-size: 0.8125rem;
    color: var(--muted);
    font-family: 'SF Mono', 'JetBrains Mono', monospace;
  }}

  .summary-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin-bottom: 3rem;
  }}

  .summary-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
    text-align: center;
    box-shadow: 0 1px 3px var(--shadow);
    transition: transform 0.15s ease;
  }}

  .summary-card:hover {{
    transform: translateY(-1px);
  }}

  .summary-card .value {{
    font-size: 2.5rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    line-height: 1;
    margin-bottom: 0.25rem;
  }}

  .summary-card .label {{
    font-size: 0.8125rem;
    color: var(--secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 500;
  }}

  .summary-card.error .value {{ color: var(--error); }}
  .summary-card.warning .value {{ color: var(--warning); }}
  .summary-card.info .value {{ color: var(--info); }}
  .summary-card.success .value {{ color: var(--success); }}

  .file-section {{
    margin-bottom: 2rem;
  }}

  .file-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem 1.25rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px 12px 0 0;
    border-bottom: none;
  }}

  .file-path {{
    font-family: 'SF Mono', 'JetBrains Mono', monospace;
    font-size: 0.875rem;
    font-weight: 600;
    color: var(--ink);
  }}

  .file-count {{
    font-size: 0.75rem;
    color: var(--secondary);
    background: var(--canvas);
    padding: 0.25rem 0.75rem;
    border-radius: 999px;
    font-weight: 500;
  }}

  .finding-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    padding: 1.25rem 1.5rem;
    border-bottom: none;
  }}

  .finding-card:last-child {{
    border-bottom: 1px solid var(--border);
    border-radius: 0 0 12px 12px;
  }}

  .finding-header {{
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 0.5rem;
  }}

  .finding-rule {{
    font-family: 'SF Mono', 'JetBrains Mono', monospace;
    font-size: 0.8125rem;
    font-weight: 600;
    color: var(--ink);
  }}

  .finding-line {{
    font-size: 0.75rem;
    color: var(--muted);
    margin-left: auto;
    font-family: 'SF Mono', 'JetBrains Mono', monospace;
  }}

  .finding-message {{
    font-size: 0.9375rem;
    color: var(--ink);
    margin-bottom: 0.5rem;
    line-height: 1.5;
  }}

  .finding-suggestion {{
    font-size: 0.8125rem;
    color: var(--success);
    padding: 0.5rem 0.75rem;
    background: var(--success-bg);
    border-radius: 6px;
    border-left: 3px solid var(--success);
  }}

  .badge {{
    display: inline-flex;
    align-items: center;
    padding: 0.2rem 0.6rem;
    border-radius: 6px;
    font-size: 0.6875rem;
    font-weight: 700;
    letter-spacing: 0.03em;
    text-transform: uppercase;
    flex-shrink: 0;
  }}

  .badge-error {{ background: var(--error-bg); color: var(--error); border: 1px solid var(--error-border); }}
  .badge-warning {{ background: var(--warning-bg); color: var(--warning); border: 1px solid var(--warning-border); }}
  .badge-info {{ background: var(--info-bg); color: var(--info); border: 1px solid var(--info-border); }}

  .evidence {{
    margin-top: 0.75rem;
    background: var(--canvas);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }}

  .evidence-header {{
    padding: 0.5rem 0.75rem;
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--secondary);
    text-transform: uppercase;
    letter-spacing: 0.03em;
    border-bottom: 1px solid var(--border);
  }}

  .evidence-code {{
    padding: 0.75rem;
    font-family: 'SF Mono', 'JetBrains Mono', monospace;
    font-size: 0.8125rem;
    line-height: 1.5;
    overflow-x: auto;
    white-space: pre;
    color: var(--ink);
    margin: 0;
  }}

  .evidence-row {{
    padding: 0.375rem 0.75rem;
    font-size: 0.8125rem;
    color: var(--secondary);
    border-top: 1px solid var(--border);
  }}

  .evidence-label {{
    font-weight: 600;
    color: var(--ink);
  }}

  .empty-state {{
    text-align: center;
    padding: 4rem 2rem;
    color: var(--secondary);
  }}

  .empty-state .icon {{
    font-size: 3rem;
    margin-bottom: 1rem;
    opacity: 0.5;
  }}

  .footer {{
    margin-top: 4rem;
    padding-top: 2rem;
    border-top: 1px solid var(--border);
    text-align: center;
    font-size: 0.8125rem;
    color: var(--muted);
  }}

  @media (max-width: 768px) {{
    body {{ padding: 1.5rem 1rem; }}
    .summary-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .header h1 {{ font-size: 1.75rem; }}
  }}

  @media (prefers-color-scheme: dark) {{
    :root {{
      --canvas: #0A0A0A;
      --surface: #18181B;
      --ink: #FAFAFA;
      --secondary: #A1A1AA;
      --muted: #71717A;
      --border: rgba(63,63,70,0.5);
      --shadow: rgba(0,0,0,0.3);
      --error-bg: rgba(220,38,38,0.1);
      --error-border: rgba(220,38,38,0.2);
      --warning-bg: rgba(217,119,6,0.1);
      --warning-border: rgba(217,119,6,0.2);
      --info-bg: rgba(37,99,235,0.1);
      --info-border: rgba(37,99,235,0.2);
      --success-bg: rgba(5,150,105,0.1);
    }}
  }}
</style>
</head>
<body>
  <div class="header">
    <h1>Sentinel</h1>
    <div class="subtitle">Code review that proves it's right</div>
    <div class="meta">
      <span>{target}</span>
      <span>{data.get('timestamp', '')[:10]}</span>
      <span>v{data.get('tool_version', '0.1.0')}</span>
    </div>
  </div>

  <div class="summary-grid">
    <div class="summary-card">
      <div class="value">{summary.get('total_files', 0)}</div>
      <div class="label">Files Scanned</div>
    </div>
    <div class="summary-card error">
      <div class="value">{total_errors}</div>
      <div class="label">Errors</div>
    </div>
    <div class="summary-card warning">
      <div class="value">{total_warnings}</div>
      <div class="label">Warnings</div>
    </div>
    <div class="summary-card success">
      <div class="value">{compliance}%</div>
      <div class="label">Compliance</div>
    </div>
  </div>

  {f'<h2 style="font-size:1.5rem;font-weight:600;margin-bottom:1.5rem;letter-spacing:-0.01em;">Findings</h2>{findings_html}' if findings_html else '<div class="empty-state"><div class="icon">&#10003;</div><div>No issues found</div></div>'}

  <div class="footer">
    Generated by Sentinel v{data.get('tool_version', '0.1.0')} &middot; {total} finding{"s" if total != 1 else ""} across {summary.get('total_files', 0)} files
  </div>
</body>
</html>"""


def _output_terminal(report: Any) -> None:
    from rich.table import Table as RichTable

    summary = report.summary

    table = RichTable(title="Scan Summary", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    table.add_row("Files scanned", str(summary.total_files))
    table.add_row("Files with issues", str(summary.files_with_findings))
    table.add_row("Total findings", str(summary.total_findings))
    for sev, count in sorted(summary.by_severity.items()):
        color = {"error": "red", "warning": "yellow", "info": "blue"}.get(sev, "white")
        table.add_row(f"  {sev.capitalize()}", f"[{color}]{count}[/{color}]")
    table.add_row("Compliance", f"{summary.compliance_score}%")
    console.print(table)

    # Show findings by file
    for fr in report.file_reports:
        if not fr.findings:
            continue
        file_table = RichTable(
            title=f"[dim]{fr.path}[/dim] ({len(fr.findings)} issues)",
            show_header=True,
        )
        file_table.add_column("Line", width=6)
        file_table.add_column("Severity", width=10)
        file_table.add_column("Rule", width=25)
        file_table.add_column("Message", max_width=50)
        for f in fr.findings[:20]:
            color = {
                "error": "red",
                "warning": "yellow",
                "info": "blue",
            }.get(str(f.severity), "white")
            file_table.add_row(
                str(f.line) if f.line else "-",
                f"[{color}]{f.severity}[/{color}]",
                f.rule or "-",
                f.message[:50],
            )
        if len(fr.findings) > 20:
            file_table.add_row("...", "...", "...", f"[dim]{len(fr.findings) - 20} more[/dim]")
        console.print(file_table)
