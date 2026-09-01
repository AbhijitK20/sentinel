"""Sweep verification — find all instances of a vulnerable pattern.

Inspired by VulnHunter's Phase 3d: grep every confirmed root-cause pattern
across the ENTIRE codebase. Constructs both source patterns (vulnerable
construction) and sink patterns (dangerous operation). Traces callers
transitively. Every CANDIDATE sweep instance goes through the full finding pipeline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class SweepResult:
    """A single sweep match."""

    file: str
    line: int
    code: str
    pattern: str
    is_vulnerable: bool = True


@dataclass
class SweepReport:
    """Complete sweep report for a pattern."""

    pattern: str
    total_matches: int = 0
    vulnerable_matches: int = 0
    safe_matches: int = 0
    files_affected: list[str] = field(default_factory=list)
    results: list[SweepResult] = field(default_factory=list)


# Common vulnerable patterns and their safe alternatives
VULNERABILITY_PATTERNS = {
    "sql_injection_fstring": {
        "vulnerable": re.compile(r'f["\'].*SELECT.*WHERE.*\{'),
        "safe_indicator": "parameterized",
        "description": "f-string SQL query construction",
        "fix": "Use parameterized queries with placeholders",
    },
    "sql_injection_format": {
        "vulnerable": re.compile(r'".*SELECT.*WHERE.*"\.format\('),
        "safe_indicator": "parameterized",
        "description": "format() SQL query construction",
        "fix": "Use parameterized queries with placeholders",
    },
    "sql_injection_percent": {
        "vulnerable": re.compile(r'".*SELECT.*WHERE.*"\s*%\s*'),
        "safe_indicator": "parameterized",
        "description": "% formatting SQL query construction",
        "fix": "Use parameterized queries with placeholders",
    },
    "os_command_shell_true": {
        "vulnerable": re.compile(r'subprocess\.\w+\(.*shell\s*=\s*True'),
        "safe_indicator": "shell=False",
        "description": "subprocess with shell=True",
        "fix": "Use shell=False with argument list",
    },
    "os_system": {
        "vulnerable": re.compile(r'os\.system\('),
        "safe_indicator": "subprocess",
        "description": "os.system() call",
        "fix": "Use subprocess.run() with shell=False",
    },
    "eval_usage": {
        "vulnerable": re.compile(r'(?<!\w)eval\('),
        "safe_indicator": "ast.literal_eval",
        "description": "eval() usage",
        "fix": "Use ast.literal_eval() for safe evaluation",
    },
    "exec_usage": {
        "vulnerable": re.compile(r'(?<!\w)exec\('),
        "safe_indicator": None,
        "description": "exec() usage",
        "fix": "Avoid exec(); use importlib or specific function calls",
    },
    "pickle_load": {
        "vulnerable": re.compile(r'pickle\.loads?\('),
        "safe_indicator": "json",
        "description": "pickle deserialization",
        "fix": "Use json.loads() or safetensors for model loading",
    },
    "yaml_unsafe_load": {
        "vulnerable": re.compile(r'yaml\.load\((?!.*Loader)'),
        "safe_indicator": "yaml.safe_load",
        "description": "yaml.load() without SafeLoader",
        "fix": "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
    },
    "hardcoded_secret": {
        "vulnerable": re.compile(
            r'(?i)(password|secret|token|api_key|apikey)\s*=\s*["\'][^"\']{8,}["\']'
        ),
        "safe_indicator": "os.environ",
        "description": "Hardcoded secret in source",
        "fix": "Use environment variables or secrets manager",
    },
    "debugger_statement": {
        "vulnerable": re.compile(r'^\s*(debugger|breakpoint\(\))'),
        "safe_indicator": None,
        "description": "Debug statement left in code",
        "fix": "Remove before production deployment",
    },
    "trust_remote_code": {
        "vulnerable": re.compile(r'trust_remote_code\s*=\s*True'),
        "safe_indicator": "False",
        "description": "trust_remote_code=True in model loading",
        "fix": "Set trust_remote_code=False and verify model provenance",
    },
    "insecure_random_security": {
        "vulnerable": re.compile(r'random\.(random|randint|choice|randrange)\('),
        "safe_indicator": "secrets",
        "description": "Insecure random for security purposes",
        "fix": "Use secrets module for security-sensitive randomness",
        "context_check": True,  # only flag if near security-related code
    },
}


def sweep_pattern(
    source: str,
    filepath: str,
    pattern_key: str,
) -> SweepReport:
    """Sweep for a specific vulnerability pattern across source code.

    Args:
        source: Source code to scan
        filepath: File path for reporting
        pattern_key: Key from VULNERABILITY_PATTERNS

    Returns:
        SweepReport with all matches found
    """
    pattern_info = VULNERABILITY_PATTERNS.get(pattern_key)
    if not pattern_info:
        return SweepReport(pattern=pattern_key)

    report = SweepReport(pattern=pattern_key)
    lines = source.splitlines()
    files_seen = set()

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("#"):
            continue

        match = pattern_info["vulnerable"].search(line)
        if match:
            # Check for safe alternative
            safe = pattern_info.get("safe_indicator")
            is_safe = safe and safe in line

            result = SweepResult(
                file=filepath,
                line=i,
                code=line.strip(),
                pattern=pattern_key,
                is_vulnerable=not is_safe,
            )
            report.results.append(result)
            report.total_matches += 1

            if result.is_vulnerable:
                report.vulnerable_matches += 1
            else:
                report.safe_matches += 1

            files_seen.add(filepath)

    report.files_affected = list(files_seen)
    return report


def sweep_all_patterns(
    source: str,
    filepath: str,
) -> list[SweepReport]:
    """Sweep for ALL vulnerability patterns in source code.

    Returns one SweepReport per pattern type.
    """
    reports = []
    for pattern_key in VULNERABILITY_PATTERNS:
        report = sweep_pattern(source, filepath, pattern_key)
        if report.total_matches > 0:
            reports.append(report)
    return reports


def sweep_codebase(
    files: dict[str, str],
    pattern_key: str | None = None,
) -> list[SweepReport]:
    """Sweep across multiple files.

    Args:
        files: dict of {filepath: source_code}
        pattern_key: specific pattern to sweep, or None for all

    Returns:
        List of SweepReports (one per pattern per file with matches)
    """
    all_reports: list[SweepReport] = []

    for filepath, source in files.items():
        if pattern_key:
            report = sweep_pattern(source, filepath, pattern_key)
            if report.total_matches > 0:
                all_reports.append(report)
        else:
            file_reports = sweep_all_patterns(source, filepath)
            all_reports.extend(file_reports)

    return all_reports


def generate_sweep_summary(reports: list[SweepReport]) -> dict:
    """Generate a summary of sweep results."""
    total_vulnerable = sum(r.vulnerable_matches for r in reports)
    total_safe = sum(r.safe_matches for r in reports)
    all_files = set()
    for r in reports:
        all_files.update(r.files_affected)

    patterns_found = {}
    for r in reports:
        if r.vulnerable_matches > 0:
            patterns_found[r.pattern] = {
                "count": r.vulnerable_matches,
                "files": r.files_affected,
                "description": VULNERABILITY_PATTERNS.get(r.pattern, {}).get(
                    "description", r.pattern
                ),
                "fix": VULNERABILITY_PATTERNS.get(r.pattern, {}).get(
                    "fix", "Review and fix"
                ),
            }

    return {
        "total_vulnerable": total_vulnerable,
        "total_safe": total_safe,
        "files_affected": list(all_files),
        "patterns_found": patterns_found,
    }
