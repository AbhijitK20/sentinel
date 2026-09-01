"""Type stubs for the Rust _core module."""


class Severity:
    Error: str
    Warning: str
    Info: str

class Category:
    Security: str
    Correctness: str
    Compliance: str
    AntiCheat: str
    Style: str
    Performance: str

class Evidence:
    reproduction_code: str
    expected_behavior: str
    actual_behavior: str
    proof_type: str
    def __init__(
        self,
        reproduction_code: str,
        expected_behavior: str,
        actual_behavior: str,
        proof_type: str,
    ) -> None: ...

class ComplianceMapping:
    framework: str
    control: str
    description: str
    severity: Severity
    def __init__(
        self, framework: str, control: str, description: str, severity: Severity
    ) -> None: ...

class Finding:
    id: str
    rule: str
    severity: Severity
    category: Category
    file: str
    line: int
    column: int
    end_line: int | None
    end_column: int | None
    message: str
    suggestion: str
    confidence: float
    evidence: Evidence | None
    def __init__(
        self,
        id: str,
        rule: str,
        severity: Severity,
        category: Category,
        file: str,
        line: int,
        column: int,
        message: str,
        suggestion: str,
        confidence: float,
        evidence: Evidence | None = None,
        end_line: int | None = None,
        end_column: int | None = None,
    ) -> None: ...

class FileReport:
    path: str
    findings: list[Finding]
    source_hash: str
    total_lines: int
    def __init__(
        self, path: str, findings: list[Finding], source_hash: str, total_lines: int
    ) -> None: ...

class ReportSummary:
    total_files: int
    files_with_findings: int
    total_findings: int
    by_severity: dict[str, int]
    by_category: dict[str, int]
    by_rule: dict[str, int]
    compliance_score: float
    def __init__(self) -> None: ...

class ScanReport:
    target: str
    timestamp: str
    tool_version: str
    file_reports: list[FileReport]
    summary: ReportSummary
    file_hashes: dict[str, str]
    def __init__(self, target: str) -> None: ...
    def compute_summary(self) -> None: ...
    def to_json(self) -> str: ...

def scan_file(path: str, source: str) -> FileReport: ...
def scan_directory(dir_path: str) -> ScanReport: ...
def scan_source(source: str, filename: str) -> FileReport: ...
