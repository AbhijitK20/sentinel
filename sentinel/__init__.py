"""sentinel — Code review that proves it's right."""

__version__ = "0.1.0"

from sentinel._core import (
    Category,
    ComplianceMapping,
    Evidence,
    FileReport,
    Finding,
    ReportSummary,
    ScanReport,
    Severity,
    scan_directory,
    scan_file,
    scan_source,
)
from sentinel.llm_fix import FixSuggestionEngine, get_fix_engine

__all__ = [
    "Category",
    "ComplianceMapping",
    "Evidence",
    "FileReport",
    "Finding",
    "FixSuggestionEngine",
    "ReportSummary",
    "ScanReport",
    "Severity",
    "get_fix_engine",
    "scan_directory",
    "scan_file",
    "scan_source",
]
