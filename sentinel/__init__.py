"""sentinel — Code review that proves it's right."""

__version__ = "0.1.0"

from sentinel._core import (
    Category,
    ComplianceMapping,
    Evidence,
    FileReport,
    ReportSummary,
    ScanReport,
    Severity,
    Finding,
    scan_directory,
    scan_file,
    scan_source,
)
from sentinel.llm_fix import FixSuggestionEngine, get_fix_engine

__all__ = [
    "scan_file",
    "scan_directory",
    "scan_source",
    "Finding",
    "Evidence",
    "FileReport",
    "ScanReport",
    "ReportSummary",
    "Severity",
    "Category",
    "ComplianceMapping",
    "FixSuggestionEngine",
    "get_fix_engine",
]
