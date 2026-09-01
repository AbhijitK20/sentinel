use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[pyclass]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[pymethods]
impl Severity {
    fn __str__(&self) -> String {
        match self {
            Severity::Error => "error".to_string(),
            Severity::Warning => "warning".to_string(),
            Severity::Info => "info".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[pyclass]
pub enum Category {
    Security,
    Correctness,
    Compliance,
    AntiCheat,
    Style,
    Performance,
}

#[pymethods]
impl Category {
    fn __str__(&self) -> String {
        match self {
            Category::Security => "security".to_string(),
            Category::Correctness => "correctness".to_string(),
            Category::Compliance => "compliance".to_string(),
            Category::AntiCheat => "anti_cheat".to_string(),
            Category::Style => "style".to_string(),
            Category::Performance => "performance".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[pyclass]
pub struct Finding {
    #[pyo3(get)]
    pub id: String,
    #[pyo3(get)]
    pub rule: String,
    #[pyo3(get)]
    pub severity: Severity,
    #[pyo3(get)]
    pub category: Category,
    #[pyo3(get)]
    pub file: String,
    #[pyo3(get)]
    pub line: usize,
    #[pyo3(get)]
    pub column: usize,
    #[pyo3(get)]
    pub end_line: Option<usize>,
    #[pyo3(get)]
    pub end_column: Option<usize>,
    #[pyo3(get)]
    pub message: String,
    #[pyo3(get)]
    pub suggestion: String,
    #[pyo3(get)]
    pub confidence: f64,
    #[pyo3(get)]
    pub evidence: Option<Evidence>,
}

#[pymethods]
impl Finding {
    #[new]
    #[pyo3(signature = (id, rule, severity, category, file, line, column, message, suggestion, confidence, evidence=None, end_line=None, end_column=None))]
    pub fn new(
        id: String,
        rule: String,
        severity: Severity,
        category: Category,
        file: String,
        line: usize,
        column: usize,
        message: String,
        suggestion: String,
        confidence: f64,
        evidence: Option<Evidence>,
        end_line: Option<usize>,
        end_column: Option<usize>,
    ) -> Self {
        Finding {
            id,
            rule,
            severity,
            category,
            file,
            line,
            column,
            end_line,
            end_column,
            message,
            suggestion,
            confidence,
            evidence,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[pyclass]
pub struct Evidence {
    #[pyo3(get)]
    pub reproduction_code: String,
    #[pyo3(get)]
    pub expected_behavior: String,
    #[pyo3(get)]
    pub actual_behavior: String,
    #[pyo3(get)]
    pub proof_type: String,
}

#[pymethods]
impl Evidence {
    #[new]
    pub fn new(
        reproduction_code: String,
        expected_behavior: String,
        actual_behavior: String,
        proof_type: String,
    ) -> Self {
        Evidence {
            reproduction_code,
            expected_behavior,
            actual_behavior,
            proof_type,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[pyclass]
pub struct ComplianceMapping {
    #[pyo3(get)]
    pub framework: String,
    #[pyo3(get)]
    pub control: String,
    #[pyo3(get)]
    pub description: String,
    #[pyo3(get)]
    pub severity: Severity,
}

#[pymethods]
impl ComplianceMapping {
    #[new]
    pub fn new(framework: String, control: String, description: String, severity: Severity) -> Self {
        ComplianceMapping {
            framework,
            control,
            description,
            severity,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[pyclass]
pub struct ReportSummary {
    #[pyo3(get)]
    pub total_files: usize,
    #[pyo3(get)]
    pub files_with_findings: usize,
    #[pyo3(get)]
    pub total_findings: usize,
    #[pyo3(get)]
    pub by_severity: std::collections::HashMap<String, usize>,
    #[pyo3(get)]
    pub by_category: std::collections::HashMap<String, usize>,
    #[pyo3(get)]
    pub by_rule: std::collections::HashMap<String, usize>,
    #[pyo3(get)]
    pub compliance_score: f64,
}

#[pymethods]
impl ReportSummary {
    #[new]
    pub fn new() -> Self {
        ReportSummary {
            total_files: 0,
            files_with_findings: 0,
            total_findings: 0,
            by_severity: std::collections::HashMap::new(),
            by_category: std::collections::HashMap::new(),
            by_rule: std::collections::HashMap::new(),
            compliance_score: 100.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[pyclass]
pub struct FileReport {
    #[pyo3(get)]
    pub path: String,
    #[pyo3(get)]
    pub findings: Vec<Finding>,
    #[pyo3(get)]
    pub source_hash: String,
    #[pyo3(get)]
    pub total_lines: usize,
}

#[pymethods]
impl FileReport {
    #[new]
    pub fn new(path: String, findings: Vec<Finding>, source_hash: String, total_lines: usize) -> Self {
        FileReport {
            path,
            findings,
            source_hash,
            total_lines,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[pyclass]
pub struct ScanReport {
    #[pyo3(get)]
    pub target: String,
    #[pyo3(get)]
    pub timestamp: String,
    #[pyo3(get)]
    pub tool_version: String,
    #[pyo3(get)]
    pub file_reports: Vec<FileReport>,
    #[pyo3(get)]
    pub summary: ReportSummary,
    #[pyo3(get)]
    pub file_hashes: std::collections::HashMap<String, String>,
}

#[pymethods]
impl ScanReport {
    #[new]
    pub fn new(target: String) -> Self {
        ScanReport {
            target,
            timestamp: chrono_free_timestamp(),
            tool_version: "0.1.0".to_string(),
            file_reports: Vec::new(),
            summary: ReportSummary::new(),
            file_hashes: std::collections::HashMap::new(),
        }
    }

    pub fn compute_summary(&mut self) {
        let mut summary = ReportSummary::new();
        summary.total_files = self.file_reports.len();

        let mut all_findings: Vec<&Finding> = Vec::new();
        for fr in &self.file_reports {
            if !fr.findings.is_empty() {
                summary.files_with_findings += 1;
            }
            for f in &fr.findings {
                all_findings.push(f);
            }
        }

        summary.total_findings = all_findings.len();

        for f in &all_findings {
            let sev = f.severity.__str__();
            *summary.by_severity.entry(sev).or_insert(0) += 1;

            let cat = f.category.__str__();
            *summary.by_category.entry(cat).or_insert(0) += 1;

            *summary.by_rule.entry(f.rule.clone()).or_insert(0) += 1;
        }

        let total = summary.total_findings as f64;
        if total > 0.0 {
            let errors = *summary.by_severity.get("error").unwrap_or(&0) as f64;
            summary.compliance_score = ((total - errors) / total * 100.0).round();
        }

        self.summary = summary;
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

fn chrono_free_timestamp() -> String {
    // Simple timestamp without chrono dependency
    "2026-09-01T00:00:00Z".to_string()
}
