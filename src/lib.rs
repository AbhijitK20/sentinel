pub mod ast;
pub mod evidence;
pub mod report;
pub mod rules;

use pyo3::prelude::*;
use std::path::Path;

use report::{FileReport, Finding, ScanReport};
use rules::run_all_rules;

#[pyfunction]
pub fn scan_file(path: String, source: String) -> FileReport {
    let source_hash = ast::compute_hash(&source);
    let findings: Vec<Finding> = run_all_rules(&path, &source);
    let total_lines = source.lines().count();

    FileReport::new(path, findings, source_hash, total_lines)
}

#[pyfunction]
pub fn scan_directory(dir_path: String) -> ScanReport {
    let mut report = ScanReport::new(dir_path.clone());
    let path = Path::new(&dir_path);
    if !path.exists() {
        return report;
    }

    let entries: Vec<_> = if path.is_dir() {
        collect_python_files(path)
    } else if path.is_file() && path.extension().map_or(false, |e| e == "py") {
        vec![path.to_path_buf()]
    } else {
        vec![]
    };

    for entry in entries {
        let entry_str = entry.to_string_lossy().to_string();
        if let Ok(source) = std::fs::read_to_string(&entry) {
            let file_report = scan_file(entry_str.clone(), source);
            report
                .file_hashes
                .insert(entry_str, file_report.source_hash.clone());
            report.file_reports.push(file_report);
        }
    }

    report.compute_summary();
    report
}

#[pyfunction]
pub fn scan_source(source: String, filename: String) -> FileReport {
    scan_file(filename, source)
}

fn collect_python_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let exclude_dirs = [
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "node_modules",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "env",
        "target",
        ".tox",
    ];

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let dir_name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                if exclude_dirs.contains(&dir_name.as_str()) {
                    continue;
                }
                files.extend(collect_python_files(&path));
            } else if path.is_file() && path.extension().map_or(false, |e| e == "py") {
                files.push(path);
            }
        }
    }

    files.sort();
    files
}

#[pymodule]
#[pyo3(name = "_core")]
fn sentinel_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan_file, m)?)?;
    m.add_function(wrap_pyfunction!(scan_directory, m)?)?;
    m.add_function(wrap_pyfunction!(scan_source, m)?)?;
    m.add_class::<report::Finding>()?;
    m.add_class::<report::Evidence>()?;
    m.add_class::<report::FileReport>()?;
    m.add_class::<report::ScanReport>()?;
    m.add_class::<report::ReportSummary>()?;
    m.add_class::<report::Severity>()?;
    m.add_class::<report::Category>()?;
    m.add_class::<report::ComplianceMapping>()?;
    Ok(())
}
