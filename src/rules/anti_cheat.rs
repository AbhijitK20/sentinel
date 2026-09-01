use crate::report::{Category, Finding, Severity};

pub fn check_linter_evasion(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("# noqa") {
            let noqa_count = source.lines().filter(|l| l.contains("# noqa")).count();
            if noqa_count > 3 {
                findings.push(Finding::new(
                    format!("linter-evasion-noqa-{}", i),
                    "excessive-noqa".to_string(),
                    Severity::Warning,
                    Category::AntiCheat,
                    path.to_string(),
                    i + 1,
                    0,
                    format!("File has {} noqa comments — possible linter evasion", noqa_count),
                    "Review noqa usage: suppressions should be rare and justified".to_string(),
                    0.60,
                    None,
                    None,
                    None,
                ));
            }
        }
        if trimmed.contains("# type: ignore") {
            let type_ignore_count = source.lines().filter(|l| l.contains("# type: ignore")).count();
            if type_ignore_count > 5 {
                findings.push(Finding::new(
                    format!("linter-evasion-typeignore-{}", i),
                    "excessive-type-ignore".to_string(),
                    Severity::Info,
                    Category::AntiCheat,
                    path.to_string(),
                    i + 1,
                    0,
                    format!(
                        "File has {} type:ignore comments — possible type-check evasion",
                        type_ignore_count
                    ),
                    "Fix type errors instead of suppressing them".to_string(),
                    0.50,
                    None,
                    None,
                    None,
                ));
            }
        }
    }
    findings
}

pub fn check_dynamic_import_evasion(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("__import__(")
            || (trimmed.contains("importlib") && trimmed.contains("import_module"))
        {
            findings.push(Finding::new(
                format!("dynamic-import-{}", i),
                "dynamic-import".to_string(),
                Severity::Info,
                Category::AntiCheat,
                path.to_string(),
                i + 1,
                0,
                "Dynamic import detected — may hide dependencies from static analysis".to_string(),
                "Use static imports at the top of the file when possible".to_string(),
                0.50,
                None,
                None,
                None,
            ));
        }
    }
    findings
}

pub fn check_string_concat_obfuscation(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("' + '") || trimmed.contains("\" + \"")
            || trimmed.contains("'+'") || trimmed.contains("\"+\"")
        {
            let concat_count = trimmed.matches(" + ").count();
            if concat_count > 3 {
                findings.push(Finding::new(
                    format!("string-obfuscation-{}", i),
                    "string-concat-obfuscation".to_string(),
                    Severity::Info,
                    Category::AntiCheat,
                    path.to_string(),
                    i + 1,
                    0,
                    "Excessive string concatenation — possible obfuscation".to_string(),
                    "Use f-strings or string literals instead of concatenation".to_string(),
                    0.40,
                    None,
                    None,
                    None,
                ));
            }
        }
    }
    findings
}

pub fn check_conditional_suppression(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = source.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("sys.platform") || trimmed.contains("os.name") {
            for j in (i + 1)..std::cmp::min(i + 10, lines.len()) {
                let inner = lines[j].trim();
                if inner.contains("noqa")
                    || inner.contains("type: ignore")
                    || inner.contains("pylint: disable")
                {
                    findings.push(Finding::new(
                        format!("conditional-suppress-{}", i),
                        "conditional-linter-suppression".to_string(),
                        Severity::Warning,
                        Category::AntiCheat,
                        path.to_string(),
                        i + 1,
                        0,
                        "Platform-conditional code with linter suppression — may hide from CI"
                            .to_string(),
                        "Ensure all platform paths are covered by linter checks".to_string(),
                        0.65,
                        None,
                        None,
                        None,
                    ));
                    break;
                }
            }
        }
    }
    findings
}
