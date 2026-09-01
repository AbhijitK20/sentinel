use crate::evidence;
use crate::report::{Category, Finding, Severity};

pub fn check_unclosed_resource(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = source.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("= open(") && !trimmed.contains("with ") {
            let var_name = trimmed.split('=').next().unwrap_or("").trim();
            let later_uses_close = lines.iter().skip(i + 1).any(|l| {
                l.contains(&format!("{}.close()", var_name))
                    || l.contains(&format!("with {var_name}"))
                    || (l.contains("with ") && l.contains(var_name))
            });
            if !later_uses_close {
                let ev = evidence::generate_resource_leak_proof(trimmed, var_name);
                findings.push(Finding::new(
                    format!("unclosed-resource-{}", i),
                    "unclosed-resource".to_string(),
                    Severity::Warning,
                    Category::Correctness,
                    path.to_string(),
                    i + 1,
                    0,
                    format!("File opened without context manager or close(): '{}'", var_name),
                    "Use 'with open(...) as f:' to ensure proper resource cleanup".to_string(),
                    0.90,
                    Some(ev),
                    None,
                    None,
                ));
            }
        }
    }
    findings
}

pub fn check_mutable_default(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("def ")
            && (trimmed.contains("=[]") || trimmed.contains("={}") || trimmed.contains("=set()"))
        {
            let ev = evidence::generate_mutable_default_proof(trimmed);
            findings.push(Finding::new(
                format!("mutable-default-{}", i),
                "mutable-default-argument".to_string(),
                Severity::Warning,
                Category::Correctness,
                path.to_string(),
                i + 1,
                0,
                "Mutable default argument — shared across all calls".to_string(),
                "Use None as default: def f(items=None): items = items or []".to_string(),
                0.90,
                Some(ev),
                None,
                None,
            ));
        }
    }
    findings
}

pub fn check_bare_except(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed == "except:" {
            findings.push(Finding::new(
                format!("bare-except-{}", i),
                "bare-except".to_string(),
                Severity::Warning,
                Category::Correctness,
                path.to_string(),
                i + 1,
                0,
                "Bare 'except:' catches all exceptions including SystemExit and KeyboardInterrupt"
                    .to_string(),
                "Specify exception type: 'except Exception:' at minimum".to_string(),
                0.85,
                None,
                None,
                None,
            ));
        }
    }
    findings
}

pub fn check_except_pass(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("except") && i + 1 < lines.len() {
            let next = lines[i + 1].trim();
            if next == "pass" {
                let ev = evidence::generate_except_pass_proof(trimmed);
                findings.push(Finding::new(
                    format!("except-pass-{}", i),
                    "except-pass".to_string(),
                    Severity::Warning,
                    Category::Correctness,
                    path.to_string(),
                    i + 1,
                    0,
                    format!(
                        "Silent exception swallowing: '{}' followed by 'pass'",
                        trimmed
                    ),
                    "Log the exception or handle it explicitly".to_string(),
                    0.85,
                    Some(ev),
                    None,
                    None,
                ));
            }
        }
    }
    findings
}

pub fn check_return_in_init(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    let mut in_init = false;
    let mut init_indent = 0;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("def __init__(") {
            in_init = true;
            init_indent = line.len() - line.trim_start().len();
            continue;
        }
        if in_init {
            let current_indent = line.len() - line.trim_start().len();
            if current_indent <= init_indent && !line.trim().is_empty() && !line.trim().starts_with('#') {
                in_init = false;
                continue;
            }
            if trimmed.starts_with("return ") && trimmed != "return None" && trimmed != "return" {
                findings.push(Finding::new(
                    format!("return-in-init-{}", i),
                    "return-in-init".to_string(),
                    Severity::Error,
                    Category::Correctness,
                    path.to_string(),
                    i + 1,
                    0,
                    "Return value in __init__ — must return None".to_string(),
                    "Remove the return value or move logic to a @classmethod".to_string(),
                    0.95,
                    None,
                    None,
                    None,
                ));
            }
        }
    }
    findings
}

pub fn check_comparison_to_none(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if trimmed.contains("== None") || trimmed.contains("!= None") {
            let op = if trimmed.contains("== None") { "==" } else { "!=" };
            findings.push(Finding::new(
                format!("comparison-none-{}-{}", op, i),
                "comparison-to-none".to_string(),
                Severity::Info,
                Category::Style,
                path.to_string(),
                i + 1,
                0,
                format!("Use 'is None' / 'is not None' instead of '{}' comparison", op),
                format!("Replace '{}' with 'is None' or 'is not None'", op),
                0.95,
                None,
                None,
                None,
            ));
        }
    }
    findings
}

pub fn check_unreachable_code(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = source.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if (trimmed.starts_with("return ")
            || trimmed == "return"
            || trimmed.starts_with("raise ")
            || trimmed.starts_with("sys.exit"))
            && i + 1 < lines.len()
        {
            let next = lines[i + 1].trim();
            if !next.is_empty()
                && !next.starts_with('#')
                && !next.starts_with("def ")
                && !next.starts_with("class ")
                && !next.starts_with('@')
                && next != "else:"
                && !next.starts_with("elif ")
                && next != "except"
                && next != "finally:"
                && next != "}"
            {
                findings.push(Finding::new(
                    format!("unreachable-{}", i),
                    "unreachable-code".to_string(),
                    Severity::Warning,
                    Category::Correctness,
                    path.to_string(),
                    i + 2,
                    0,
                    "Code after return/raise/exit is unreachable".to_string(),
                    "Remove unreachable code or fix control flow".to_string(),
                    0.80,
                    None,
                    None,
                    None,
                ));
            }
        }
    }
    findings
}

// ============================================================================
// DYNAMO TASK PATTERNS (from incomplete tasks)
// ============================================================================

pub fn check_config_override(path: &str, source: &str) -> Vec<Finding> {
    // Detect ENV variables that silently override config file values.
    // Pattern from dynamo-0a286a6 (ML infra task): Dockerfile ENV vars
    // override config.json, and modules check ENV before config.
    let mut findings = Vec::new();
    let lines: Vec<&str> = source.lines().collect();

    // Check for ENV override patterns
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Pattern: os.environ.get() with fallback that shadows config
        if trimmed.contains("os.environ.get(") || trimmed.contains("os.environ[") {
            // Check if there's also a config file load nearby
            let has_config_load = lines.iter().any(|l| {
                l.contains("config.json") || l.contains("config.toml")
                    || l.contains("settings.") || l.contains("Config.")
            });

            if has_config_load {
                // Check if ENV is checked BEFORE config
                let env_first = lines.iter().take(i).any(|l| {
                    l.contains("os.environ.get(") || l.contains("os.environ[")
                });

                if !env_first {
                    findings.push(Finding::new(
                        format!("config-override-{}", i),
                        "config-override".to_string(),
                        Severity::Warning,
                        Category::Correctness,
                        path.to_string(),
                        i + 1,
                        0,
                        "ENV variable checked before config file — may silently override config".to_string(),
                        "Document ENV override precedence or remove ENV check".to_string(),
                        0.70,
                        None,
                        None,
                        None,
                    ));
                }
            }
        }

        // Pattern: os.getenv with default that matches config value
        if trimmed.contains("os.getenv(") {
            // Look for the same variable being loaded from config later
            if let Some(var_start) = trimmed.find("os.getenv('") {
                let var_end = trimmed[var_start + 11..].find('\'');
                if let Some(end) = var_end {
                    let var_name = &trimmed[var_start + 11..var_start + 11 + end];
                    // Check if same var appears in config load
                    let config_shadows = lines.iter().any(|l| {
                        l.contains(var_name) && (l.contains("config") || l.contains("settings"))
                    });
                    if config_shadows {
                        findings.push(Finding::new(
                            format!("env-config-shadow-{}", i),
                            "config-override".to_string(),
                            Severity::Info,
                            Category::Correctness,
                            path.to_string(),
                            i + 1,
                            0,
                            format!("ENV var '{}' also loaded from config — precedence may cause bugs", var_name),
                            "Document which source takes precedence".to_string(),
                            0.60,
                            None,
                            None,
                            None,
                        ));
                    }
                }
            }
        }
    }
    findings
}

pub fn check_comment_defends_bug(path: &str, source: &str) -> Vec<Finding> {
    // Detect comments that defend buggy behavior as intentional.
    // Pattern from dynamo-0a286a6: code contains comments like
    // "a running denominator gives a cumulative picture..." that
    // defend bugs as intentional design choices.
    let mut findings = Vec::new();
    let defensive_phrases = [
        "this is intentional",
        "by design",
        "this is correct",
        "works as intended",
        "by design choice",
        "this is expected",
        "not a bug",
        "intentional behavior",
        "deliberate",
        "this is fine",
    ];

    for (i, line) in source.lines().enumerate() {
        let lower = line.to_lowercase();
        if lower.contains('#') || lower.contains("//") {
            for phrase in &defensive_phrases {
                if lower.contains(phrase) {
                    findings.push(Finding::new(
                        format!("comment-defends-bug-{}", i),
                        "comment-defends-bug".to_string(),
                        Severity::Info,
                        Category::Correctness,
                        path.to_string(),
                        i + 1,
                        0,
                        format!("Comment defends behavior as '{}' — may be hiding a bug", phrase),
                        "Verify the behavior is actually correct, not just defended".to_string(),
                        0.50,
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

pub fn check_hidden_constant(path: &str, source: &str) -> Vec<Finding> {
    // Detect suspiciously specific numeric constants.
    // Pattern from dynamo-8afbe42 (embedded task): tests detect hardcoded
    // ground-truth values like 200.0/8.0 that match expected output.
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        // Look for magic numbers that might be hardcoded ground truth
        // Pattern: exact division that produces a specific value
        if let Some(eq_pos) = trimmed.find('=') {
            let right = trimmed[eq_pos + 1..].trim();
            // Detect patterns like: x = 200.0 / 8.0 or x = 12345.6789
            if right.contains('/') && right.matches('.').count() >= 2 {
                // Division with decimals - could be hardcoded calculation
                let parts: Vec<&str> = right.split('/').collect();
                if parts.len() == 2 {
                    let left_val = parts[0].trim().parse::<f64>();
                    let right_val = parts[1].trim().parse::<f64>();
                    if let (Ok(l), Ok(r)) = (left_val, right_val) {
                        let result = l / r;
                        // If result is a "nice" number, might be hardcoded
                        if result.fract() == 0.0 && result > 0.0 && result < 100000.0 {
                            findings.push(Finding::new(
                                format!("hidden-constant-{}", i),
                                "hardcoded-constant".to_string(),
                                Severity::Info,
                                Category::Correctness,
                                path.to_string(),
                                i + 1,
                                0,
                                format!("Magic constant {} = {} / {} — may be hardcoded ground truth", result, l, r),
                                "Derive this value from config or input data instead of hardcoding".to_string(),
                                0.40,
                                None,
                                None,
                                None,
                            ));
                        }
                    }
                }
            }
        }
    }
    findings
}
