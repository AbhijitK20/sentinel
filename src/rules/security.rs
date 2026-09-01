use crate::evidence;
use crate::report::{Category, Finding, Severity};

pub fn check_sql_injection(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = source.lines().collect();

    // First pass: find variables assigned f-strings with SQL keywords
    let mut sql_fstring_vars: std::collections::HashSet<String> = std::collections::HashSet::new();
    for line in &lines {
        let trimmed = line.trim();
        if (trimmed.contains("f\"") || trimmed.contains("f'"))
            && (trimmed.to_uppercase().contains("SELECT") || trimmed.to_uppercase().contains("INSERT")
                || trimmed.to_uppercase().contains("UPDATE") || trimmed.to_uppercase().contains("DELETE")
                || trimmed.to_uppercase().contains("WHERE"))
        {
            if let Some(eq_pos) = trimmed.find('=') {
                let var = trimmed[..eq_pos].trim().to_string();
                sql_fstring_vars.insert(var);
            }
            // Also detect inline: cursor.execute(f"...")
            if trimmed.contains("execute") {
                let ev = evidence::generate_sql_injection_proof(trimmed);
                findings.push(Finding::new(
                    format!("sql-injection-inline-{}", trimmed.len()),
                    "sql-injection".to_string(),
                    Severity::Error,
                    Category::Security,
                    path.to_string(),
                    0,
                    0,
                    "SQL query built with f-string — potential SQL injection".to_string(),
                    "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))".to_string(),
                    0.95,
                    Some(ev),
                    None,
                    None,
                ));
            }
        }
    }

    // Second pass: check if those variables are passed to execute()
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("execute") || trimmed.contains("executemany") {
            for var in &sql_fstring_vars {
                if trimmed.contains(var) {
                    let ev = evidence::generate_sql_injection_proof(trimmed);
                    findings.push(Finding::new(
                        format!("sql-injection-{}", i),
                        "sql-injection".to_string(),
                        Severity::Error,
                        Category::Security,
                        path.to_string(),
                        i + 1,
                        0,
                        format!("Variable '{}' contains f-string SQL — passed to execute()", var),
                        "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))".to_string(),
                        0.95,
                        Some(ev),
                        None,
                        None,
                    ));
                }
            }
        }
    }

    findings
}

pub fn check_shell_injection(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("shell=True") {
            let ev = evidence::generate_shell_injection_proof(line.trim());
            findings.push(Finding::new(
                format!("shell-injection-{}", i),
                "subprocess-shell-true".to_string(),
                Severity::Error,
                Category::Security,
                path.to_string(),
                i + 1,
                0,
                "subprocess called with shell=True — potential command injection".to_string(),
                "Use shell=False with a list of arguments: subprocess.run(['ls', '-la'], shell=False)".to_string(),
                0.95,
                Some(ev),
                None,
                None,
            ));
        }
    }
    findings
}

pub fn check_eval_exec(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        for keyword in &["eval(", "exec("] {
            if trimmed.contains(keyword) {
                let kw = keyword.trim_end_matches('(');
                let ev = evidence::generate_eval_exec_proof(line.trim(), kw);
                findings.push(Finding::new(
                    format!("eval-exec-{}-{}", kw, i),
                    format!("use-of-{}", kw),
                    Severity::Error,
                    Category::Security,
                    path.to_string(),
                    i + 1,
                    0,
                    format!("Use of {}() — potential code injection", kw),
                    format!("Replace {}() with a safe alternative: ast.literal_eval() for data, importlib for modules", kw),
                    0.90,
                    Some(ev),
                    None,
                    None,
                ));
                break;
            }
        }
    }
    findings
}

pub fn check_hardcoded_secrets(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let secret_names = [
        "password", "passwd", "secret", "token", "api_key",
        "apikey", "api-key", "auth_token", "private_key", "secret_key",
        "access_key", "db_password", "database_password",
    ];

    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        for name in &secret_names {
            if trimmed.to_lowercase().contains(&name.to_lowercase()) {
                if let Some(eq_pos) = trimmed.find('=') {
                    let after_eq = trimmed[eq_pos + 1..].trim();
                    if (after_eq.starts_with('"') && after_eq.len() > 5)
                        || (after_eq.starts_with('\'') && after_eq.len() > 5)
                    {
                        let ev = evidence::generate_secret_proof(line.trim(), name);
                        findings.push(Finding::new(
                            format!("hardcoded-secret-{}-{}", name, i),
                            "hardcoded-secret".to_string(),
                            Severity::Error,
                            Category::Security,
                            path.to_string(),
                            i + 1,
                            0,
                            format!("Potential hardcoded secret in variable '{}'", name),
                            "Use environment variables: os.environ.get('SECRET_KEY') or a secrets manager".to_string(),
                            0.85,
                            Some(ev),
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

pub fn check_insecure_random(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("random.random()")
            || trimmed.contains("random.randint(")
            || trimmed.contains("random.choice(")
        {
            if trimmed.contains("password") || trimmed.contains("token")
                || trimmed.contains("secret") || trimmed.contains("key")
                || trimmed.contains("salt") || trimmed.contains("nonce")
            {
                findings.push(Finding::new(
                    format!("insecure-random-{}", i),
                    "insecure-random".to_string(),
                    Severity::Warning,
                    Category::Security,
                    path.to_string(),
                    i + 1,
                    0,
                    "random module used for security-sensitive value — not cryptographically secure".to_string(),
                    "Use secrets.token_hex() or os.urandom() for security-sensitive randomness".to_string(),
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

pub fn check_path_traversal(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if (trimmed.contains("open(") || trimmed.contains("os.path.join("))
            && (trimmed.contains("..") || trimmed.contains("user_input")
                || trimmed.contains("request") || trimmed.contains("argv"))
        {
            findings.push(Finding::new(
                format!("path-traversal-{}", i),
                "path-traversal".to_string(),
                Severity::Warning,
                Category::Security,
                path.to_string(),
                i + 1,
                0,
                "File path includes user-controlled input — potential path traversal".to_string(),
                "Validate and sanitize file paths: use os.path.realpath() and check the path starts with an allowed directory".to_string(),
                0.70,
                None,
                None,
                None,
            ));
        }
    }
    findings
}

pub fn check_debug_code(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("debugger") || trimmed.starts_with("breakpoint()") {
            findings.push(Finding::new(
                format!("debug-code-{}", i),
                "debug-statement".to_string(),
                Severity::Warning,
                Category::Security,
                path.to_string(),
                i + 1,
                0,
                "Debug statement left in code — should be removed before production".to_string(),
                "Remove debugger/breakpoint() calls before deploying to production".to_string(),
                0.95,
                None,
                None,
                None,
            ));
        }
    }
    findings
}

pub fn check_unsafe_deserialization(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("pickle.load(") || trimmed.contains("pickle.loads(") {
            findings.push(Finding::new(
                format!("unsafe-deserialize-{}", i),
                "unsafe-deserialization".to_string(),
                Severity::Error,
                Category::Security,
                path.to_string(),
                i + 1,
                0,
                "pickle deserialization — can execute arbitrary code".to_string(),
                "Use json.loads() or msgpack for safe deserialization".to_string(),
                0.90,
                None,
                None,
                None,
            ));
        }
        if trimmed.contains("yaml.load(") && !trimmed.contains("Loader") {
            findings.push(Finding::new(
                format!("unsafe-yaml-{}", i),
                "unsafe-yaml-load".to_string(),
                Severity::Warning,
                Category::Security,
                path.to_string(),
                i + 1,
                0,
                "yaml.load() without SafeLoader — potential code execution".to_string(),
                "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)".to_string(),
                0.85,
                None,
                None,
                None,
            ));
        }
    }
    findings
}

// ============================================================================
// NEW RULES FROM ANTHROPIC-CYBERSECURITY-SKILLS (CWE-mapped)
// ============================================================================

pub fn check_jwt_insecurity(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        // CWE-347: JWT decoded without algorithm verification
        if trimmed.contains("jwt.decode(")
            && (trimmed.contains("algorithms=[\"none\"]")
                || trimmed.contains("algorithms=['none']"))
        {
            findings.push(Finding::new(
                format!("jwt-none-alg-{}", i),
                "jwt-none-algorithm".to_string(),
                Severity::Error,
                Category::Security,
                path.to_string(),
                i + 1,
                0,
                "JWT decoded with 'none' algorithm — allows token forgery (CWE-347)".to_string(),
                "Always specify strong algorithms: jwt.decode(token, key, algorithms=['HS256'])".to_string(),
                0.95,
                None,
                None,
                None,
            ));
        }
        // CWE-345: JWT verification disabled
        if trimmed.contains("jwt.decode(")
            && trimmed.contains("verify_signature")
            && trimmed.contains("False")
        {
            findings.push(Finding::new(
                format!("jwt-no-verify-{}", i),
                "jwt-verification-disabled".to_string(),
                Severity::Error,
                Category::Security,
                path.to_string(),
                i + 1,
                0,
                "JWT signature verification disabled (CWE-345)".to_string(),
                "Enable signature verification: jwt.decode(token, key, algorithms=['HS256'])".to_string(),
                0.90,
                None,
                None,
                None,
            ));
        }
    }
    findings
}

pub fn check_ssrf(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if (trimmed.contains("requests.get(") || trimmed.contains("requests.post(")
            || trimmed.contains("httpx.get(") || trimmed.contains("httpx.post(")
            || trimmed.contains("urllib.request.urlopen("))
            && (trimmed.contains("user_input") || trimmed.contains("request.args")
                || trimmed.contains("request.form") || trimmed.contains("argv")
                || trimmed.contains("input("))
        {
            findings.push(Finding::new(
                format!("ssrf-{}", i),
                "potential-ssrf".to_string(),
                Severity::Warning,
                Category::Security,
                path.to_string(),
                i + 1,
                0,
                "HTTP request with user-controlled URL — potential SSRF (OWASP A10)".to_string(),
                "Validate and whitelist allowed URLs before making requests".to_string(),
                0.75,
                None,
                None,
                None,
            ));
        }
    }
    findings
}

pub fn check_nosql_injection(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if (trimmed.contains("$ne") || trimmed.contains("$gt") || trimmed.contains("$regex")
            || trimmed.contains("$where") || trimmed.contains("$exists"))
            && (trimmed.contains("request.json") || trimmed.contains("request.form")
                || trimmed.contains("json.loads") || trimmed.contains("user_input"))
        {
            findings.push(Finding::new(
                format!("nosql-injection-{}", i),
                "nosql-injection".to_string(),
                Severity::Warning,
                Category::Security,
                path.to_string(),
                i + 1,
                0,
                "NoSQL operator in user input — potential NoSQL injection (OWASP API8)".to_string(),
                "Validate input types and use parameterized queries".to_string(),
                0.70,
                None,
                None,
                None,
            ));
        }
    }
    findings
}

pub fn check_debug_code_production(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("debugger") || trimmed.starts_with("breakpoint()") {
            findings.push(Finding::new(
                format!("debug-production-{}", i),
                "debug-statement".to_string(),
                Severity::Warning,
                Category::Security,
                path.to_string(),
                i + 1,
                0,
                "Debug statement left in code — should be removed before production".to_string(),
                "Remove debugger/breakpoint() calls before deploying".to_string(),
                0.95,
                None,
                None,
                None,
            ));
        }
    }
    findings
}

// ============================================================================
// AI/ML SECURITY RULES (from MEDUSA's OWASP LLM Top 10 2025)
// ============================================================================

pub fn check_prompt_injection(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        // LLM01: Prompt injection via f-string with user input in LLM call
        if (trimmed.contains("completions") || trimmed.contains("chat")
            || trimmed.contains("messages") || trimmed.contains("generate")
            || trimmed.contains("invoke") || trimmed.contains("llm"))
            && (trimmed.contains("f\"") || trimmed.contains("f'"))
            && (trimmed.contains("user_input") || trimmed.contains("user_message")
                || trimmed.contains("user_query") || trimmed.contains("request.json")
                || trimmed.contains("input("))
        {
            findings.push(Finding::new(
                format!("prompt-injection-{}", i),
                "prompt-injection".to_string(),
                Severity::Error,
                Category::Security,
                path.to_string(),
                i + 1,
                0,
                "User input in f-string passed to LLM — potential prompt injection (OWASP LLM01)".to_string(),
                "Sanitize user input before passing to LLM. Use structured prompts with clear delimiters.".to_string(),
                0.90,
                None,
                None,
                None,
            ));
        }
        // LLM01: HumanMessage with user input
        if trimmed.contains("HumanMessage")
            && (trimmed.contains("f\"") || trimmed.contains("f'"))
            && (trimmed.contains("user") || trimmed.contains("input") || trimmed.contains("query"))
        {
            findings.push(Finding::new(
                format!("human-message-injection-{}", i),
                "prompt-injection".to_string(),
                Severity::Error,
                Category::Security,
                path.to_string(),
                i + 1,
                0,
                "HumanMessage with f-string user input — potential prompt injection (OWASP LLM01)".to_string(),
                "Use parameterized prompts: HumanMessage(content=[('user', template.format(data= sanitized_input))])".to_string(),
                0.85,
                None,
                None,
                None,
            ));
        }
    }
    findings
}

pub fn check_llm_output_handling(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        // LLM05: eval/exec on LLM output
        if (trimmed.contains("eval(") || trimmed.contains("exec("))
            && (trimmed.contains("response") || trimmed.contains("output")
                || trimmed.contains("completion") || trimmed.contains("result")
                || trimmed.contains("llm") || trimmed.contains("ai"))
        {
            findings.push(Finding::new(
                format!("llm-output-exec-{}", i),
                "llm-output-eval".to_string(),
                Severity::Error,
                Category::Security,
                path.to_string(),
                i + 1,
                0,
                "eval/exec on LLM output — arbitrary code execution (OWASP LLM05)".to_string(),
                "Never execute LLM output as code. Use structured output formats and validation.".to_string(),
                0.95,
                None,
                None,
                None,
            ));
        }
        // LLM05: subprocess on LLM output
        if trimmed.contains("subprocess")
            && (trimmed.contains("response") || trimmed.contains("output")
                || trimmed.contains("completion") || trimmed.contains("llm"))
        {
            findings.push(Finding::new(
                format!("llm-output-subprocess-{}", i),
                "llm-output-subprocess".to_string(),
                Severity::Error,
                Category::Security,
                path.to_string(),
                i + 1,
                0,
                "subprocess with LLM output — command injection (OWASP LLM05)".to_string(),
                "Validate LLM output against allowlist before passing to subprocess.".to_string(),
                0.90,
                None,
                None,
                None,
            ));
        }
    }
    findings
}

pub fn check_mcp_security(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        // MCP: Tool description injection
        if trimmed.contains("__doc__")
            && (trimmed.contains("requests.get") || trimmed.contains("httpx")
                || trimmed.contains("urllib") || trimmed.contains("fetch"))
        {
            findings.push(Finding::new(
                format!("mcp-tool-injection-{}", i),
                "mcp-tool-injection".to_string(),
                Severity::Error,
                Category::Security,
                path.to_string(),
                i + 1,
                0,
                "Dynamic tool description from remote source — MCP tool injection".to_string(),
                "Never load tool descriptions from untrusted remote sources".to_string(),
                0.90,
                None,
                None,
                None,
            ));
        }
        // MCP: Dynamic tool modification
        if trimmed.contains("setattr(")
            && (trimmed.contains("__doc__") || trimmed.contains("__name__")
                || trimmed.contains("tool") || trimmed.contains("function"))
        {
            findings.push(Finding::new(
                format!("mcp-dynamic-mod-{}", i),
                "mcp-dynamic-modification".to_string(),
                Severity::Warning,
                Category::Security,
                path.to_string(),
                i + 1,
                0,
                "Dynamic tool/function modification — potential MCP tool poisoning".to_string(),
                "Avoid dynamic modification of tool metadata at runtime".to_string(),
                0.75,
                None,
                None,
                None,
            ));
        }
    }
    findings
}

pub fn check_insecure_model_loading(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        // LLM03: trust_remote_code=True
        if trimmed.contains("trust_remote_code") && trimmed.contains("True") {
            findings.push(Finding::new(
                format!("trust-remote-code-{}", i),
                "trust-remote-code".to_string(),
                Severity::Error,
                Category::Security,
                path.to_string(),
                i + 1,
                0,
                "trust_remote_code=True — allows arbitrary code execution from model (OWASP LLM03)".to_string(),
                "Set trust_remote_code=False and verify model provenance".to_string(),
                0.90,
                None,
                None,
                None,
            ));
        }
        // LLM03: pickle.load for model loading
        if trimmed.contains("pickle.load")
            && (trimmed.contains("model") || trimmed.contains("weights")
                || trimmed.contains("checkpoint") || trimmed.contains(".pkl"))
        {
            findings.push(Finding::new(
                format!("pickle-model-{}", i),
                "insecure-model-loading".to_string(),
                Severity::Error,
                Category::Security,
                path.to_string(),
                i + 1,
                0,
                "Pickle deserialization for model loading — arbitrary code execution (OWASP LLM03)".to_string(),
                "Use safetensors or PyTorch native format instead of pickle".to_string(),
                0.85,
                None,
                None,
                None,
            ));
        }
    }
    findings
}
