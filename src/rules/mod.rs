pub mod anti_cheat;
pub mod compliance;
pub mod correctness;
pub mod security;

use crate::report::Finding;

pub fn run_all_rules(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Security rules
    findings.extend(security::check_sql_injection(path, source));
    findings.extend(security::check_shell_injection(path, source));
    findings.extend(security::check_eval_exec(path, source));
    findings.extend(security::check_hardcoded_secrets(path, source));
    findings.extend(security::check_insecure_random(path, source));
    findings.extend(security::check_path_traversal(path, source));
    findings.extend(security::check_debug_code(path, source));
    findings.extend(security::check_unsafe_deserialization(path, source));
    // New rules from Anthropic-Cybersecurity-Skills
    findings.extend(security::check_jwt_insecurity(path, source));
    findings.extend(security::check_ssrf(path, source));
    findings.extend(security::check_nosql_injection(path, source));
    findings.extend(security::check_debug_code_production(path, source));
    // AI/ML security rules from MEDUSA (OWASP LLM Top 10 2025)
    findings.extend(security::check_prompt_injection(path, source));
    findings.extend(security::check_llm_output_handling(path, source));
    findings.extend(security::check_mcp_security(path, source));
    findings.extend(security::check_insecure_model_loading(path, source));

    // Correctness rules
    findings.extend(correctness::check_unclosed_resource(path, source));
    findings.extend(correctness::check_mutable_default(path, source));
    findings.extend(correctness::check_bare_except(path, source));
    findings.extend(correctness::check_except_pass(path, source));
    findings.extend(correctness::check_return_in_init(path, source));
    findings.extend(correctness::check_comparison_to_none(path, source));
    findings.extend(correctness::check_unreachable_code(path, source));
    // Dynamo task patterns
    findings.extend(correctness::check_config_override(path, source));
    findings.extend(correctness::check_comment_defends_bug(path, source));
    findings.extend(correctness::check_hidden_constant(path, source));

    // Compliance rules
    findings.extend(compliance::check_hipaa(path, source));
    findings.extend(compliance::check_soc2(path, source));
    findings.extend(compliance::check_gdpr(path, source));
    findings.extend(compliance::check_pci(path, source));
    findings.extend(compliance::check_sox(path, source));

    // Anti-cheat rules
    findings.extend(anti_cheat::check_linter_evasion(path, source));
    findings.extend(anti_cheat::check_dynamic_import_evasion(path, source));
    findings.extend(anti_cheat::check_string_concat_obfuscation(path, source));
    findings.extend(anti_cheat::check_conditional_suppression(path, source));

    findings
}
