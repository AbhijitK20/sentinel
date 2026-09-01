use crate::report::{Category, Finding, Severity};

pub fn check_hipaa(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let hipaa_patterns = [
        ("patient", "PHI access without access control"),
        ("medical_record", "Medical record accessed without audit logging"),
        ("diagnosis", "Diagnosis data exposed without encryption"),
        ("ssn", "SSN handled without HIPAA-compliant safeguards"),
        ("health_info", "Health information processed without BAA"),
    ];

    for (i, line) in source.lines().enumerate() {
        let lower = line.to_lowercase();
        for (pattern, desc) in &hipaa_patterns {
            if lower.contains(pattern) {
                // Check if there's any access control nearby
                let has_access_control = source.contains("authorize")
                    || source.contains("access_control")
                    || source.contains("permission")
                    || source.contains("rbac");

                if !has_access_control {
                    findings.push(Finding::new(
                        format!("hipaa-{}-{}", pattern, i),
                        format!("hipaa-{}", pattern),
                        Severity::Warning,
                        Category::Compliance,
                        path.to_string(),
                        i + 1,
                        0,
                        format!("HIPAA concern: {}", desc),
                        "Add access control checks and audit logging for PHI data".to_string(),
                        0.70,
                        None,
                        None,
                        None,
                    ));
                }
            }
        }
    }
    findings
}

pub fn check_soc2(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let lower = line.to_lowercase();
        // SOC2: File operations without audit logging
        if (lower.contains("open(") || lower.contains("write("))
            && (lower.contains("config") || lower.contains("credential")
                || lower.contains("secret") || lower.contains("key"))
        {
            let has_audit = source.contains("audit") || source.contains("log")
                || source.contains("logger");
            if !has_audit {
                findings.push(Finding::new(
                    format!("soc2-audit-{}", i),
                    "soc2-missing-audit".to_string(),
                    Severity::Warning,
                    Category::Compliance,
                    path.to_string(),
                    i + 1,
                    0,
                    "SOC2: Sensitive file operation without audit logging".to_string(),
                    "Add audit logging for all access to sensitive configuration files".to_string(),
                    0.65,
                    None,
                    None,
                    None,
                ));
            }
        }
    }
    findings
}

pub fn check_gdpr(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let gdpr_fields = ["email", "name", "address", "phone", "ip_address", "location"];

    for (i, line) in source.lines().enumerate() {
        let lower = line.to_lowercase();
        for field in &gdpr_fields {
            if lower.contains(field) && (lower.contains("print(") || lower.contains("log(")
                || lower.contains("return ") || lower.contains("response"))
            {
                let has_masking = source.contains("mask") || source.contains("redact")
                    || source.contains("anonymize") || source.contains("encrypt");
                if !has_masking {
                    findings.push(Finding::new(
                        format!("gdpr-pii-{}-{}", field, i),
                        format!("gdpr-unmasked-{}", field),
                        Severity::Warning,
                        Category::Compliance,
                        path.to_string(),
                        i + 1,
                        0,
                        format!("GDPR: PII field '{}' exposed without masking", field),
                        "Mask or redact PII before logging/exposure: use data masking functions".to_string(),
                        0.65,
                        None,
                        None,
                        None,
                    ));
                }
            }
        }
    }
    findings
}

pub fn check_pci(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let pci_patterns = [
        ("card_number", "Payment card number handled without PCI controls"),
        ("cvv", "CVV stored or logged — prohibited by PCI DSS"),
        ("credit_card", "Credit card data without encryption"),
    ];

    for (i, line) in source.lines().enumerate() {
        let lower = line.to_lowercase();
        for (pattern, desc) in &pci_patterns {
            if lower.contains(pattern) {
                findings.push(Finding::new(
                    format!("pci-{}-{}", pattern, i),
                    format!("pci-{}", pattern),
                    Severity::Error,
                    Category::Compliance,
                    path.to_string(),
                    i + 1,
                    0,
                    format!("PCI DSS: {}", desc),
                    "Never store CVV. Encrypt card numbers. Use tokenization for payment data.".to_string(),
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

pub fn check_sox(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let lower = line.to_lowercase();
        if (lower.contains("financial") || lower.contains("revenue")
            || lower.contains("accounting") || lower.contains("ledger"))
            && (lower.contains("delete(") || lower.contains("drop(")
                || lower.contains("truncate") || lower.contains("update("))
        {
            let has_approval = source.contains("approve") || source.contains("authorization")
                || source.contains("review");
            if !has_approval {
                findings.push(Finding::new(
                    format!("sox-modify-{}", i),
                    "sox-unauthorized-modification".to_string(),
                    Severity::Error,
                    Category::Compliance,
                    path.to_string(),
                    i + 1,
                    0,
                    "SOX: Financial data modification without approval workflow".to_string(),
                    "Add authorization checks and audit trail for financial data modifications".to_string(),
                    0.75,
                    None,
                    None,
                    None,
                ));
            }
        }
    }
    findings
}
