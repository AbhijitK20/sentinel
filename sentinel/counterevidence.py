"""Counterevidence analysis — inspired by Strix's analysis/counterevidence skill.

From Strix: every finding must include a 'counterevidence' field —
the strongest case AGAINST the finding being real. This forces the
tool to consider false positives before reporting.

The counterevidence must be validated (non-empty) and must be a genuine
argument, not just "this might be a false positive."
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Counterevidence:
    """The strongest argument against a finding being a true positive."""

    finding_rule: str
    finding_line: int
    argument: str
    confidence_if_true: float  # confidence if counterevidence is valid
    severity_adjustment: str  # "none", "downgrade", "discard"


def generate_counterevidence(
    source: str,
    rule: str,
    line: int,
    confidence: float,
) -> Counterevidence:
    """Generate counterevidence for a finding.

    This is a heuristic-based implementation. In a full Strix-like system,
    this would use an LLM to reason about the finding.
    """
    lines = source.splitlines()
    target_line = lines[line - 1] if line <= len(lines) else ""
    context_start = max(0, line - 5)
    context_end = min(len(lines), line + 5)
    context = "\n".join(lines[context_start:context_end])

    # Generate counterevidence based on rule type
    counterevidence_map = {
        "sql-injection": _counter_sql_injection,
        "subprocess-shell-true": _counter_shell_true,
        "use-of-eval": _counter_eval,
        "hardcoded-secret": _counter_hardcoded_secret,
        "bare-except": _counter_bare_except,
        "except-pass": _counter_except_pass,
        "jwt-none-algorithm": _counter_jwt,
        "prompt-injection": _counter_prompt_injection,
        "unsafe-deserialization": _counter_deserialization,
    }

    generator = counterevidence_map.get(rule, _counter_generic)
    return generator(source, target_line, context, confidence)


def _counter_sql_injection(
    source: str, line: str, context: str, confidence: float
) -> Counterevidence:
    """Counterevidence for SQL injection findings."""
    # Check if parameterized query is used nearby
    if "execute(" in context and ("?" in context or "%s" in context):
        return Counterevidence(
            finding_rule="sql-injection",
            finding_line=0,
            argument="Parameterized query detected nearby — f-string may not reach execute()",
            confidence_if_true=0.3,
            severity_adjustment="downgrade",
        )

    # Check if input is hardcoded (not user-controlled)
    if "=" in line:
        var_name = line.split("=")[0].strip()
        if var_name and not any(
            w in var_name.lower()
            for w in ["user", "input", "request", "param", "arg"]
        ):
            return Counterevidence(
                finding_rule="sql-injection",
                finding_line=0,
                argument=f"Variable '{var_name}' appears to be internally assigned, not user-controlled",
                confidence_if_true=0.4,
                severity_adjustment="downgrade",
            )

    return Counterevidence(
        finding_rule="sql-injection",
        finding_line=0,
        argument="No counterevidence found — finding appears to be a true positive",
        confidence_if_true=confidence,
        severity_adjustment="none",
    )


def _counter_shell_true(
    source: str, line: str, context: str, confidence: float
) -> Counterevidence:
    """Counterevidence for shell=True findings."""
    if "shlex.quote" in context or "pipes.quote" in context:
        return Counterevidence(
            finding_rule="subprocess-shell-true",
            finding_line=0,
            argument="Input is quoted with shlex.quote — shell injection prevented",
            confidence_if_true=0.2,
            severity_adjustment="discard",
        )

    return Counterevidence(
        finding_rule="subprocess-shell-true",
        finding_line=0,
        argument="No counterevidence found — shell=True with user input is dangerous",
        confidence_if_true=confidence,
        severity_adjustment="none",
    )


def _counter_eval(
    source: str, line: str, context: str, confidence: float
) -> Counterevidence:
    """Counterevidence for eval/exec findings."""
    if "ast.literal_eval" in context:
        return Counterevidence(
            finding_rule="use-of-eval",
            finding_line=0,
            argument="ast.literal_eval used nearby — safe alternative present",
            confidence_if_true=0.2,
            severity_adjustment="discard",
        )

    if "compile(" in line and "exec" not in line:
        return Counterevidence(
            finding_rule="use-of-eval",
            finding_line=0,
            argument="compile() for code object creation, not arbitrary execution",
            confidence_if_true=0.5,
            severity_adjustment="downgrade",
        )

    return Counterevidence(
        finding_rule="use-of-eval",
        finding_line=0,
        argument="No counterevidence found — eval/exec is dangerous",
        confidence_if_true=confidence,
        severity_adjustment="none",
    )


def _counter_hardcoded_secret(
    source: str, line: str, context: str, confidence: float
) -> Counterevidence:
    """Counterevidence for hardcoded secret findings."""
    if "os.environ" in context or "os.getenv" in context:
        return Counterevidence(
            finding_rule="hardcoded-secret",
            finding_line=0,
            argument="Environment variable loading detected nearby",
            confidence_if_true=0.3,
            severity_adjustment="downgrade",
        )

    # Check if value looks like a placeholder
    if any(
        p in line.lower()
        for p in ["placeholder", "example", "xxx", "changeme", "test", "dummy"]
    ):
        return Counterevidence(
            finding_rule="hardcoded-secret",
            finding_line=0,
            argument="Value appears to be a placeholder, not a real secret",
            confidence_if_true=0.2,
            severity_adjustment="discard",
        )

    return Counterevidence(
        finding_rule="hardcoded-secret",
        finding_line=0,
        argument="No counterevidence found — hardcoded secrets are dangerous",
        confidence_if_true=confidence,
        severity_adjustment="none",
    )


def _counter_bare_except(
    source: str, line: str, context: str, confidence: float
) -> Counterevidence:
    """Counterevidence for bare except findings."""
    # Bare except is almost always wrong
    return Counterevidence(
        finding_rule="bare-except",
        finding_line=0,
        argument="No counterevidence — bare except catches SystemExit and KeyboardInterrupt",
        confidence_if_true=confidence,
        severity_adjustment="none",
    )


def _counter_except_pass(
    source: str, line: str, context: str, confidence: float
) -> Counterevidence:
    """Counterevidence for except-pass findings."""
    return Counterevidence(
        finding_rule="except-pass",
        finding_line=0,
        argument="No counterevidence — silent exception swallowing hides bugs",
        confidence_if_true=confidence,
        severity_adjustment="none",
    )


def _counter_jwt(
    source: str, line: str, context: str, confidence: float
) -> Counterevidence:
    """Counterevidence for JWT none algorithm findings."""
    return Counterevidence(
        finding_rule="jwt-none-algorithm",
        finding_line=0,
        argument="No counterevidence — JWT none algorithm allows token forgery",
        confidence_if_true=confidence,
        severity_adjustment="none",
    )


def _counter_prompt_injection(
    source: str, line: str, context: str, confidence: float
) -> Counterevidence:
    """Counterevidence for prompt injection findings."""
    if "sanitiz" in context.lower() or "escape" in context.lower():
        return Counterevidence(
            finding_rule="prompt-injection",
            finding_line=0,
            argument="Sanitization/escaping detected nearby",
            confidence_if_true=0.3,
            severity_adjustment="downgrade",
        )

    return Counterevidence(
        finding_rule="prompt-injection",
        finding_line=0,
        argument="No counterevidence — user input in LLM prompts is dangerous",
        confidence_if_true=confidence,
        severity_adjustment="none",
    )


def _counter_deserialization(
    source: str, line: str, context: str, confidence: float
) -> Counterevidence:
    """Counterevidence for unsafe deserialization findings."""
    if "json.loads" in context or "yaml.safe_load" in context:
        return Counterevidence(
            finding_rule="unsafe-deserialization",
            finding_line=0,
            argument="Safe deserialization alternative detected nearby",
            confidence_if_true=0.2,
            severity_adjustment="discard",
        )

    return Counterevidence(
        finding_rule="unsafe-deserialization",
        finding_line=0,
        argument="No counterevidence — pickle/yaml.load is dangerous",
        confidence_if_true=confidence,
        severity_adjustment="none",
    )


def _counter_generic(
    source: str, line: str, context: str, confidence: float
) -> Counterevidence:
    """Generic counterevidence for unknown rules."""
    return Counterevidence(
        finding_rule="unknown",
        finding_line=0,
        argument="No specific counterevidence available for this rule type",
        confidence_if_true=confidence,
        severity_adjustment="none",
    )


def should_adjust_finding(
    counterevidence: Counterevidence,
    original_confidence: float,
) -> tuple[float, str]:
    """Decide whether to adjust a finding based on counterevidence.

    Returns (new_confidence, adjustment_reason).
    """
    if counterevidence.severity_adjustment == "discard":
        return 0.0, f"Counterevidence discards finding: {counterevidence.argument}"

    if counterevidence.severity_adjustment == "downgrade":
        new_confidence = min(original_confidence, counterevidence.confidence_if_true)
        return new_confidence, f"Counterevidence downgrades: {counterevidence.argument}"

    return original_confidence, "No adjustment"
