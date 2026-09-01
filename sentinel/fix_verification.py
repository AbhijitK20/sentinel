"""Fix verification gates — inspired by Strix's 5-gate verification system.

From Strix's fix_verification.md:
1. Applicability — fix_before matches the file character-for-character
2. Security closure — re-trace source -> sink through patched code
3. Bypass review — re-read diff without leaning on original reasoning
4. Preserved behavior — legitimate inputs still work
5. Repository checks — syntax/type/lint/test on changed lines

We implement a simplified version for static analysis findings.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass


@dataclass
class VerificationGate:
    """Result of a single verification gate."""

    gate: str
    passed: bool
    reason: str
    confidence: float = 0.0


@dataclass
class FixVerification:
    """Complete verification result for a proposed fix."""

    finding_id: str
    gates: list[VerificationGate]
    overall_passed: bool
    overall_confidence: float

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "gates": [
                {"gate": g.gate, "passed": g.passed, "reason": g.reason}
                for g in self.gates
            ],
            "overall_passed": self.overall_passed,
            "overall_confidence": self.overall_confidence,
        }


def verify_fix(
    original_source: str,
    fixed_source: str,
    finding_rule: str,
    finding_line: int,
) -> FixVerification:
    """Run all 5 verification gates on a proposed fix.

    Args:
        original_source: The original buggy source code
        fixed_source: The source after the fix is applied
        finding_rule: The rule ID that was triggered
        finding_line: The line number of the finding

    Returns:
        FixVerification with all gate results
    """
    gates = []

    # Gate 1: Applicability — fix actually changed something
    g1 = gate_1_applicability(original_source, fixed_source)
    gates.append(g1)

    # Gate 2: Security closure — vulnerable pattern is gone
    g2 = gate_2_security_closure(fixed_source, finding_rule, finding_line)
    gates.append(g2)

    # Gate 3: Bypass review — fix doesn't introduce new issues
    g3 = gate_3_bypass_review(original_source, fixed_source, finding_rule)
    gates.append(g3)

    # Gate 4: Preserved behavior — fix doesn't break legitimate code
    g4 = gate_4_preserved_behavior(original_source, fixed_source)
    gates.append(g4)

    # Gate 5: Repository checks — syntax is valid
    g5 = gate_5_repository_checks(fixed_source)
    gates.append(g5)

    # Calculate overall result
    passed_gates = sum(1 for g in gates if g.passed)
    total_gates = len(gates)
    confidence = passed_gates / total_gates if total_gates > 0 else 0.0

    return FixVerification(
        finding_id="",
        gates=gates,
        overall_passed=passed_gates >= 4,  # Need at least 4/5 gates
        overall_confidence=confidence,
    )


def gate_1_applicability(
    original: str,
    fixed: str,
) -> VerificationGate:
    """Gate 1: Did the fix actually change something?"""
    if original == fixed:
        return VerificationGate(
            gate="applicability",
            passed=False,
            reason="Fix did not change the source code",
        )

    # Count changed lines
    orig_lines = set(original.splitlines())
    fix_lines = set(fixed.splitlines())
    added = fix_lines - orig_lines
    removed = orig_lines - fix_lines

    return VerificationGate(
        gate="applicability",
        passed=True,
        reason=f"Fix changed {len(added)} lines added, {len(removed)} removed",
    )


def gate_2_security_closure(
    fixed_source: str,
    rule: str,
    line: int,
) -> VerificationGate:
    """Gate 2: Is the vulnerable pattern gone from the fixed code?"""
    # Map rules to patterns that should be absent
    dangerous_patterns = {
        "sql-injection": [r'f["\'].*SELECT.*WHERE', r'\.format\(.*SELECT'],
        "subprocess-shell-true": [r'shell\s*=\s*True'],
        "use-of-eval": [r'(?<!\w)eval\('],
        "use-of-exec": [r'(?<!\w)exec\('],
        "hardcoded-secret": [r'(?i)(password|secret|token)\s*=\s*["\'][^"\']{8,}'],
        "unsafe-deserialization": [r'pickle\.loads?\('],
        "jwt-none-algorithm": [r'algorithms\s*=\s*\[\s*["\']none["\']\s*\]'],
        "bare-except": [r'^\s*except\s*:\s*$'],
        "except-pass": [r'except.*:\s*\n\s*pass'],
    }

    patterns = dangerous_patterns.get(rule, [])
    if not patterns:
        return VerificationGate(
            gate="security_closure",
            passed=True,
            reason=f"No pattern check defined for rule '{rule}'",
        )

    lines = fixed_source.splitlines()
    target_line = lines[line - 1] if line <= len(lines) else ""

    for pattern in patterns:
        if re.search(pattern, target_line):
            return VerificationGate(
                gate="security_closure",
                passed=False,
                reason=f"Dangerous pattern still present at line {line}: {pattern}",
            )

    return VerificationGate(
        gate="security_closure",
        passed=True,
        reason=f"Vulnerable pattern for '{rule}' not found in fixed code",
    )


def gate_3_bypass_review(
    original: str,
    fixed: str,
    rule: str,
) -> VerificationGate:
    """Gate 3: Does the fix introduce new issues?"""
    issues = []

    # Check for new eval/exec introduced
    orig_eval_count = original.count("eval(") + original.count("exec(")
    fix_eval_count = fixed.count("eval(") + fixed.count("exec(")
    if fix_eval_count > orig_eval_count:
        issues.append("Fix introduced new eval/exec calls")

    # Check for new subprocess calls
    orig_subprocess = original.count("subprocess.")
    fix_subprocess = fixed.count("subprocess.")
    if fix_subprocess > orig_subprocess:
        issues.append("Fix introduced new subprocess calls")

    # Check for new shell=True
    orig_shell = original.count("shell=True")
    fix_shell = fixed.count("shell=True")
    if fix_shell > orig_shell:
        issues.append("Fix introduced new shell=True")

    if issues:
        return VerificationGate(
            gate="bypass_review",
            passed=False,
            reason="; ".join(issues),
        )

    return VerificationGate(
        gate="bypass_review",
        passed=True,
        reason="No new security issues introduced by fix",
    )


def gate_4_preserved_behavior(
    original: str,
    fixed: str,
) -> VerificationGate:
    """Gate 4: Does the fix preserve legitimate behavior?"""
    # Check that function signatures are preserved
    orig_funcs = set(re.findall(r'def (\w+)\(', original))
    fix_funcs = set(re.findall(r'def (\w+)\(', fixed))

    removed_funcs = orig_funcs - fix_funcs
    if removed_funcs:
        return VerificationGate(
            gate="preserved_behavior",
            passed=False,
            reason=f"Functions removed: {removed_funcs}",
        )

    # Check that class definitions are preserved
    orig_classes = set(re.findall(r'class (\w+)', original))
    fix_classes = set(re.findall(r'class (\w+)', fixed))

    removed_classes = orig_classes - fix_classes
    if removed_classes:
        return VerificationGate(
            gate="preserved_behavior",
            passed=False,
            reason=f"Classes removed: {removed_classes}",
        )

    return VerificationGate(
        gate="preserved_behavior",
        passed=True,
        reason="Function and class signatures preserved",
    )


def gate_5_repository_checks(
    fixed_source: str,
) -> VerificationGate:
    """Gate 5: Is the fixed code syntactically valid?"""
    try:
        ast.parse(fixed_source)
        return VerificationGate(
            gate="repository_checks",
            passed=True,
            reason="Fixed code parses successfully",
        )
    except SyntaxError as e:
        return VerificationGate(
            gate="repository_checks",
            passed=False,
            reason=f"Syntax error in fixed code: {e}",
        )


def generate_fix_suggestion(
    source: str,
    rule: str,
    line: int,
) -> dict | None:
    """Generate a concrete fix suggestion for a finding.

    Returns a dict with fix_before/fix_after or None if no fix can be generated.
    """
    lines = source.splitlines()
    if line < 1 or line > len(lines):
        return None

    target_line = lines[line - 1]
    indent = len(target_line) - len(target_line.lstrip())
    indent_str = " " * indent

    fixes = {
        "sql-injection": {
            "pattern": r'f["\'].*SELECT.*WHERE.*\{(\w+)\}',
            "replace": lambda m: f'{indent_str}cursor.execute("SELECT * FROM users WHERE id = ?", ({m.group(1) if m else "param"},))',
        },
        "subprocess-shell-true": {
            "pattern": r'shell\s*=\s*True',
            "replace": lambda m: target_line.replace("shell=True", "shell=False"),
        },
        "use-of-eval": {
            "pattern": r'eval\((.+)\)',
            "replace": lambda m: target_line.replace("eval(", "ast.literal_eval("),
        },
        "bare-except": {
            "pattern": r'except\s*:',
            "replace": lambda m: target_line.replace("except:", "except Exception:"),
        },
        "except-pass": {
            "pattern": None,
            "replace": lambda m: target_line.replace("pass", "raise"),
        },
        "comparison-to-none": {
            "pattern": r'== None',
            "replace": lambda m: target_line.replace("== None", "is None"),
        },
        "comparison-to-none-ne": {
            "pattern": r'!= None',
            "replace": lambda m: target_line.replace("!= None", "is not None"),
        },
        "mutable-default-argument": {
            "pattern": r'def (\w+)\((.+)=\[\]',
            "replace": lambda m: target_line.replace("=[]", "=None"),
        },
        "jwt-none-algorithm": {
            "pattern": r'algorithms=\["none"\]',
            "replace": lambda m: target_line.replace('algorithms=["none"]', 'algorithms=["HS256"]'),
        },
    }

    fix_info = fixes.get(rule)
    if not fix_info:
        return None

    fixed_line = fix_info["replace"](None)

    return {
        "file": "",  # to be filled by caller
        "start_line": line,
        "end_line": line,
        "fix_before": target_line,
        "fix_after": fixed_line,
        "label": f"Fix for {rule}",
    }
