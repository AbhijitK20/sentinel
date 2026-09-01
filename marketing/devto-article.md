# How I Built a Verify-First Code Review Engine in Rust + Python

Most security tools tell you what *might* be wrong. I wanted to build one that tells you what *is* wrong — and proves it.

## The Problem

I was tired of running security scanners and getting hundreds of false positives. "Potential SQL injection here" — but is it actually exploitable? "Hardcoded secret detected" — but it's just a placeholder.

I wanted a tool that:
1. Finds real vulnerabilities
2. Generates proof they're real
3. Suggests fixes
4. Verifies the fixes work

## The Solution: Sentinel

[Sentinel](https://github.com/AbhijitK20/sentinel) is a code review tool that generates **evidence** for every finding. It's built with a Rust core for speed and Python for flexibility.

### Key Features

- **41 analysis rules** across 5 categories (security, AI/ML, correctness, compliance, anti-cheat)
- **Evidence per finding** — reproduction tests that prove the bug is real
- **5-gate fix verification** — proves your fix actually works
- **CVSS auto-calculation** — scores every finding automatically
- **SARIF output** — integrates with GitHub Security tab

## Architecture

```
Rust Core (PyO3)
├── 41 analysis rules
├── SHA-256 evidence hashing
└── CVSS calculation

Python CLI (Typer + Rich)
├── 4 output formats (terminal, JSON, HTML, SARIF)
├── Fix verification
├── Counterevidence analysis
└── AI-powered suggestions
```

## Example Output

```bash
$ sentinel scan ./my-project

✗ SQL INJECTION
  [ERROR] sql-injection — Line 6
  Variable 'query' contains f-string SQL

  Evidence (behavioral):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    # Returns ALL rows — injection confirmed

  Fix: cursor.execute("...WHERE id = ?", (user_id,))
```

## Technical Deep Dive

### The Rust Core

I used PyO3 to expose Rust analysis rules to Python. Each rule is a function that takes source code and returns findings:

```rust
pub fn check_sql_injection(path: &str, source: &str) -> Vec<Finding> {
    // Pattern matching on source code
    // Returns findings with evidence
}
```

### Evidence Generation

Every finding includes a reproduction test:

```python
{
    "proof_type": "behavioral",
    "reproduction_code": "import sqlite3\n...",
    "expected_behavior": "Query returns only matching user",
    "actual_behavior": "F-string allows SQL injection"
}
```

### Fix Verification

Before suggesting a fix, Sentinel runs 5 gates:
1. **Applicability** — Does the fix change anything?
2. **Security closure** — Is the vulnerability gone?
3. **Bypass review** — Does the fix introduce new issues?
4. **Preserved behavior** — Does legitimate code still work?
5. **Repository checks** — Is the syntax valid?

## What I Learned

1. **Rust + Python is powerful** — Rust for speed, Python for flexibility
2. **Evidence changes everything** — When you prove a bug is real, developers actually fix it
3. **False positives kill adoption** — The counterevidence system reduces noise
4. **SARIF is the standard** — GitHub, GitLab, and other tools all consume it

## Try It

```bash
pip install sentinel-code-review
sentinel scan ./my-project
```

GitHub: https://github.com/AbhijitK20/sentinel

---

*Built with Rust, Python, and a lot of coffee.*
