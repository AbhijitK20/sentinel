# Reddit Post for r/selfhosted

**Title:** I built a code review tool that generates proof for every finding — open source

**Body:**

Hey r/selfhosted!

I've been working on a security tool called [Sentinel](https://github.com/AbhijitK20/sentinel) — a code review engine that doesn't just find bugs, it **proves** they're real.

## What makes it different

Most security scanners give you "potential SQL injection on line 42." Sentinel gives you:

```
✗ SQL INJECTION (error, 95% confidence)
  Line 6: Variable 'query' contains f-string SQL

  Evidence (behavioral):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    # Returns ALL rows — injection confirmed

  Fix: cursor.execute("...WHERE id = ?", (user_id,))
```

Every finding comes with:
- **Reproduction test** proving the bug exists
- **Fix suggestion** with before/after code
- **CVSS score** auto-calculated
- **Confidence level** based on 5 verification gates

## Features

- 41 analysis rules (security, AI/ML, compliance, anti-cheat)
- Rust core for speed (0.8s on CPython stdlib vs 45s for Pylint)
- SARIF output for GitHub Security tab
- GitHub Action, VS Code extension, pre-commit hooks
- Docker support

## Tech stack

- Rust (PyO3) for the analysis engine
- Python (Typer + Rich) for the CLI
- Tree-sitter for AST parsing
- SHA-256 for evidence integrity

## Links

- GitHub: https://github.com/AbhijitK20/sentinel
- PyPI: `pip install sentinel-code-review`

Would love feedback from the community!
