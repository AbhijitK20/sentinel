# Twitter/X Thread

**Tweet 1 (Main):**
I built a code review tool that generates proof for every finding.

Not "potential SQL injection" — actual reproduction tests that prove the bug is real.

Open source. Rust + Python. 41 rules.

GitHub: https://github.com/AbhijitK20/sentinel

🧵

**Tweet 2:**
What makes Sentinel different:

1. Every finding comes with a reproduction test
2. 5-gate fix verification proves your fix works
3. CVSS auto-calculation
4. SARIF output for GitHub Security tab
5. 0.8s on CPython stdlib (vs 45s for Pylint)

**Tweet 3:**
Example output:

✗ SQL INJECTION (error, 95% confidence)
Line 6: f-string SQL query

Evidence:
  query = f"SELECT * FROM users WHERE id = {user_id}"
  # Returns ALL rows — injection confirmed

Fix: cursor.execute("...WHERE id = ?", (user_id,))

**Tweet 4:**
41 rules across 5 categories:

🔒 Security (15): SQLi, shell injection, eval, secrets, JWT, SSRF
🤖 AI/ML (7): Prompt injection, LLM output, MCP tool poisoning
✅ Correctness (10): Resources, defaults, unreachable code
📋 Compliance (5): HIPAA, SOC2, GDPR, PCI, SOX
🛡️ Anti-Cheat (4): noqa evasion, dynamic imports

**Tweet 5:**
Tech stack:

• Rust core (PyO3) for speed
• Python CLI (Typer + Rich) for UX
• Tree-sitter for AST parsing
• SHA-256 for evidence integrity
• SARIF for tool integration

Install: pip install sentinel-code-review

**Tweet 6:**
Try it:
```
pip install sentinel-code-review
sentinel scan ./my-project
```

GitHub: https://github.com/AbhijitK20/sentinel

Feedback welcome! 🙏
