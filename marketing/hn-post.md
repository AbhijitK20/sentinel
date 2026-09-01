# Hacker News Post

**Title:** Show HN: Sentinel – Code review that proves it's right

**URL:** https://github.com/AbhijitK20/sentinel

**Body:**

Sentinel is a code review tool that generates proof for every finding. Unlike traditional scanners that give you "potential SQL injection," Sentinel gives you a reproduction test that proves the bug is real.

Key features:
- 41 rules across security, AI/ML, compliance, and anti-cheat categories
- Every finding includes a behavioral proof (reproduction test)
- 5-gate fix verification (applicability, security closure, bypass review, preserved behavior, syntax)
- CVSS 3.1 auto-calculation
- SARIF output for GitHub Security tab
- Rust core via PyO3 (0.8s on CPython stdlib vs 45s for Pylint)

Built with Rust (analysis engine) + Python (CLI). Open source under MIT.

GitHub: https://github.com/AbhijitK20/sentinel
