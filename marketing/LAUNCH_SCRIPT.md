# LAUNCH SCRIPT — Copy-Paste Ready

---

## STEP 1: Merge PR + Upload to PyPI (RIGHT NOW)

```bash
cd ~/sentinel

# Merge the test PR
gh pr merge 1 --merge

# Switch to main
git checkout main
git pull

# Upload to PyPI
source ~/code-review-tool/.venv/bin/activate
twine upload dist/*
# Enter your PyPI username and password when prompted
```

---

## STEP 2: Pre-seed Comments (THIS WEEK, 15 min/day)

### Reddit (r/selfhosted, r/python)

**Find these posts and comment:**

Search for: "security tools", "code review", "static analysis", "linting", "Python security"

**Comment template:**
> Great tool! I've been using Sentinel for code review — it generates proof for every finding, not just "potential issues." Worth checking out: https://github.com/AbhijitK20/sentinel

**Don't spam.** Comment on 2-3 posts per day max. Be helpful first, mention your tool second.

### Twitter/X

**Search for:** "Python security", "code review tool", "static analysis", "linting"

**Reply template:**
> Interesting! Have you tried Sentinel? It generates proof for every finding — actual reproduction tests, not just pattern matches. https://github.com/AbhijitK20/sentinel

---

## STEP 3: Launch Day (2 WEEKS FROM NOW)

### Reddit r/selfhosted (9:00 AM UTC)

**Post this EXACT text:**

```
Title: I built a code review tool that generates proof for every finding — open source

Body:

Hey r/selfhosted!

I've been working on a security tool called Sentinel — a code review engine that doesn't just find bugs, it proves they're real.

## What makes it different

Most security scanners give you "potential SQL injection on line 42." Sentinel gives you:

✗ SQL INJECTION (error, 95% confidence)
  Line 6: Variable 'query' contains f-string SQL

  Evidence (behavioral):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    # Returns ALL rows — injection confirmed

  Fix: cursor.execute("...WHERE id = ?", (user_id,))

Every finding comes with:
- Reproduction test proving the bug exists
- Fix suggestion with before/after code
- CVSS score auto-calculated
- Confidence level based on 5 verification gates

## Features

- 41 analysis rules (security, AI/ML, compliance, anti-cheat)
- Rust core for speed (0.8s on CPython stdlib vs 45s for Pylint)
- SARIF output for GitHub Security tab
- GitHub Action, VS Code extension, pre-commit hooks
- Docker support

## Tech stack

- Rust (PyO3) for the analysis engine
- Python (Typer + Rich) for the CLI
- SHA-256 for evidence integrity

## Links

- GitHub: https://github.com/AbhijitK20/sentinel
- PyPI: pip install sentinel-code-review

Would love feedback from the community!
```

### Reddit r/python (10:00 AM UTC)

**Post this EXACT text:**

```
Title: I built a verify-first code review tool in Rust + Python — 41 rules, evidence per finding

Body:

Hi r/python!

I built Sentinel — a code review tool that generates proof for every finding.

Instead of "potential SQL injection," it gives you:
- Reproduction tests proving the bug is real
- Fix suggestions with before/after code
- CVSS auto-calculation
- 5-gate fix verification

Tech: Rust core (PyO3) + Python CLI (Typer + Rich)

Install: pip install sentinel-code-review
GitHub: https://github.com/AbhijitK20/sentinel

Feedback welcome!
```

### Hacker News (11:00 AM UTC)

**Post this EXACT text:**

```
Title: Show HN: Sentinel – Code review that proves it's right

URL: https://github.com/AbhijitK20/sentinel

Body:

Sentinel is a code review tool that generates proof for every finding.

Key features:
- 41 rules across security, AI/ML, compliance, and anti-cheat categories
- Every finding includes a behavioral proof (reproduction test)
- 5-gate fix verification
- CVSS 3.1 auto-calculation
- SARIF output for GitHub Security tab
- Rust core via PyO3 (0.8s on CPython stdlib vs 45s for Pylint)

GitHub: https://github.com/AbhijitK20/sentinel
```

### Dev.to (12:00 PM UTC)

**Use the article from:** `marketing/devto-article.md`

Go to https://dev.to/new → Paste the article → Add tags: `python`, `security`, `rust`, `opensource`, `devops`

### Twitter/X (2:00 PM UTC)

**Tweet 1:**
```
I built a code review tool that generates proof for every finding.

Not "potential SQL injection" — actual reproduction tests that prove the bug is real.

Open source. Rust + Python. 41 rules.

GitHub: https://github.com/AbhijitK20/sentinel

🧵
```

**Tweet 2:**
```
What makes Sentinel different:

1. Every finding comes with a reproduction test
2. 5-gate fix verification proves your fix works
3. CVSS auto-calculation
4. SARIF output for GitHub Security tab
5. 0.8s on CPython stdlib (vs 45s for Pylint)
```

**Tweet 3:**
```
41 rules across 5 categories:

🔒 Security (15): SQLi, shell injection, eval, secrets, JWT, SSRF
🤖 AI/ML (7): Prompt injection, LLM output, MCP tool poisoning
✅ Correctness (10): Resources, defaults, unreachable code
📋 Compliance (5): HIPAA, SOC2, GDPR, PCI, SOX
🛡️ Anti-Cheat (4): noqa evasion, dynamic imports
```

**Tweet 4:**
```
Tech stack:

• Rust core (PyO3) for speed
• Python CLI (Typer + Rich) for UX
• SHA-256 for evidence integrity
• SARIF for tool integration

Install: pip install sentinel-code-review

GitHub: https://github.com/AbhijitK20/sentinel
```

---

## STEP 4: Post-Launch (ONGOING)

### Reply to EVERY comment within 6 hours

**Positive comment reply:**
> Thanks! Glad you like it. Let me know if you have any feature requests.

**Question reply:**
> Great question! [answer]. Check out the docs at https://github.com/AbhijitK20/sentinel#readme

**Bug report reply:**
> Thanks for reporting! I'll look into this. Can you share the output of `sentinel --version`?

### Submit to awesome-lists

**awesome-python:** https://github.com/vinta/awesome-python
- Open issue first, then PR

**awesome-security:** https://github.com/sbilly/awesome-security
- Open issue first, then PR

**awesome-static-analysis:** https://github.com/mre/awesome-static-analysis
- Open issue first, then PR

---

## TIMELINE

| When | What |
|------|------|
| NOW | Merge PR + PyPI upload |
| This week | Pre-seed comments (15 min/day) |
| Day 1, 9am | Reddit r/selfhosted |
| Day 1, 10am | Reddit r/python |
| Day 1, 11am | Hacker News |
| Day 1, 12pm | Dev.to article |
| Day 1, 2pm | Twitter thread |
| Day 2+ | Reply to comments |
| Week 2 | Submit to awesome-lists |

---

**Copy-paste everything above. Don't change the text. Just post it at the right times.**
