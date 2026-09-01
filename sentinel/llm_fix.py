"""LLM-powered fix suggestion generator.

Uses the AI Interviewer's Gemini service pattern for multi-provider LLM support
with graceful fallback to heuristic-based suggestions.
"""

from __future__ import annotations

import os


class FixSuggestionEngine:
    """Generates AI-powered fix suggestions for code findings.

    Pattern from: ai-interviewer/ai-service/app/services/llm_service.py
    - Environment-driven config (LLM_PROVIDER, LLM_API_KEY, LLM_MODEL)
    - Graceful fallback to mock/heuristic on failure
    - Async-first design
    """

    def __init__(self) -> None:
        self.provider = os.getenv("SENTINEL_LLM_PROVIDER", "heuristic")
        self.api_key = os.getenv("SENTINEL_LLM_API_KEY", "")
        self.model = os.getenv("SENTINEL_LLM_MODEL", "gemini-2.0-flash")

    def generate_fix(self, source: str, finding: dict) -> str | None:
        """Generate a fix suggestion for a finding.

        Args:
            source: The full source code of the file
            finding: The finding dict with rule, message, line, etc.

        Returns:
            Fix suggestion string or None if generation fails
        """
        if self.provider == "heuristic" or not self.api_key:
            return self._heuristic_fix(finding)

        try:
            return self._llm_fix(source, finding)
        except Exception:
            return self._heuristic_fix(finding)

    def _llm_fix(self, source: str, finding: dict) -> str | None:
        """Generate fix using LLM API."""
        rule = finding.get("rule", "")
        message = finding.get("message", "")
        line = finding.get("line", 0)
        suggestion = finding.get("suggestion", "")

        prompt = f"""You are a Python security expert. Given this code finding, provide a specific, actionable fix.

Rule: {rule}
Issue: {message}
Line: {line}
Current suggestion: {suggestion}

Source code context (around line {line}):
```python
{self._get_context(source, line)}
```

Provide a concrete fix. Return ONLY the fixed code snippet, no explanation."""

        if self.provider == "gemini":
            return self._call_gemini(prompt)
        elif self.provider == "openai":
            return self._call_openai(prompt)

        return None

    def _call_gemini(self, prompt: str) -> str | None:
        """Call Google Gemini API (pattern from AI Interviewer)."""
        try:
            from google import genai

            client = genai.Client(api_key=self.api_key)
            response = client.models.generate_content(
                model=self.model,
                contents=prompt,
            )
            return response.text
        except Exception:
            return None

    def _call_openai(self, prompt: str) -> str | None:
        """Call OpenAI API."""
        try:
            from openai import OpenAI

            client = OpenAI(api_key=self.api_key)
            response = client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=500,
                temperature=0.1,
            )
            return response.choices[0].message.content
        except Exception:
            return None

    def _heuristic_fix(self, finding: dict) -> str | None:
        """Generate fix using pattern matching (no LLM needed)."""
        rule = finding.get("rule", "")

        fixes = {
            "sql-injection": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            "subprocess-shell-true": "subprocess.run(args, shell=False)",
            "use-of-eval": "ast.literal_eval(value)  # safe alternative to eval()",
            "use-of-exec": "import importlib; module = importlib.import_module(name)",
            "hardcoded-secret": "os.environ.get('SECRET_KEY')  # use environment variable",
            "unsafe-deserialization": "json.loads(data)  # safe alternative to pickle",
            "jwt-none-algorithm": "jwt.decode(token, key, algorithms=['HS256'])",
            "jwt-verification-disabled": "jwt.decode(token, key, algorithms=['HS256'])",
            "insecure-random": "secrets.token_hex(16)  # cryptographically secure",
            "bare-except": "except Exception:  # specify exception type",
            "except-pass": "except Exception as e: logging.error(e)  # log the error",
            "return-in-init": "# Remove return value — __init__ must return None",
            "comparison-to-none": "# Use 'is None' instead of '== None'",
            "mutable-default-argument": "def f(items=None): items = items or []",
            "unsafe-yaml-load": "yaml.safe_load(data)  # safe alternative",
            "path-traversal": "path = os.path.realpath(path); assert path.startswith(allowed_dir)",
            "debug-statement": "# Remove this line before production",
            "potential-ssrf": "url = validate_url(user_input);  # whitelist allowed URLs",
            "nosql-injection": "# Validate input types before passing to MongoDB",
            "dynamic-import": "# Use static imports at the top of the file",
        }

        return fixes.get(rule)

    @staticmethod
    def _get_context(source: str, line: int, context_lines: int = 5) -> str:
        """Get source code context around a line."""
        lines = source.splitlines()
        start = max(0, line - context_lines - 1)
        end = min(len(lines), line + context_lines)
        return "\n".join(f"{i+1}: {ln}" for i, ln in enumerate(lines[start:end], start=start))


# Singleton instance
_fix_engine: FixSuggestionEngine | None = None


def get_fix_engine() -> FixSuggestionEngine:
    """Get the global fix suggestion engine."""
    global _fix_engine
    if _fix_engine is None:
        _fix_engine = FixSuggestionEngine()
    return _fix_engine
