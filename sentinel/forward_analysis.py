"""Attacker-first forward analysis module.

Inspired by VulnHunter's approach: trace from attacker-accessible entry points
forward to dangerous sinks, not the other way around.

Key insight: Traditional SAST starts at sinks (eval, SQL, subprocess) and searches
backward for an attacker. VulnHunter starts at entry points (APIs, user input,
file uploads) and traces forward to prove an attacker can reach a sink.

This module implements the 5 hard gates from VulnHunter for false positive elimination.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class EntryType(Enum):
    """Types of attacker-accessible entry points."""

    HTTP_PARAM = "http_param"
    CLI_ARG = "cli_arg"
    FILE_READ = "file_read"
    ENV_VAR = "env_var"
    DB_READ = "db_read"
    MESSAGE_QUEUE = "message_queue"
    WEBSOCKET = "websocket"
    STDIN = "stdin"
    TEMPLATE = "template"
    COOKIE = "cookie"
    HEADER = "header"


class SinkType(Enum):
    """Types of dangerous sinks."""

    SQL_EXEC = "sql_exec"
    OS_COMMAND = "os_command"
    CODE_EXEC = "code_exec"
    FILE_WRITE = "file_write"
    FILE_READ_UNTRUSTED = "file_read_untrusted"
    HTTP_REQUEST = "http_request"
    TEMPLATE_RENDER = "template_render"
    DESERIALIZATION = "deserialization"
    RESPONSE_RENDER = "response_render"
    REDIRECT = "redirect"


class GateResult(Enum):
    """Result of a hard gate check."""

    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


@dataclass
class Entry:
    """An attacker-accessible entry point."""

    name: str
    entry_type: EntryType
    file: str
    line: int
    trust_level: float = 0.0  # 0.0 = fully untrusted, 1.0 = fully trusted
    description: str = ""


@dataclass
class Sink:
    """A dangerous sink operation."""

    name: str
    sink_type: SinkType
    file: str
    line: int
    description: str = ""


@dataclass
class TracePath:
    """A path from entry to sink."""

    entry: Entry
    sink: Sink
    intermediate_vars: list[str] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)
    files_traversed: list[str] = field(default_factory=list)


@dataclass
class GateCheck:
    """Result of a single gate check."""

    gate: str
    result: GateResult
    reason: str = ""
    evidence: str = ""


@dataclass
class FindingCandidate:
    """A candidate finding before gate verification."""

    entry: Entry
    sink: Sink
    trace: TracePath
    gates: list[GateCheck] = field(default_factory=list)
    severity: str = "medium"
    confidence: float = 0.5

    @property
    def passed_all_gates(self) -> bool:
        return all(g.result == GateResult.PASS for g in self.gates)

    @property
    def gate_failures(self) -> list[GateCheck]:
        return [g for g in self.gates if g.result == GateResult.FAIL]


# ============================================================================
# ENTRY POINT DETECTION
# ============================================================================

# Patterns that indicate attacker-accessible entry points
ENTRY_PATTERNS = {
    EntryType.HTTP_PARAM: [
        "request.args.get", "request.form.get", "request.json",
        "request.args[", "request.form[", "request.json[",
        "request.values.get", "request.values[",
        "request.files.get", "request.files[",
        "request.cookies.get", "request.cookies[",
        "request.headers.get", "request.headers[",
        "QueryParams", "Form", "Body", "Header",
        "Depends(",  # FastAPI/Starlette
    ],
    EntryType.CLI_ARG: [
        "sys.argv", "argparse", "click.option", "click.argument",
        "typer.Option", "typer.Argument", "input(",
    ],
    EntryType.FILE_READ: [
        "open(", "Path(", "pathlib",
        "read_file", "read_bytes", "read_text",
    ],
    EntryType.ENV_VAR: [
        "os.environ.get", "os.environ[", "os.getenv",
        "dotenv", "environ",
    ],
    EntryType.DB_READ: [
        ".query(", ".execute(", "cursor.fetchone",
        "cursor.fetchall", "cursor.fetchmany",
        "db.get(", "cache.get(",
    ],
    EntryType.MESSAGE_QUEUE: [
        "consume(", "receive(", "get_message",
        "poll(", "recv(",
    ],
    EntryType.WEBSOCKET: [
        "websocket.receive", "ws.recv", "await ws",
        "socket.recv",
    ],
    EntryType.TEMPLATE: [
        "render_template_string", "render_template",
        "Template(", "Jinja2",
    ],
}

# Patterns that indicate dangerous sinks
SINK_PATTERNS = {
    SinkType.SQL_EXEC: [
        "cursor.execute", "db.execute", "session.execute",
        "connection.execute", "engine.execute",
        ".raw(", ".extra(",
    ],
    SinkType.OS_COMMAND: [
        "os.system", "os.popen", "subprocess.run",
        "subprocess.call", "subprocess.Popen",
        "subprocess.check_output", "subprocess.check_call",
        "os.execl", "os.execv",
    ],
    SinkType.CODE_EXEC: [
        "eval(", "exec(", "compile(",
        "execfile(", "__import__(",
    ],
    SinkType.FILE_WRITE: [
        "open(",  # with write mode
        ".write(", ".writelines(",
    ],
    SinkType.HTTP_REQUEST: [
        "requests.get", "requests.post", "requests.put",
        "requests.delete", "httpx.get", "httpx.post",
        "urllib.request.urlopen", "aiohttp.get",
    ],
    SinkType.TEMPLATE_RENDER: [
        "render_template_string", "render_template",
        "Template(", "format_string",
    ],
    SinkType.DESERIALIZATION: [
        "pickle.load", "pickle.loads",
        "yaml.load", "yaml.unsafe_load",
        "marshal.load", "marshal.loads",
        "shelve.open",
    ],
    SinkType.RESPONSE_RENDER: [
        "return ", "Response(", "jsonify(",
        "make_response(",
    ],
    SinkType.REDIRECT: [
        "redirect(", "location =",
        "301", "302", "307", "308",
    ],
}

# Sanitizer patterns
SANITIZER_PATTERNS = [
    "html.escape", "bleach.clean", "markupsafe.escape",
    "shlex.quote", "pipes.quote",
    "os.path.realpath", "os.path.abspath",
    "parameterized", "placeholder",
    "int(", "float(",  # type coercion as partial sanitizer
    "json.loads",  # safe deserialization
    "yaml.safe_load",
    "ast.literal_eval",  # safe eval
]


def detect_entries(source: str, filepath: str) -> list[Entry]:
    """Detect attacker-accessible entry points in source code."""
    entries: list[Entry] = []
    lines = source.splitlines()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        for entry_type, patterns in ENTRY_PATTERNS.items():
            for pattern in patterns:
                if pattern in stripped:
                    name = _extract_var_name(stripped, pattern)
                    entries.append(
                        Entry(
                            name=name,
                            entry_type=entry_type,
                            file=filepath,
                            line=i,
                            description=f"Entry point: {pattern}",
                        )
                    )
                    break  # one match per line per type

    return entries


def detect_sinks(source: str, filepath: str) -> list[Sink]:
    """Detect dangerous sinks in source code."""
    sinks: list[Sink] = []
    lines = source.splitlines()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        for sink_type, patterns in SINK_PATTERNS.items():
            for pattern in patterns:
                if pattern in stripped:
                    name = _extract_var_name(stripped, pattern)
                    sinks.append(
                        Sink(
                            name=name,
                            sink_type=sink_type,
                            file=filepath,
                            line=i,
                            description=f"Sink: {pattern}",
                        )
                    )
                    break

    return sinks


def detect_sanitizers(source: str) -> list[str]:
    """Detect sanitizer functions used in source code."""
    found = []
    for pattern in SANITIZER_PATTERNS:
        if pattern in source:
            found.append(pattern)
    return found


def trace_entry_to_sink(
    entry: Entry,
    sink: Sink,
    source: str,
) -> TracePath | None:
    """Trace if an entry's data flows to a sink (simplified forward trace)."""
    lines = source.splitlines()
    entry_line_idx = entry.line - 1
    sink_line_idx = sink.line - 1

    if entry_line_idx >= sink_line_idx:
        return None  # sink is before entry

    # Simple forward trace: check if entry variable appears between entry and sink
    entry_var = entry.name
    intermediate: list[str] = []
    files = [entry.file]

    for i in range(entry_line_idx + 1, sink_line_idx):
        if i < len(lines):
            line = lines[i]
            if entry_var in line:
                intermediate.append(f"L{i+1}")

    if not intermediate and entry_var not in lines[sink_line_idx]:
        return None  # no connection found

    # Check for sanitizers along the path
    path_source = "\n".join(lines[entry_line_idx:sink_line_idx])
    sanitizers = detect_sanitizers(path_source)

    return TracePath(
        entry=entry,
        sink=sink,
        intermediate_vars=intermediate,
        sanitizers=sanitizers,
        files_traversed=files,
    )


# ============================================================================
# THE 5 HARD GATES (from VulnHunter)
# ============================================================================


def gate_0_intentional_design(candidate: FindingCandidate) -> GateCheck:
    """Gate 0: Is this the application doing what it's designed to do?

    Eliminates intentional features (reverse proxies, caller-supplied keys).
    Decision test: 'If I removed this input, would the application lose an
    intentional feature?'
    """
    # If the entry is in a function named 'proxy', 'forward', 'redirect'
    # it might be intentional behavior
    entry_line = candidate.trace.entry.description.lower()
    if any(w in entry_line for w in ["proxy", "forward", "redirect", "relay"]):
        return GateCheck(
            gate="0_intentional_design",
            result=GateResult.FAIL,
            reason="Appears to be intentional proxy/forward behavior",
        )

    return GateCheck(
        gate="0_intentional_design",
        result=GateResult.PASS,
        reason="Not identified as intentional design",
    )


def gate_1_reachability(
    candidate: FindingCandidate,
    full_source: str,
) -> GateCheck:
    """Gate 1: Is the code reachable?

    Grep for ALL call sites across production code.
    Route registration does NOT equal code reachability.
    Must exhaust ALL callers.
    """
    entry_var = candidate.trace.entry.name
    sink_line = candidate.sink.line

    # Check if the entry variable is actually used before the sink
    lines = full_source.splitlines()
    usage_count = 0
    for i, line in enumerate(lines):
        if i + 1 == sink_line:
            break
        if entry_var in line and not line.strip().startswith("#"):
            usage_count += 1

    if usage_count == 0:
        return GateCheck(
            gate="1_reachability",
            result=GateResult.FAIL,
            reason=f"Entry variable '{entry_var}' not found before sink",
        )

    return GateCheck(
        gate="1_reachability",
        result=GateResult.PASS,
        reason=f"Entry variable used {usage_count} time(s) before sink",
    )


def gate_2a_attacker_controlled(
    candidate: FindingCandidate,
) -> GateCheck:
    """Gate 2a: Is the input attacker-controlled?

    Verify origin from forward trace: user input vs framework/internal metadata.
    Must verify indirect control through stores (multi-hop tracing).
    """
    entry = candidate.trace.entry

    # Fully trusted sources are not attacker-controlled
    if entry.trust_level > 0.8:
        return GateCheck(
            gate="2a_attacker_controlled",
            result=GateResult.FAIL,
            reason=f"Entry has high trust level ({entry.trust_level})",
        )

    # Entry types that are always attacker-controlled
    attacker_controlled_types = {
        EntryType.HTTP_PARAM,
        EntryType.CLI_ARG,
        EntryType.FILE_READ,
        EntryType.MESSAGE_QUEUE,
        EntryType.WEBSOCKET,
        EntryType.STDIN,
        EntryType.COOKIE,
        EntryType.HEADER,
    }

    if entry.entry_type in attacker_controlled_types:
        return GateCheck(
            gate="2a_attacker_controlled",
            result=GateResult.PASS,
            reason=f"Entry type '{entry.entry_type.value}' is attacker-controlled",
        )

    # Env vars and DB reads might be attacker-controlled (indirect)
    if entry.entry_type in {EntryType.ENV_VAR, EntryType.DB_READ}:
        return GateCheck(
            gate="2a_attacker_controlled",
            result=GateResult.UNKNOWN,
            reason=f"Entry type '{entry.entry_type.value}' requires multi-hop tracing",
        )

    return GateCheck(
        gate="2a_attacker_controlled",
        result=GateResult.UNKNOWN,
        reason="Requires manual verification of trust level",
    )


def gate_2b_sanitization(
    candidate: FindingCandidate,
) -> GateCheck:
    """Gate 2b: Is there effective sanitization between source and sink?

    Empirically verify what the defense does -- do NOT rely on training knowledge.
    For EVERY defense: read source code OR treat as ineffective.
    Verify defense matches context (HTML sanitizer on URL sink = NOT effective).
    """
    sanitizers = candidate.trace.sanitizers

    if not sanitizers:
        return GateCheck(
            gate="2b_sanitization",
            result=GateResult.PASS,
            reason="No sanitizers found between entry and sink",
        )

    # Context-aware sanitizer validation
    sink_type = candidate.sink.sink_type
    sanitizer_effectiveness = {
        SinkType.SQL_EXEC: ["parameterized", "placeholder"],
        SinkType.OS_COMMAND: ["shlex.quote", "pipes.quote"],
        SinkType.CODE_EXEC: ["ast.literal_eval"],
        SinkType.HTTP_REQUEST: [],  # URL validation is needed, not sanitization
        SinkType.TEMPLATE_RENDER: ["html.escape", "bleach.clean", "markupsafe.escape"],
        SinkType.DESERIALIZATION: ["yaml.safe_load", "json.loads"],
    }

    effective = sanitizer_effectiveness.get(sink_type, [])
    found_effective = [s for s in sanitizers if any(e in s for e in effective)]

    if found_effective:
        return GateCheck(
            gate="2b_sanitization",
            result=GateResult.FAIL,
            reason=f"Effective sanitizers found: {found_effective}",
        )

    return GateCheck(
        gate="2b_sanitization",
        result=GateResult.PASS,
        reason=f"Sanitizers present but not effective for {sink_type.value}: {sanitizers}",
    )


def gate_3_new_capability(
    candidate: FindingCandidate,
) -> GateCheck:
    """Gate 3: Does the attacker gain a NEW capability?

    Must AFFIRMATIVELY demonstrate what new outcome the attacker achieves.
    'I could not find a path that gives the same outcome' is NOT sufficient.
    """
    sink_type = candidate.sink.sink_type

    # Dangerous sinks always grant new capabilities
    high_capability_sinks = {
        SinkType.SQL_EXEC,
        SinkType.OS_COMMAND,
        SinkType.CODE_EXEC,
        SinkType.DESERIALIZATION,
    }

    if sink_type in high_capability_sinks:
        return GateCheck(
            gate="3_new_capability",
            result=GateResult.PASS,
            reason=f"Sink type '{sink_type.value}' grants significant capability",
        )

    return GateCheck(
        gate="3_new_capability",
        result=GateResult.UNKNOWN,
        reason=f"Requires manual assessment of capability gain for {sink_type.value}",
    )


def verify_candidate(
    candidate: FindingCandidate,
    full_source: str,
) -> FindingCandidate:
    """Run all 5 hard gates on a candidate finding."""
    candidate.gates = [
        gate_0_intentional_design(candidate),
        gate_1_reachability(candidate, full_source),
        gate_2a_attacker_controlled(candidate),
        gate_2b_sanitization(candidate),
        gate_3_new_capability(candidate),
    ]

    # Calculate confidence based on gate results
    pass_count = sum(1 for g in candidate.gates if g.result == GateResult.PASS)
    fail_count = sum(1 for g in candidate.gates if g.result == GateResult.FAIL)
    total = len(candidate.gates)

    candidate.confidence = pass_count / total if total > 0 else 0.0

    # Severity based on sink type and gate results
    if candidate.sink.sink_type in {SinkType.SQL_EXEC, SinkType.OS_COMMAND, SinkType.CODE_EXEC}:
        candidate.severity = "error"
    elif candidate.sink.sink_type in {SinkType.DESERIALIZATION, SinkType.HTTP_REQUEST}:
        candidate.severity = "warning"
    else:
        candidate.severity = "info"

    return candidate


def analyze_source(filepath: str, source: str) -> list[FindingCandidate]:
    """Run attacker-first forward analysis on a source file.

    1. Detect all entry points
    2. Detect all sinks
    3. Trace entry → sink paths
    4. Apply 5 hard gates to filter false positives
    """
    entries = detect_entries(source, filepath)
    sinks = detect_sinks(source, filepath)

    candidates: list[FindingCandidate] = []

    for entry in entries:
        for sink in sinks:
            trace = trace_entry_to_sink(entry, sink, source)
            if trace is None:
                continue

            candidate = FindingCandidate(
                entry=entry,
                sink=sink,
                trace=trace,
            )

            candidate = verify_candidate(candidate, source)
            candidates.append(candidate)

    # Filter: only keep candidates that passed most gates
    verified = [c for c in candidates if c.confidence >= 0.4]

    # Sort by confidence (highest first)
    verified.sort(key=lambda c: c.confidence, reverse=True)

    return verified


def _extract_var_name(line: str, pattern: str) -> str:
    """Extract variable name from a line containing a pattern."""
    # Simple heuristic: look for assignment before the pattern
    if "=" in line:
        left = line.split("=")[0].strip()
        if left and not left.startswith(("if", "while", "for", "def", "class")):
            return left

    # Look for function call target
    idx = line.find(pattern)
    if idx > 0:
        before = line[:idx].strip()
        if before:
            return before.split()[-1] if before.split() else pattern

    return pattern
