"""CVSS 3.1 auto-calculation from vulnerability findings.

Based on Strix's CVSS calculation logic. Takes a breakdown of 8 metrics
and computes the CVSS score, severity, and vector string.
"""

from dataclasses import dataclass


@dataclass
class CVSSResult:
    """CVSS 3.1 calculation result."""

    score: float
    severity: str
    vector: str
    breakdown: dict[str, str]

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "severity": self.severity,
            "vector": self.vector,
            "breakdown": self.breakdown,
        }


# CVSS 3.1 metric weights
CVSS_WEIGHTS = {
    "attack_vector": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "attack_complexity": {"L": 0.77, "H": 0.44},
    "privileges_required": {
        "N": {"U": 0.85, "C": 0.85},
        "L": {"U": 0.62, "C": 0.68},
        "H": {"U": 0.27, "C": 0.50},
    },
    "user_interaction": {"N": 0.85, "R": 0.62},
    "scope": {"U": 1.0, "C": 1.08},
    "confidentiality": {"N": 0.0, "L": 0.22, "H": 0.56},
    "integrity": {"N": 0.0, "L": 0.22, "H": 0.56},
    "availability": {"N": 0.0, "L": 0.22, "H": 0.56},
}

# Valid values for each metric
CVSS_VALID = {
    "attack_vector": ["N", "A", "L", "P"],
    "attack_complexity": ["L", "H"],
    "privileges_required": ["N", "L", "H"],
    "user_interaction": ["N", "R"],
    "scope": ["U", "C"],
    "confidentiality": ["N", "L", "H"],
    "integrity": ["N", "L", "H"],
    "availability": ["N", "L", "H"],
}


def calculate_cvss(breakdown: dict[str, str]) -> CVSSResult:
    """Calculate CVSS 3.1 score from metric breakdown.

    Args:
        breakdown: Dict with keys: attack_vector, attack_complexity,
                  privileges_required, user_interaction, scope,
                  confidentiality, integrity, availability

    Returns:
        CVSSResult with score, severity, vector string
    """
    # Validate inputs
    for metric, valid in CVSS_VALID.items():
        val = breakdown.get(metric, "N")
        if val not in valid:
            raise ValueError(f"Invalid {metric}: {val}. Must be one of {valid}")

    # Calculate Impact Sub-Score (ISS)
    conf = CVSS_WEIGHTS["confidentiality"][breakdown["confidentiality"]]
    integ = CVSS_WEIGHTS["integrity"][breakdown["integrity"]]
    avail = CVSS_WEIGHTS["availability"][breakdown["availability"]]
    iss = 1.0 - ((1.0 - conf) * (1.0 - integ) * (1.0 - avail))

    # Impact
    scope = breakdown["scope"]
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    # Exploitability
    av = CVSS_WEIGHTS["attack_vector"][breakdown["attack_vector"]]
    ac = CVSS_WEIGHTS["attack_complexity"][breakdown["attack_complexity"]]
    ui = CVSS_WEIGHTS["user_interaction"][breakdown["user_interaction"]]
    pr = CVSS_WEIGHTS["privileges_required"][breakdown["privileges_required"]][scope]
    exploitability = 8.22 * av * ac * pr * ui

    # Base Score
    if impact <= 0:
        score = 0.0
    else:
        if scope == "U":
            score = min(impact + exploitability, 10.0)
        else:
            score = min(1.08 * (impact + exploitability), 10.0)

    # Round to nearest tenth
    score = round(score, 1)

    # Severity rating
    severity = _score_to_severity(score)

    # Build vector string
    vector = (
        f"CVSS:3.1/AV:{breakdown['attack_vector']}/"
        f"AC:{breakdown['attack_complexity']}/"
        f"PR:{breakdown['privileges_required']}/"
        f"UI:{breakdown['user_interaction']}/"
        f"S:{scope}/"
        f"C:{breakdown['confidentiality']}/"
        f"I:{breakdown['integrity']}/"
        f"A:{breakdown['availability']}"
    )

    return CVSSResult(
        score=score,
        severity=severity,
        vector=vector,
        breakdown=breakdown,
    )


def _score_to_severity(score: float) -> str:
    """Convert CVSS score to severity rating."""
    if score == 0.0:
        return "none"
    elif score <= 3.9:
        return "low"
    elif score <= 6.9:
        return "medium"
    elif score <= 8.9:
        return "high"
    else:
        return "critical"


def estimate_cvss_from_rule(rule: str) -> CVSSResult:
    """Estimate CVSS score from a sentinel rule ID.

    Uses common vulnerability patterns to estimate likely CVSS metrics.
    """
    estimates = {
        "sql-injection": {
            "attack_vector": "N", "attack_complexity": "L",
            "privileges_required": "N", "user_interaction": "N",
            "scope": "U", "confidentiality": "H", "integrity": "H",
            "availability": "H",
        },
        "subprocess-shell-true": {
            "attack_vector": "N", "attack_complexity": "L",
            "privileges_required": "N", "user_interaction": "N",
            "scope": "U", "confidentiality": "H", "integrity": "H",
            "availability": "H",
        },
        "use-of-eval": {
            "attack_vector": "N", "attack_complexity": "L",
            "privileges_required": "N", "user_interaction": "N",
            "scope": "U", "confidentiality": "H", "integrity": "H",
            "availability": "H",
        },
        "hardcoded-secret": {
            "attack_vector": "N", "attack_complexity": "L",
            "privileges_required": "N", "user_interaction": "N",
            "scope": "U", "confidentiality": "H", "integrity": "L",
            "availability": "N",
        },
        "prompt-injection": {
            "attack_vector": "N", "attack_complexity": "L",
            "privileges_required": "N", "user_interaction": "R",
            "scope": "U", "confidentiality": "H", "integrity": "H",
            "availability": "N",
        },
        "llm-output-eval": {
            "attack_vector": "N", "attack_complexity": "L",
            "privileges_required": "N", "user_interaction": "R",
            "scope": "U", "confidentiality": "H", "integrity": "H",
            "availability": "H",
        },
        "jwt-none-algorithm": {
            "attack_vector": "N", "attack_complexity": "L",
            "privileges_required": "N", "user_interaction": "N",
            "scope": "U", "confidentiality": "H", "integrity": "H",
            "availability": "N",
        },
        "bare-except": {
            "attack_vector": "L", "attack_complexity": "H",
            "privileges_required": "L", "user_interaction": "N",
            "scope": "U", "confidentiality": "L", "integrity": "L",
            "availability": "N",
        },
        "except-pass": {
            "attack_vector": "L", "attack_complexity": "H",
            "privileges_required": "L", "user_interaction": "N",
            "scope": "U", "confidentiality": "L", "integrity": "L",
            "availability": "N",
        },
        "comparison-to-none": {
            "attack_vector": "N", "attack_complexity": "H",
            "privileges_required": "N", "user_interaction": "N",
            "scope": "U", "confidentiality": "N", "integrity": "N",
            "availability": "N",
        },
    }

    # Try exact match, then partial match
    breakdown = estimates.get(rule)
    if not breakdown:
        for key in estimates:
            if key in rule:
                breakdown = estimates[key]
                break

    if not breakdown:
        # Default low-severity estimate
        breakdown = {
            "attack_vector": "L", "attack_complexity": "H",
            "privileges_required": "L", "user_interaction": "N",
            "scope": "U", "confidentiality": "N", "integrity": "N",
            "availability": "N",
        }

    return calculate_cvss(breakdown)
