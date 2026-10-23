"""Severity helpers shared by the scanner and report generator."""
from dataclasses import dataclass
from typing import Literal

Severity = Literal["Critical", "High", "Medium", "Low", "Informational"]
Confidence = Literal["High", "Medium", "Low"]

@dataclass
class Finding:
    name: str
    severity: Severity
    confidence: Confidence
    evidence: str
    impact: str
    remediation: str

def finding(name: str, severity: Severity, evidence: str, impact: str, remediation: str,
            confidence: Confidence = "High") -> Finding:
    """Construct a consistent finding record."""
    return Finding(name, severity, confidence, evidence[:500], impact, remediation)
