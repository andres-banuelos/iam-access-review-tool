"""
findings.py — Dataclass that represents a single audit finding.

Each Finding maps directly to a row in the HTML report table.
Risk levels follow a simple High / Medium / Low taxonomy consistent
with Big 4 IT audit deliverables.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class RiskLevel(str, Enum):
    HIGH   = "High"
    MEDIUM = "Medium"
    LOW    = "Low"
    INFO   = "Informational"


class FindingCategory(str, Enum):
    OVERPRIVILEGED   = "Overprivileged Account"
    ORPHANED_ACCOUNT = "Orphaned Account"
    STALE_PERMISSION = "Stale Permission"
    EXCESSIVE_SP     = "Excessive Service Principal Permission"
    GUEST_ELEVATED   = "Elevated Guest Account"


@dataclass
class Finding:
    """A single access review finding."""
    category:      FindingCategory
    risk:          RiskLevel
    principal_name: str
    principal_id:   str
    detail:         str
    recommendation: str
    evidence:       str = ""            # supporting data (e.g. last sign-in date)
    cis_control:    Optional[str] = None  # optional CIS / NIST reference

    def to_dict(self) -> dict:
        return {
            "Category":       self.category.value,
            "Risk":           self.risk.value,
            "Principal":      self.principal_name,
            "Principal ID":   self.principal_id,
            "Detail":         self.detail,
            "Recommendation": self.recommendation,
            "Evidence":       self.evidence,
            "CIS Control":    self.cis_control or "",
        }
