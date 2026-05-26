"""Finding models used by the analyzer and reporting layers."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RiskLevel(str, Enum):
    """Normalized finding severity."""

    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


class FindingCategory(str, Enum):
    """Supported access review finding categories."""

    OVERPRIVILEGED = "Overprivileged Account"
    ORPHANED_ACCOUNT = "Orphaned Account"
    STALE_PERMISSION = "Stale Permission"
    EXCESSIVE_SP = "Excessive Service Principal Permission"
    GUEST_ELEVATED = "Elevated Guest Account"


@dataclass(frozen=True)
class Finding:
    """A single audit finding included in the generated report."""

    category: FindingCategory
    risk: RiskLevel
    principal_name: str
    principal_id: str
    detail: str
    recommendation: str
    evidence: str = ""
    cis_control: str | None = None

    def to_dict(self) -> dict[str, str]:
        """Serialize the finding for tabular export or rendering."""
        return {
            "Category": self.category.value,
            "Risk": self.risk.value,
            "Principal": self.principal_name,
            "Principal ID": self.principal_id,
            "Detail": self.detail,
            "Recommendation": self.recommendation,
            "Evidence": self.evidence,
            "CIS Control": self.cis_control or "",
        }
