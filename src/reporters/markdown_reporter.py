"""Markdown report generation for IAM access review findings."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from src.analyzers.findings import Finding, RiskLevel

RISK_EMOJI = {
    RiskLevel.HIGH: "🔴",
    RiskLevel.MEDIUM: "🟡",
    RiskLevel.LOW: "🟢",
    RiskLevel.INFO: "ℹ️",
}



def render_markdown_report(
    findings: list[Finding],
    tenant_name: str,
    output_path: str | Path,
) -> str:
    """Render findings to a Markdown file and return the absolute output path."""
    generated_at = datetime.now(timezone.utc)
    counts = {risk_level: 0 for risk_level in RiskLevel}
    for finding in findings:
        counts[finding.risk] += 1

    lines = [
        f"# IAM Access Review — {tenant_name}",
        (
            f"> **Review Date:** {generated_at.strftime('%B %d, %Y')}  |  "
            "**Tool:** IAM Access Review Automation  |  **Classification:** Confidential"
        ),
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "| Risk Level | Count |",
        "|---|---|",
        f"| 🔴 High | {counts[RiskLevel.HIGH]} |",
        f"| 🟡 Medium | {counts[RiskLevel.MEDIUM]} |",
        f"| 🟢 Low | {counts[RiskLevel.LOW]} |",
        f"| ℹ️ Informational | {counts[RiskLevel.INFO]} |",
        f"| **Total** | **{len(findings)}** |",
        "",
        "---",
        "",
        "## Detailed Findings",
        "",
    ]

    for index, finding in enumerate(findings, start=1):
        lines.extend(
            [
                (
                    f"### Finding {index:02d} — {RISK_EMOJI[finding.risk]} "
                    f"{finding.risk.value}: {finding.principal_name}"
                ),
                "",
                f"**Category:** {finding.category.value}  ",
                f"**Principal ID:** `{finding.principal_id}`  ",
                f"**Evidence:** {finding.evidence}  ",
                "",
                f"**Detail:** {finding.detail}",
                "",
                f"**Recommendation:** {finding.recommendation}",
                "",
                f"**CIS Control:** {finding.cis_control}" if finding.cis_control else "",
                "",
                "---",
                "",
            ]
        )

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines), encoding="utf-8")
    return str(destination.resolve())
