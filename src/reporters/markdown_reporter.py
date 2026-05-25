"""
markdown_reporter.py — Render findings as GitHub-Flavored Markdown.

Useful for pasting into Confluence, attaching to Jira tickets, or
committing alongside code changes as a PR comment artefact.
"""
from __future__ import annotations
import os
from datetime import datetime, timezone
from typing import List

from src.analyzers.findings import Finding, RiskLevel

RISK_EMOJI = {
    RiskLevel.HIGH:   "🔴",
    RiskLevel.MEDIUM: "🟡",
    RiskLevel.LOW:    "🟢",
    RiskLevel.INFO:   "ℹ️",
}


def render_markdown_report(
    findings: List[Finding],
    tenant_name: str,
    output_path: str,
) -> str:
    """Render findings to a Markdown file and return the output path."""
    now = datetime.now(timezone.utc)
    lines = [
        f"# IAM Access Review — {tenant_name}",
        f"> **Review Date:** {now.strftime('%B %d, %Y')}  |  "
        f"**Tool:** IAM Access Review Automation  |  **Classification:** Confidential",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
    ]

    counts = {r: 0 for r in RiskLevel}
    for f in findings:
        counts[f.risk] += 1

    lines += [
        f"| Risk Level | Count |",
        f"|---|---|",
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

    for i, f in enumerate(findings, 1):
        lines += [
            f"### Finding {i:02d} — {RISK_EMOJI[f.risk]} {f.risk.value}: {f.principal_name}",
            "",
            f"**Category:** {f.category.value}  ",
            f"**Principal ID:** `{f.principal_id}`  ",
            f"**Evidence:** {f.evidence}  ",
            "",
            f"**Detail:** {f.detail}",
            "",
            f"**Recommendation:** {f.recommendation}",
            "",
            (f"**CIS Control:** {f.cis_control}" if f.cis_control else ""),
            "",
            "---",
            "",
        ]

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    return os.path.abspath(output_path)
