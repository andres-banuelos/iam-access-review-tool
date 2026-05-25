"""
html_reporter.py — Render findings into a professional HTML audit report.

Uses Jinja2 templating. The template lives in templates/report.html.j2 so
non-developers can tweak formatting without touching Python code.
"""
from __future__ import annotations
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.analyzers.findings import Finding, RiskLevel


TEMPLATE_DIR = Path(__file__).parent.parent.parent / "templates"


def render_html_report(
    findings: List[Finding],
    tenant_name: str,
    tenant_id: str,
    total_users: int,
    total_roles: int,
    total_sps: int,
    output_path: str,
) -> str:
    """
    Render findings to an HTML file and return the output path.
    """
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True,
    )

    template = env.get_template("report.html.j2")

    counts = {r: 0 for r in RiskLevel}
    for f in findings:
        counts[f.risk] += 1

    from collections import defaultdict
    grouped = defaultdict(list)
    for f in findings:
        grouped[f.category.value].append(f)

    now = datetime.now(timezone.utc)

    html = template.render(
        tenant_name   = tenant_name,
        tenant_id     = tenant_id,
        report_date   = now.strftime("%B %d, %Y"),
        report_time   = now.strftime("%H:%M UTC"),
        total_users   = total_users,
        total_roles   = total_roles,
        total_sps     = total_sps,
        total_findings= len(findings),
        counts        = counts,
        findings      = findings,
        grouped       = dict(grouped),
        RiskLevel     = RiskLevel,
    )

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    return os.path.abspath(output_path)
