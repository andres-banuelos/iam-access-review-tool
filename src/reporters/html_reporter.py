"""HTML report generation for IAM access review findings."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.analyzers.findings import Finding, RiskLevel

TEMPLATE_DIR = Path(__file__).resolve().parents[2] / "templates"



def render_html_report(
    findings: list[Finding],
    tenant_name: str,
    tenant_id: str,
    total_users: int,
    total_roles: int,
    total_sps: int,
    output_path: str | Path,
) -> str:
    """Render findings into an HTML report and return the absolute output path."""
    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(enabled_extensions=("html", "xml")),
    )
    template = environment.get_template("report.html.j2")

    counts = {risk_level: 0 for risk_level in RiskLevel}
    grouped_findings: dict[str, list[Finding]] = defaultdict(list)

    for finding in findings:
        counts[finding.risk] += 1
        grouped_findings[finding.category.value].append(finding)

    generated_at = datetime.now(timezone.utc)
    rendered_html = template.render(
        tenant_name=tenant_name,
        tenant_id=tenant_id,
        report_date=generated_at.strftime("%B %d, %Y"),
        report_time=generated_at.strftime("%H:%M UTC"),
        total_users=total_users,
        total_roles=total_roles,
        total_sps=total_sps,
        total_findings=len(findings),
        counts=counts,
        findings=findings,
        grouped=dict(grouped_findings),
        RiskLevel=RiskLevel,
    )

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(rendered_html, encoding="utf-8")
    return str(destination.resolve())
