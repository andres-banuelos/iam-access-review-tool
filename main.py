#!/usr/bin/env python3
"""Command-line entry point for the IAM Access Review Automation Tool."""

from __future__ import annotations

import argparse
import asyncio
import logging
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from src.analyzers.access_analyzer import run_all_checks
from src.analyzers.findings import RiskLevel
from src.collectors.graph_client import get_graph_client
from src.collectors.roles import fetch_directory_role_assignments, fetch_service_principals
from src.collectors.users import fetch_all_users
from src.config import OUTPUT_DIR, TENANT_ID, require_azure_credentials
from src.reporters.html_reporter import render_html_report
from src.reporters.markdown_reporter import render_markdown_report

LOGGER = logging.getLogger(__name__)


def configure_logging(verbose: bool = False) -> None:
    """Configure application logging for CLI execution."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="IAM Access Review Automation Tool — Azure Entra ID",
    )
    parser.add_argument(
        "--tenant-name",
        default="Azure Tenant",
        help="Human-readable tenant name for the report header.",
    )
    parser.add_argument(
        "--output-dir",
        default=OUTPUT_DIR,
        help=f"Directory to write report files (default: {OUTPUT_DIR}).",
    )
    parser.add_argument(
        "--format",
        choices=["html", "md", "both"],
        default="both",
        help="Report output format.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser.parse_args(argv)


async def run_review(args: argparse.Namespace) -> int:
    """Run the access review workflow and return a process exit code."""
    require_azure_credentials()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    LOGGER.info("Starting IAM access review for tenant '%s' (%s)", args.tenant_name, TENANT_ID)

    client = get_graph_client()

    LOGGER.info("Collecting users, role assignments, and service principals from Microsoft Graph")
    users, role_assignments, service_principals = await asyncio.gather(
        fetch_all_users(client),
        fetch_directory_role_assignments(client),
        fetch_service_principals(client),
    )

    LOGGER.info(
        "Collected %s users, %s role assignments, and %s service principals",
        len(users),
        len(role_assignments),
        len(service_principals),
    )

    findings = run_all_checks(users, role_assignments, service_principals)
    risk_counts = {level: sum(1 for finding in findings if finding.risk is level) for level in RiskLevel}

    LOGGER.info(
        "Generated %s findings (High=%s, Medium=%s, Low=%s, Informational=%s)",
        len(findings),
        risk_counts[RiskLevel.HIGH],
        risk_counts[RiskLevel.MEDIUM],
        risk_counts[RiskLevel.LOW],
        risk_counts[RiskLevel.INFO],
    )

    if args.format in {"html", "both"}:
        html_path = output_dir / f"iam_review_{timestamp}.html"
        render_html_report(
            findings=findings,
            tenant_name=args.tenant_name,
            tenant_id=TENANT_ID,
            total_users=len(users),
            total_roles=len(role_assignments),
            total_sps=len(service_principals),
            output_path=html_path,
        )
        LOGGER.info("Wrote HTML report to %s", html_path)

    if args.format in {"md", "both"}:
        markdown_path = output_dir / f"iam_review_{timestamp}.md"
        render_markdown_report(
            findings=findings,
            tenant_name=args.tenant_name,
            output_path=markdown_path,
        )
        LOGGER.info("Wrote Markdown report to %s", markdown_path)

    LOGGER.info("Access review complete")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Program entry point."""
    args = parse_args(argv)
    configure_logging(verbose=args.verbose)

    try:
        return asyncio.run(run_review(args))
    except KeyboardInterrupt:
        LOGGER.warning("Execution interrupted by user")
        return 130
    except Exception:
        LOGGER.exception("IAM access review failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
