#!/usr/bin/env python3
"""Offline simulation entry point — runs the full review pipeline without Azure credentials.

Usage:
    python run_sample_review.py [--tenant-name "Demo Corp"] [--format html|md|both]
"""

from __future__ import annotations

import argparse
import json
import logging
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from src.analyzers.access_analyzer import run_all_checks
from src.analyzers.findings import RiskLevel
from src.reporters.html_reporter import render_html_report
from src.reporters.markdown_reporter import render_markdown_report

LOGGER = logging.getLogger(__name__)

SAMPLE_DIR = Path(__file__).resolve().parent / "sample_data"
OUTPUT_DIR = Path(__file__).resolve().parent / "output"


def configure_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def load_json(filename: str) -> list:
    """Load a JSON fixture from the sample_data directory."""
    path = SAMPLE_DIR / filename
    return json.loads(path.read_text(encoding="utf-8"))


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="IAM Access Review — offline simulation mode (no Azure credentials required)."
    )
    parser.add_argument(
        "--tenant-name",
        default="Demo Corp",
        help="Tenant name shown in the report header.",
    )
    parser.add_argument(
        "--format",
        choices=["html", "md", "both"],
        default="both",
        help="Report output format.",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    configure_logging(verbose=args.verbose)

    LOGGER.info("Starting offline simulation for tenant '%s'", args.tenant_name)

    users = load_json("users.json")
    role_assignments = load_json("role_assignments.json")
    service_principals = load_json("service_principals.json")

    LOGGER.info(
        "Loaded %s users, %s role assignments, %s service principals from sample_data/",
        len(users),
        len(role_assignments),
        len(service_principals),
    )

    findings = run_all_checks(users, role_assignments, service_principals)
    risk_counts = {level: sum(1 for f in findings if f.risk is level) for level in RiskLevel}

    LOGGER.info(
        "Generated %s findings (High=%s, Medium=%s, Low=%s, Informational=%s)",
        len(findings),
        risk_counts[RiskLevel.HIGH],
        risk_counts[RiskLevel.MEDIUM],
        risk_counts[RiskLevel.LOW],
        risk_counts[RiskLevel.INFO],
    )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("sample_%Y%m%d_%H%M%S")

    if args.format in {"html", "both"}:
        html_path = OUTPUT_DIR / f"iam_review_{timestamp}.html"
        render_html_report(
            findings=findings,
            tenant_name=args.tenant_name,
            tenant_id="00000000-0000-0000-0000-000000000000",
            total_users=len(users),
            total_roles=len(role_assignments),
            total_sps=len(service_principals),
            output_path=html_path,
        )
        LOGGER.info("Wrote HTML report to %s", html_path)

    if args.format in {"md", "both"}:
        md_path = OUTPUT_DIR / f"iam_review_{timestamp}.md"
        render_markdown_report(
            findings=findings,
            tenant_name=args.tenant_name,
            output_path=md_path,
        )
        LOGGER.info("Wrote Markdown report to %s", md_path)

    LOGGER.info("Simulation complete — open the HTML report in your browser")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
