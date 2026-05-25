#!/usr/bin/env python3
"""
main.py — Entry point for the IAM Access Review Automation Tool.

Usage:
    python main.py [--tenant-name "Contoso Ltd"] [--output-dir ./output] [--format html|md|both]

The script:
  1. Authenticates to Microsoft Graph via client credentials (app-only)
  2. Collects users, directory roles, and service principals
  3. Runs risk analysis checks
  4. Outputs a formatted HTML and/or Markdown report
"""
import asyncio
import argparse
import os
import sys
from datetime import datetime

# Allow running from project root without installing the package
sys.path.insert(0, os.path.dirname(__file__))

from src.config import TENANT_ID, OUTPUT_DIR
from src.collectors.graph_client import get_graph_client
from src.collectors.users import fetch_all_users
from src.collectors.roles import fetch_directory_role_assignments, fetch_service_principals
from src.analyzers.access_analyzer import run_all_checks
from src.reporters.html_reporter import render_html_report
from src.reporters.markdown_reporter import render_markdown_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="IAM Access Review Automation Tool — Azure Entra ID"
    )
    parser.add_argument(
        "--tenant-name",
        default="Azure Tenant",
        help="Human-readable tenant name for the report header (default: 'Azure Tenant')",
    )
    parser.add_argument(
        "--output-dir",
        default=OUTPUT_DIR,
        help=f"Directory to write report files (default: {OUTPUT_DIR})",
    )
    parser.add_argument(
        "--format",
        choices=["html", "md", "both"],
        default="both",
        help="Report output format (default: both)",
    )
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    print("=" * 60)
    print("  IAM Access Review Automation Tool")
    print(f"  Tenant: {args.tenant_name} ({TENANT_ID})")
    print("=" * 60)

    # ── Step 1: Authenticate ──────────────────────────────────────────
    print("\n[1/4] Authenticating to Microsoft Graph...")
    client = get_graph_client()
    print("      ✓ Authenticated (client credentials flow)")

    # ── Step 2: Collect data ──────────────────────────────────────
    print("\n[2/4] Collecting data from Graph API...")
    users, role_assignments, service_principals = await asyncio.gather(
        fetch_all_users(client),
        fetch_directory_role_assignments(client),
        fetch_service_principals(client),
    )
    print(f"      ✓ Users: {len(users)}")
    print(f"      ✓ Role assignments: {len(role_assignments)}")
    print(f"      ✓ Service principals: {len(service_principals)}")

    # ── Step 3: Analyse ───────────────────────────────────────────
    print("\n[3/4] Running risk analysis checks...")
    findings = run_all_checks(users, role_assignments, service_principals)

    high   = sum(1 for f in findings if f.risk.value == "High")
    medium = sum(1 for f in findings if f.risk.value == "Medium")
    low    = sum(1 for f in findings if f.risk.value == "Low")
    print(f"      ✓ {len(findings)} findings: {high} High | {medium} Medium | {low} Low")

    # ── Step 4: Report ────────────────────────────────────────────
    print("\n[4/4] Generating reports...")
    os.makedirs(args.output_dir, exist_ok=True)

    if args.format in ("html", "both"):
        html_path = os.path.join(args.output_dir, f"iam_review_{ts}.html")
        render_html_report(
            findings        = findings,
            tenant_name     = args.tenant_name,
            tenant_id       = TENANT_ID,
            total_users     = len(users),
            total_roles     = len(role_assignments),
            total_sps       = len(service_principals),
            output_path     = html_path,
        )
        print(f"      ✓ HTML report: {html_path}")

    if args.format in ("md", "both"):
        md_path = os.path.join(args.output_dir, f"iam_review_{ts}.md")
        render_markdown_report(
            findings    = findings,
            tenant_name = args.tenant_name,
            output_path = md_path,
        )
        print(f"      ✓ Markdown report: {md_path}")

    print("\n✓ Review complete. Open the HTML report in a browser for the full deliverable.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
