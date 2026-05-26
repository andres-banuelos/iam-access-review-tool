#!/usr/bin/env python3
"""
run_sample_review.py -- Offline simulation mode for IAM Access Review Automation Tool.

This script bypasses Microsoft Graph completely and feeds canned JSON data
into the existing analyzer + report pipeline. Use this for:
  * Demoing the tool without Azure access
  * Validating findings logic
  * Generating portfolio screenshots

Usage:
    python3 run_sample_review.py --tenant-name "Demo Corp IAM"
"""

import argparse
import json
import os
import sys
from datetime import datetime

# Ensure src/ is importable when running from repo root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.analyzers.access_analyzer import run_all_checks
from src.reporters.html_reporter import render_html_report
from src.reporters.markdown_reporter import render_markdown_report

SAMPLE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_data")
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")


def load_json(filename: str) -> list:
    """Load a JSON file from sample_data/ and return its contents."""
    path = os.path.join(SAMPLE_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Offline simulation run — no Azure credentials required."
    )
    parser.add_argument(
        "--tenant-name",
        default="Demo Tenant",
        help="Tenant display name shown in the report header (default: Demo Tenant)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ts = datetime.now().strftime("sample_%Y%m%d_%H%M%S")

    print("=" * 60)
    print("  IAM Access Review Automation Tool -- Offline Simulation")
    print(f"  Tenant (simulated): {args.tenant_name}")
    print("=" * 60)

    # ── Step 1: Load sample data ──────────────────────────────────
    print("\n[1/3] Loading sample data from ./sample_data ...")
    users = load_json("users.json")
    role_assignments = load_json("role_assignments.json")
    service_principals = load_json("service_principals.json")
    print(f"      ✓ Users:              {len(users)}")
    print(f"      ✓ Role assignments:   {len(role_assignments)}")
    print(f"      ✓ Service principals: {len(service_principals)}")

    # ── Step 2: Run risk analysis ─────────────────────────────────
    print("\n[2/3] Running risk analysis checks ...")
    findings = run_all_checks(users, role_assignments, service_principals)
    high = sum(1 for f in findings if f.risk.value == "High")
    med  = sum(1 for f in findings if f.risk.value == "Medium")
    low  = sum(1 for f in findings if f.risk.value == "Low")
    print(f"      ✓ {len(findings)} findings: {high} High | {med} Medium | {low} Low")

    # ── Step 3: Render reports ────────────────────────────────────
    print("\n[3/3] Generating reports ...")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    html_path = os.path.join(OUTPUT_DIR, f"iam_review_{ts}.html")
    md_path   = os.path.join(OUTPUT_DIR, f"iam_review_{ts}.md")

    render_html_report(
        findings=findings,
        tenant_name=args.tenant_name,
        tenant_id="00000000-0000-0000-0000-000000000000",
        total_users=len(users),
        total_roles=len(role_assignments),
        total_sps=len(service_principals),
        output_path=html_path,
    )
    render_markdown_report(
        findings=findings,
        tenant_name=args.tenant_name,
        output_path=md_path,
    )

    print(f"      ✓ HTML report:     {html_path}")
    print(f"      ✓ Markdown report: {md_path}")
    print("\n✓ Simulation complete. Open the HTML report in your browser.")
    print("=" * 60)


if __name__ == "__main__":
    main()
