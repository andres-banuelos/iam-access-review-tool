"""
config.py — Centralised configuration loaded from environment variables.
All credential access flows through here so it's easy to rotate secrets or
switch to Key Vault without touching business logic.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ── Azure credentials ────────────────────────────────────────────
TENANT_ID     = os.environ["AZURE_TENANT_ID"]
CLIENT_ID     = os.environ["AZURE_CLIENT_ID"]
CLIENT_SECRET = os.environ["AZURE_CLIENT_SECRET"]

# ── Analysis thresholds ──────────────────────────────────────────
INACTIVE_USER_DAYS = int(os.getenv("INACTIVE_USER_DAYS", 90))   # days since last sign-in
STALE_ROLE_DAYS    = int(os.getenv("STALE_ROLE_DAYS", 90))      # days since role last used

# ── Privileged directory role display names to flag as high-risk ─────────────
HIGH_PRIV_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "User Account Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Teams Administrator",
    "Security Administrator",
    "Billing Administrator",
    "Owner",  # Azure RBAC
}

# ── Output ──────────────────────────────────────────────────────
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "./output")
