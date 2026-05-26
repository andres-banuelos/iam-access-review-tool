"""
config.py — Centralised configuration loaded from environment variables.
All credential access flows through here so it's easy to rotate secrets or
switch to Key Vault without touching business logic.

Azure credentials are OPTIONAL — if not set, the tool runs in offline/simulation
mode using local sample data (run_sample_review.py). Live mode (main.py) will
validate these are present before attempting any Graph API calls.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ── Azure credentials (optional — not required for offline simulation mode) ──
TENANT_ID     = os.getenv("AZURE_TENANT_ID", "")
CLIENT_ID     = os.getenv("AZURE_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET", "")

# ── Analysis thresholds ───────────────────────────────────────
INACTIVE_USER_DAYS = int(os.getenv("INACTIVE_USER_DAYS", 90))
STALE_ROLE_DAYS    = int(os.getenv("STALE_ROLE_DAYS", 90))

# ── Privileged directory role display names to flag as high-risk ──────────
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

# ── Output ────────────────────────────────────────────────────
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "./output")


def require_azure_credentials() -> None:
    """Call this in live mode (main.py) to validate credentials are present.
    Not called during offline simulation."""
    missing = []
    if not TENANT_ID:     missing.append("AZURE_TENANT_ID")
    if not CLIENT_ID:     missing.append("AZURE_CLIENT_ID")
    if not CLIENT_SECRET: missing.append("AZURE_CLIENT_SECRET")
    if missing:
        raise EnvironmentError(
            f"Missing required environment variables for live mode: {', '.join(missing)}\n"
            "Copy .env.example to .env and fill in your Azure credentials,\n"
            "or run offline simulation with: python3 run_sample_review.py"
        )
