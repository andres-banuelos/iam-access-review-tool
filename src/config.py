"""Centralized application configuration and environment validation."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

DEFAULT_NEW_ACCOUNT_GRACE_DAYS = 14

HIGH_PRIV_ROLES = frozenset(
    {
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
        "Owner",
    }
)


@dataclass(frozen=True)
class Settings:
    """Runtime settings loaded from environment variables."""

    tenant_id: str
    client_id: str
    client_secret: str
    inactive_user_days: int
    stale_role_days: int
    new_account_grace_days: int
    output_dir: Path


TENANT_ID = os.getenv("AZURE_TENANT_ID", "")
CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET", "")
INACTIVE_USER_DAYS = int(os.getenv("INACTIVE_USER_DAYS", "90"))
STALE_ROLE_DAYS = int(os.getenv("STALE_ROLE_DAYS", "90"))
NEW_ACCOUNT_GRACE_DAYS = int(
    os.getenv("NEW_ACCOUNT_GRACE_DAYS", str(DEFAULT_NEW_ACCOUNT_GRACE_DAYS))
)
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "./output")

SETTINGS = Settings(
    tenant_id=TENANT_ID,
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    inactive_user_days=INACTIVE_USER_DAYS,
    stale_role_days=STALE_ROLE_DAYS,
    new_account_grace_days=NEW_ACCOUNT_GRACE_DAYS,
    output_dir=Path(OUTPUT_DIR),
)


def require_azure_credentials() -> None:
    """Validate required Azure credentials for live Graph API mode."""
    missing = []
    if not SETTINGS.tenant_id:
        missing.append("AZURE_TENANT_ID")
    if not SETTINGS.client_id:
        missing.append("AZURE_CLIENT_ID")
    if not SETTINGS.client_secret:
        missing.append("AZURE_CLIENT_SECRET")

    if missing:
        missing_vars = ", ".join(missing)
        raise OSError(
            "Missing required environment variables for live mode: "
            f"{missing_vars}. Copy .env.example to .env and fill in your Azure credentials."
        )
