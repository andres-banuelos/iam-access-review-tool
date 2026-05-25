"""
tests/test_analyzers.py — Unit tests for risk analysis checks.

Run with:  python -m pytest tests/ -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import datetime, timezone, timedelta
from src.analyzers.access_analyzer import (
    check_overprivileged_inactive,
    check_orphaned_accounts,
    check_guest_with_elevated_roles,
    check_excessive_service_principals,
)
from src.analyzers.findings import RiskLevel, FindingCategory


def _days_ago(days: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days)
    return dt.isoformat()


# ── Fixtures ──────────────────────────────────────────────────────

PRIV_INACTIVE_USER = {
    "id": "user-001", "displayName": "Admin Idle",
    "userPrincipalName": "admin@contoso.com", "mail": "",
    "accountEnabled": True, "createdDateTime": _days_ago(200),
    "userType": "Member",
    "lastInteractiveSignIn": _days_ago(120),
    "lastNonInteractiveSignIn": None,
    "hasLicenses": True,
}

PRIV_ACTIVE_USER = {
    "id": "user-002", "displayName": "Admin Active",
    "userPrincipalName": "admin2@contoso.com", "mail": "",
    "accountEnabled": True, "createdDateTime": _days_ago(200),
    "userType": "Member",
    "lastInteractiveSignIn": _days_ago(10),
    "lastNonInteractiveSignIn": None,
    "hasLicenses": True,
}

GUEST_USER = {
    "id": "user-003", "displayName": "External Vendor",
    "userPrincipalName": "vendor@external.com", "mail": "",
    "accountEnabled": True, "createdDateTime": _days_ago(30),
    "userType": "Guest",
    "lastInteractiveSignIn": _days_ago(5),
    "lastNonInteractiveSignIn": None,
    "hasLicenses": False,
}

ROLE_ASSIGNMENTS = [
    {"roleId": "r1", "roleName": "Global Administrator", "principalId": "user-001", "principalType": "user"},
    {"roleId": "r1", "roleName": "Global Administrator", "principalId": "user-002", "principalType": "user"},
    {"roleId": "r2", "roleName": "Teams Administrator",  "principalId": "user-003", "principalType": "user"},
    {"roleId": "r3", "roleName": "Global Administrator", "principalId": "sp-001",   "principalType": "servicePrincipal"},
]

SERVICE_PRINCIPALS = [
    {"id": "sp-001", "displayName": "CI Pipeline SP", "appId": "app-001",
     "enabled": True, "spType": "Application", "createdDateTime": _days_ago(300)},
]


# ── Tests ───────────────────────────────────────────────────────────

def test_overprivileged_inactive_flagged():
    findings = check_overprivileged_inactive([PRIV_INACTIVE_USER, PRIV_ACTIVE_USER], ROLE_ASSIGNMENTS)
    assert any(f.principal_id == "user-001" for f in findings), "Inactive priv user should be flagged"
    assert not any(f.principal_id == "user-002" for f in findings), "Active priv user should NOT be flagged"
    assert all(f.risk == RiskLevel.HIGH for f in findings)

def test_guest_elevated_role_flagged():
    findings = check_guest_with_elevated_roles(
        [PRIV_INACTIVE_USER, PRIV_ACTIVE_USER, GUEST_USER], ROLE_ASSIGNMENTS
    )
    assert any(f.principal_id == "user-003" for f in findings), "Guest with role should be flagged"
    assert all(f.category == FindingCategory.GUEST_ELEVATED for f in findings)

def test_excessive_service_principal_flagged():
    findings = check_excessive_service_principals(SERVICE_PRINCIPALS, ROLE_ASSIGNMENTS)
    assert any(f.principal_id == "sp-001" for f in findings), "Privileged SP should be flagged"
    assert all(f.risk == RiskLevel.HIGH for f in findings)

def test_orphaned_account_never_signed_in():
    old_unlicensed = {
        "id": "user-004", "displayName": "Ghost Account",
        "userPrincipalName": "ghost@contoso.com", "mail": "",
        "accountEnabled": True, "createdDateTime": _days_ago(60),
        "userType": "Member",
        "lastInteractiveSignIn": None,
        "lastNonInteractiveSignIn": None,
        "hasLicenses": False,
    }
    findings = check_orphaned_accounts([old_unlicensed])
    assert any(f.principal_id == "user-004" for f in findings), "Never-signed-in account should be flagged"

def test_new_account_grace_period():
    new_user = {
        "id": "user-005", "displayName": "New Hire",
        "userPrincipalName": "newhire@contoso.com", "mail": "",
        "accountEnabled": True, "createdDateTime": _days_ago(5),
        "userType": "Member",
        "lastInteractiveSignIn": None,
        "lastNonInteractiveSignIn": None,
        "hasLicenses": True,
    }
    findings = check_orphaned_accounts([new_user])
    assert not findings, "New account within grace period should NOT be flagged"
