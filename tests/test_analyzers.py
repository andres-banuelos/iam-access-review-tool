"""Unit tests for access review analyzer logic."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.analyzers.access_analyzer import (
    check_excessive_service_principals,
    check_guest_with_elevated_roles,
    check_orphaned_accounts,
    check_overprivileged_inactive,
    check_stale_role_assignments,
)
from src.analyzers.findings import FindingCategory, RiskLevel


def _days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


PRIV_INACTIVE_USER = {
    "id": "user-001",
    "displayName": "Admin Idle",
    "userPrincipalName": "admin@contoso.com",
    "mail": "",
    "accountEnabled": True,
    "createdDateTime": _days_ago(200),
    "userType": "Member",
    "lastInteractiveSignIn": _days_ago(120),
    "lastNonInteractiveSignIn": None,
    "hasLicenses": True,
}

PRIV_ACTIVE_USER = {
    "id": "user-002",
    "displayName": "Admin Active",
    "userPrincipalName": "admin2@contoso.com",
    "mail": "",
    "accountEnabled": True,
    "createdDateTime": _days_ago(200),
    "userType": "Member",
    "lastInteractiveSignIn": _days_ago(10),
    "lastNonInteractiveSignIn": None,
    "hasLicenses": True,
}

GUEST_USER = {
    "id": "user-003",
    "displayName": "External Vendor",
    "userPrincipalName": "vendor@external.com",
    "mail": "",
    "accountEnabled": True,
    "createdDateTime": _days_ago(30),
    "userType": "Guest",
    "lastInteractiveSignIn": _days_ago(5),
    "lastNonInteractiveSignIn": None,
    "hasLicenses": False,
}

STALE_STANDARD_USER = {
    "id": "user-006",
    "displayName": "Dormant Analyst",
    "userPrincipalName": "analyst@contoso.com",
    "mail": "",
    "accountEnabled": True,
    "createdDateTime": _days_ago(250),
    "userType": "Member",
    "lastInteractiveSignIn": _days_ago(150),
    "lastNonInteractiveSignIn": None,
    "hasLicenses": True,
}

ROLE_ASSIGNMENTS = [
    {
        "roleId": "r1",
        "roleName": "Global Administrator",
        "principalId": "user-001",
        "principalType": "user",
    },
    {
        "roleId": "r1",
        "roleName": "Global Administrator",
        "principalId": "user-002",
        "principalType": "user",
    },
    {
        "roleId": "r2",
        "roleName": "Teams Administrator",
        "principalId": "user-003",
        "principalType": "user",
    },
    {
        "roleId": "r3",
        "roleName": "Global Administrator",
        "principalId": "sp-001",
        "principalType": "servicePrincipal",
    },
    {
        "roleId": "r4",
        "roleName": "Reports Reader",
        "principalId": "user-006",
        "principalType": "user",
    },
]

SERVICE_PRINCIPALS = [
    {
        "id": "sp-001",
        "displayName": "CI Pipeline SP",
        "appId": "app-001",
        "enabled": True,
        "spType": "Application",
        "createdDateTime": _days_ago(300),
    },
]


def test_overprivileged_inactive_flags_only_inactive_privileged_user() -> None:
    findings = check_overprivileged_inactive(
        [PRIV_INACTIVE_USER, PRIV_ACTIVE_USER],
        ROLE_ASSIGNMENTS,
    )

    assert any(finding.principal_id == "user-001" for finding in findings)
    assert all(finding.principal_id != "user-002" for finding in findings)
    assert all(finding.risk is RiskLevel.HIGH for finding in findings)


def test_guest_elevated_role_is_flagged() -> None:
    findings = check_guest_with_elevated_roles(
        [PRIV_INACTIVE_USER, PRIV_ACTIVE_USER, GUEST_USER],
        ROLE_ASSIGNMENTS,
    )

    assert any(finding.principal_id == "user-003" for finding in findings)
    assert all(finding.category is FindingCategory.GUEST_ELEVATED for finding in findings)


def test_excessive_service_principal_is_flagged() -> None:
    findings = check_excessive_service_principals(SERVICE_PRINCIPALS, ROLE_ASSIGNMENTS)

    assert any(finding.principal_id == "sp-001" for finding in findings)
    assert all(finding.risk is RiskLevel.HIGH for finding in findings)


def test_orphaned_account_never_signed_in_is_flagged() -> None:
    old_unlicensed = {
        "id": "user-004",
        "displayName": "Ghost Account",
        "userPrincipalName": "ghost@contoso.com",
        "mail": "",
        "accountEnabled": True,
        "createdDateTime": _days_ago(60),
        "userType": "Member",
        "lastInteractiveSignIn": None,
        "lastNonInteractiveSignIn": None,
        "hasLicenses": False,
    }

    findings = check_orphaned_accounts([old_unlicensed])
    assert any(finding.principal_id == "user-004" for finding in findings)


def test_new_account_inside_grace_period_is_not_flagged() -> None:
    new_user = {
        "id": "user-005",
        "displayName": "New Hire",
        "userPrincipalName": "newhire@contoso.com",
        "mail": "",
        "accountEnabled": True,
        "createdDateTime": _days_ago(5),
        "userType": "Member",
        "lastInteractiveSignIn": None,
        "lastNonInteractiveSignIn": None,
        "hasLicenses": True,
    }

    findings = check_orphaned_accounts([new_user])
    assert findings == []


def test_stale_non_privileged_role_assignment_is_flagged() -> None:
    findings = check_stale_role_assignments([STALE_STANDARD_USER], ROLE_ASSIGNMENTS)

    assert len(findings) == 1
    assert findings[0].principal_id == "user-006"
    assert findings[0].category is FindingCategory.STALE_PERMISSION
    assert findings[0].risk is RiskLevel.LOW
