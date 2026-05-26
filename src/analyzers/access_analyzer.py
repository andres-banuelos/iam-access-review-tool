"""Core access review analysis logic for Entra ID identity findings."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from src.config import HIGH_PRIV_ROLES, INACTIVE_USER_DAYS, NEW_ACCOUNT_GRACE_DAYS, STALE_ROLE_DAYS

from .findings import Finding, FindingCategory, RiskLevel

RISK_ORDER = {
    RiskLevel.HIGH: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.LOW: 2,
    RiskLevel.INFO: 3,
}


def _days_since(iso_datetime: str | None) -> int | None:
    """Return the number of days since an ISO-8601 timestamp."""
    if not iso_datetime:
        return None
    parsed = datetime.fromisoformat(iso_datetime.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - parsed).days


def _best_sign_in_age(user: dict[str, Any]) -> int | None:
    """Return days since the most recent interactive or non-interactive sign-in."""
    candidate_ages = [
        _days_since(user.get("lastInteractiveSignIn")),
        _days_since(user.get("lastNonInteractiveSignIn")),
    ]
    valid_ages = [age for age in candidate_ages if age is not None]
    return min(valid_ages) if valid_ages else None


def _user_lookup(users: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Build a user lookup table keyed by principal id."""
    return {user["id"]: user for user in users}


def _role_assignments_by_principal(
    role_assignments: list[dict[str, Any]],
    *,
    principal_type: str,
    privileged_only: bool = False,
) -> dict[str, list[str]]:
    """Group role names by principal id with optional privilege filtering."""
    grouped: dict[str, list[str]] = defaultdict(list)

    for assignment in role_assignments:
        if assignment.get("principalType") != principal_type:
            continue

        role_name = assignment.get("roleName", "Unknown Role")
        if privileged_only and role_name not in HIGH_PRIV_ROLES:
            continue

        grouped[assignment["principalId"]].append(role_name)

    return dict(grouped)


def check_overprivileged_inactive(
    users: list[dict[str, Any]],
    role_assignments: list[dict[str, Any]],
    threshold_days: int = INACTIVE_USER_DAYS,
) -> list[Finding]:
    """Flag enabled privileged users whose sign-in activity is stale or absent."""
    findings: list[Finding] = []
    user_map = _user_lookup(users)
    privileged_users = _role_assignments_by_principal(
        role_assignments,
        principal_type="user",
        privileged_only=True,
    )

    for principal_id, role_names in privileged_users.items():
        user = user_map.get(principal_id)
        if not user or not user.get("accountEnabled"):
            continue

        sign_in_age = _best_sign_in_age(user)
        joined_roles = ", ".join(sorted(role_names))

        if sign_in_age is None:
            findings.append(
                Finding(
                    category=FindingCategory.OVERPRIVILEGED,
                    risk=RiskLevel.HIGH,
                    principal_name=user["displayName"],
                    principal_id=principal_id,
                    detail=(
                        f"Holds privileged role(s): {joined_roles}."
                        " No sign-in activity is on record."
                    ),
                    recommendation=(
                        "Revoke privileged access or validate the account's business purpose."
                        " If this is a documented break-glass account, verify compensating controls."
                    ),
                    evidence="lastSignIn: Never",
                    cis_control="CIS Control 5.4 — Restrict Administrator Privileges",
                )
            )
            continue

        if sign_in_age > threshold_days:
            findings.append(
                Finding(
                    category=FindingCategory.OVERPRIVILEGED,
                    risk=RiskLevel.HIGH,
                    principal_name=user["displayName"],
                    principal_id=principal_id,
                    detail=(
                        f"Holds privileged role(s): {joined_roles}."
                        f" Last sign-in was {sign_in_age} days ago"
                        f" (threshold: {threshold_days} days)."
                    ),
                    recommendation=(
                        "Perform user attestation and remove the privileged role if no longer required."
                        " Consider Microsoft Entra PIM for just-in-time elevation."
                    ),
                    evidence=f"lastSignIn: {sign_in_age} days ago",
                    cis_control="CIS Control 5.4 — Restrict Administrator Privileges",
                )
            )

    return findings


def check_orphaned_accounts(
    users: list[dict[str, Any]],
    threshold_days: int = INACTIVE_USER_DAYS,
    grace_days: int = NEW_ACCOUNT_GRACE_DAYS,
) -> list[Finding]:
    """Flag enabled accounts that appear dormant, stale, or never used."""
    findings: list[Finding] = []

    for user in users:
        if not user.get("accountEnabled"):
            continue

        sign_in_age = _best_sign_in_age(user)

        if sign_in_age is None:
            created_age = _days_since(user.get("createdDateTime"))
            if created_age is not None and created_age > grace_days:
                findings.append(
                    Finding(
                        category=FindingCategory.ORPHANED_ACCOUNT,
                        risk=RiskLevel.MEDIUM,
                        principal_name=user["displayName"],
                        principal_id=user["id"],
                        detail=(
                            "Account is enabled but has never signed in."
                            f" Account age: {created_age} days."
                        ),
                        recommendation=(
                            "Validate ownership with HR and the manager of record."
                            " Disable or delete the account if no active business owner"
                            " can be confirmed."
                        ),
                        evidence=(
                            f"accountEnabled: True | lastSignIn: Never"
                            f" | accountAge: {created_age}d"
                        ),
                        cis_control="CIS Control 5.3 — Disable Dormant Accounts",
                    )
                )
            continue

        if sign_in_age > threshold_days:
            findings.append(
                Finding(
                    category=FindingCategory.ORPHANED_ACCOUNT,
                    risk=RiskLevel.MEDIUM,
                    principal_name=user["displayName"],
                    principal_id=user["id"],
                    detail=(
                        f"Account is enabled but inactive for {sign_in_age} days"
                        f" (threshold: {threshold_days} days)."
                    ),
                    recommendation=(
                        "Initiate account attestation with the business owner or line manager"
                        " and disable the account pending confirmation of ongoing need."
                    ),
                    evidence=f"accountEnabled: True | lastSignIn: {sign_in_age}d ago",
                    cis_control="CIS Control 5.3 — Disable Dormant Accounts",
                )
            )

    return findings


def check_guest_with_elevated_roles(
    users: list[dict[str, Any]],
    role_assignments: list[dict[str, Any]],
) -> list[Finding]:
    """Flag guest users that hold directory roles."""
    findings: list[Finding] = []
    user_map = _user_lookup(users)

    for assignment in role_assignments:
        if assignment.get("principalType") != "user":
            continue

        user = user_map.get(assignment["principalId"])
        if not user or user.get("userType", "").lower() != "guest":
            continue

        findings.append(
            Finding(
                category=FindingCategory.GUEST_ELEVATED,
                risk=RiskLevel.HIGH,
                principal_name=user["displayName"],
                principal_id=user["id"],
                detail=(
                    f"External guest account holds directory role: {assignment['roleName']}."
                ),
                recommendation=(
                    "Remove the directory role from the guest account."
                    " External identities should use resource-scoped access"
                    " with strong lifecycle governance."
                ),
                evidence=f"userType: Guest | role: {assignment['roleName']}",
                cis_control="CIS Control 6.2 — Establish Access Granting Process",
            )
        )

    return findings


def check_stale_role_assignments(
    users: list[dict[str, Any]],
    role_assignments: list[dict[str, Any]],
    threshold_days: int = STALE_ROLE_DAYS,
) -> list[Finding]:
    """Flag non-privileged role assignments attached to stale user accounts."""
    findings: list[Finding] = []
    user_map = _user_lookup(users)

    for assignment in role_assignments:
        if assignment.get("principalType") != "user":
            continue
        if assignment.get("roleName") in HIGH_PRIV_ROLES:
            continue

        user = user_map.get(assignment["principalId"])
        if not user or not user.get("accountEnabled"):
            continue

        sign_in_age = _best_sign_in_age(user)
        if sign_in_age is None or sign_in_age <= threshold_days:
            continue

        findings.append(
            Finding(
                category=FindingCategory.STALE_PERMISSION,
                risk=RiskLevel.LOW,
                principal_name=user["displayName"],
                principal_id=user["id"],
                detail=(
                    f"Role '{assignment['roleName']}' appears stale because the user"
                    f" last signed in {sign_in_age} days ago."
                ),
                recommendation=(
                    "Review whether the role is still needed."
                    " If the entitlement is project-based or temporary,"
                    " replace it with time-bound assignment or remove it."
                ),
                evidence=f"role: {assignment['roleName']} | lastSignIn: {sign_in_age}d ago",
                cis_control="CIS Control 6.8 — Define and Maintain Role-Based Access Control",
            )
        )

    return findings


def check_excessive_service_principals(
    service_principals: list[dict[str, Any]],
    role_assignments: list[dict[str, Any]],
) -> list[Finding]:
    """Flag service principals with privileged directory roles."""
    findings: list[Finding] = []
    privileged_service_principals = _role_assignments_by_principal(
        role_assignments,
        principal_type="servicePrincipal",
        privileged_only=True,
    )
    service_principal_map = {sp["id"]: sp for sp in service_principals}

    for principal_id, role_names in privileged_service_principals.items():
        service_principal = service_principal_map.get(principal_id)
        principal_name = (
            service_principal["displayName"] if service_principal else principal_id
        )
        sp_type = (
            service_principal.get("spType", "unknown") if service_principal else "unknown"
        )

        findings.append(
            Finding(
                category=FindingCategory.EXCESSIVE_SP,
                risk=RiskLevel.HIGH,
                principal_name=principal_name,
                principal_id=principal_id,
                detail=(
                    f"Service principal holds privileged role(s):"
                    f" {', '.join(sorted(role_names))}. Type: {sp_type}."
                ),
                recommendation=(
                    "Confirm the service principal's business purpose and reduce"
                    " directory-level privileges to resource-scoped permissions"
                    " wherever possible."
                ),
                evidence=f"spType: {sp_type} | roles: {', '.join(sorted(role_names))}",
                cis_control="CIS Control 5.6 — Centralize Account Management",
            )
        )

    return findings


def run_all_checks(
    users: list[dict[str, Any]],
    role_assignments: list[dict[str, Any]],
    service_principals: list[dict[str, Any]],
) -> list[Finding]:
    """Run all analyzer checks and return a severity-sorted finding list."""
    findings: list[Finding] = []
    findings.extend(check_overprivileged_inactive(users, role_assignments))
    findings.extend(check_guest_with_elevated_roles(users, role_assignments))
    findings.extend(check_excessive_service_principals(service_principals, role_assignments))
    findings.extend(check_orphaned_accounts(users))
    findings.extend(check_stale_role_assignments(users, role_assignments))

    findings.sort(
        key=lambda finding: (RISK_ORDER[finding.risk], finding.principal_name.casefold())
    )
    return findings
