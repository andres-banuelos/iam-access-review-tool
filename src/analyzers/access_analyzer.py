"""
access_analyzer.py — Core risk-analysis logic.

Consumes the raw data collected from Graph API and produces a list of
Finding objects. Each check is a standalone function so rules are easy
to unit-test or extend independently.

Checks implemented:
  1. overprivileged_inactive_users  — priv role + no sign-in within threshold
  2. orphaned_accounts              — no sign-in ever OR beyond threshold, account still enabled
  3. guest_with_elevated_roles      — external (Guest) users holding directory roles
  4. excessive_service_principals   — SPs with no sign-in / still enabled but created long ago
  5. stale_role_assignments         — role members whose last sign-in pre-dates the stale threshold
"""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

from .findings import Finding, FindingCategory, RiskLevel
from src.config import HIGH_PRIV_ROLES, INACTIVE_USER_DAYS, STALE_ROLE_DAYS


# ── helpers ────────────────────────────────────────────────────────

def _days_since(iso_dt: str | None) -> int | None:
    """Return the number of days since an ISO-8601 timestamp, or None if absent."""
    if not iso_dt:
        return None
    dt = datetime.fromisoformat(iso_dt.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - dt).days


def _best_sign_in_age(user: Dict[str, Any]) -> int | None:
    """
    Return the number of days since the most recent sign-in across both
    interactive and non-interactive channels.  Returns None if no sign-in
    data is available (account may never have signed in).
    """
    ages = [
        _days_since(user.get("lastInteractiveSignIn")),
        _days_since(user.get("lastNonInteractiveSignIn")),
    ]
    valid = [a for a in ages if a is not None]
    return min(valid) if valid else None


def _user_lookup(users: List[Dict]) -> Dict[str, Dict]:
    return {u["id"]: u for u in users}


# ── check functions ───────────────────────────────────────────────

def check_overprivileged_inactive(
    users: List[Dict[str, Any]],
    role_assignments: List[Dict[str, Any]],
    threshold_days: int = INACTIVE_USER_DAYS,
) -> List[Finding]:
    """
    Flag users who hold a HIGH_PRIV_ROLES role AND have not signed in
    within `threshold_days`.  These are the highest-risk findings.
    """
    findings: List[Finding] = []
    user_map = _user_lookup(users)

    # Build a map: principalId → list of priv role names
    priv_assignments: Dict[str, List[str]] = {}
    for ra in role_assignments:
        if ra["roleName"] in HIGH_PRIV_ROLES and ra["principalType"] == "user":
            priv_assignments.setdefault(ra["principalId"], []).append(ra["roleName"])

    for uid, role_names in priv_assignments.items():
        user = user_map.get(uid)
        if not user:
            continue
        if not user.get("accountEnabled"):
            continue   # disabled accounts handled separately

        age = _best_sign_in_age(user)
        if age is None:
            findings.append(Finding(
                category      = FindingCategory.OVERPRIVILEGED,
                risk          = RiskLevel.HIGH,
                principal_name= user["displayName"],
                principal_id  = uid,
                detail        = f"Holds privileged role(s): {', '.join(role_names)}. No sign-in activity on record.",
                recommendation= "Revoke privileged role(s) or confirm account legitimacy with the role owner. "
                                "If the account is a break-glass account, ensure it is properly documented.",
                evidence      = "lastSignIn: Never",
                cis_control   = "CIS Control 5.4 — Restrict Administrator Privileges",
            ))
        elif age > threshold_days:
            findings.append(Finding(
                category      = FindingCategory.OVERPRIVILEGED,
                risk          = RiskLevel.HIGH,
                principal_name= user["displayName"],
                principal_id  = uid,
                detail        = f"Holds privileged role(s): {', '.join(role_names)}. "
                                f"Last sign-in was {age} days ago (threshold: {threshold_days} days).",
                recommendation= "Conduct user attestation. If access is no longer required, remove the "
                                "privileged role. Consider Just-in-Time (PIM) activation.",
                evidence      = f"lastSignIn: {age} days ago",
                cis_control   = "CIS Control 5.4 — Restrict Administrator Privileges",
            ))

    return findings


def check_orphaned_accounts(
    users: List[Dict[str, Any]],
    threshold_days: int = INACTIVE_USER_DAYS,
) -> List[Finding]:
    """
    Flag enabled accounts that have never signed in, or whose last sign-in
    exceeds the threshold.  These may belong to ex-employees or contractors.
    """
    findings: List[Finding] = []
    for user in users:
        if not user.get("accountEnabled"):
            continue

        age = _best_sign_in_age(user)

        if age is None:
            created_age = _days_since(user.get("createdDateTime"))
            if created_age and created_age > 14:  # grace period for new accounts
                findings.append(Finding(
                    category      = FindingCategory.ORPHANED_ACCOUNT,
                    risk          = RiskLevel.MEDIUM,
                    principal_name= user["displayName"],
                    principal_id  = user["id"],
                    detail        = f"Account enabled but has never signed in. "
                                    f"Account age: {created_age} days.",
                    recommendation= "Confirm with HR/IT whether the account belongs to an active employee. "
                                    "Disable or delete if no owner can be identified.",
                    evidence      = f"accountEnabled: True | lastSignIn: Never | accountAge: {created_age}d",
                    cis_control   = "CIS Control 5.3 — Disable Dormant Accounts",
                ))
        elif age > threshold_days:
            findings.append(Finding(
                category      = FindingCategory.ORPHANED_ACCOUNT,
                risk          = RiskLevel.MEDIUM,
                principal_name= user["displayName"],
                principal_id  = user["id"],
                detail        = f"Account enabled but inactive for {age} days (threshold: {threshold_days}).",
                recommendation= "Initiate a user attestation with the line manager. "
                                "Disable the account pending confirmation of active employment.",
                evidence      = f"accountEnabled: True | lastSignIn: {age}d ago",
                cis_control   = "CIS Control 5.3 — Disable Dormant Accounts",
            ))

    return findings


def check_guest_with_elevated_roles(
    users: List[Dict[str, Any]],
    role_assignments: List[Dict[str, Any]],
) -> List[Finding]:
    """
    Flag Guest (B2B) users who hold any directory role.
    External identities should not hold elevated permissions.
    """
    findings: List[Finding] = []
    user_map = _user_lookup(users)

    for ra in role_assignments:
        if ra["principalType"] != "user":
            continue
        user = user_map.get(ra["principalId"])
        if not user:
            continue
        if user.get("userType", "").lower() == "guest":
            findings.append(Finding(
                category      = FindingCategory.GUEST_ELEVATED,
                risk          = RiskLevel.HIGH,
                principal_name= user["displayName"],
                principal_id  = user["id"],
                detail        = f"External Guest account holds directory role: {ra['roleName']}.",
                recommendation= "Remove the directory role from the guest account immediately. "
                                "External identities should only hold permissions scoped to specific resources.",
                evidence      = f"userType: Guest | role: {ra['roleName']}",
                cis_control   = "CIS Control 6.2 — Establish Access Granting Process",
            ))

    return findings


def check_stale_role_assignments(
    users: List[Dict[str, Any]],
    role_assignments: List[Dict[str, Any]],
    threshold_days: int = STALE_ROLE_DAYS,
) -> List[Finding]:
    """
    Flag role assignments where the principal's last sign-in indicates
    the role has not been exercised recently (stale permission).
    Excludes accounts already captured by the overprivileged check.
    """
    findings: List[Finding] = []
    user_map = _user_lookup(users)

    for ra in role_assignments:
        if ra["principalType"] != "user":
            continue
        if ra["roleName"] in HIGH_PRIV_ROLES:
            continue   # already covered by overprivileged check

        user = user_map.get(ra["principalId"])
        if not user or not user.get("accountEnabled"):
            continue

        age = _best_sign_in_age(user)
        if age is not None and age > threshold_days:
            findings.append(Finding(
                category      = FindingCategory.STALE_PERMISSION,
                risk          = RiskLevel.LOW,
                principal_name= user["displayName"],
                principal_id  = user["id"],
                detail        = f"Role \"{ra['roleName']}\" appears stale — user last signed in {age} days ago.",
                recommendation= "Review whether this role is still required. "
                                "If the role is project-specific, consider time-bound assignment via PIM.",
                evidence      = f"role: {ra['roleName']} | lastSignIn: {age}d ago",
                cis_control   = "CIS Control 6.8 — Define and Maintain Role-Based Access Control",
            ))

    return findings


def check_excessive_service_principals(
    service_principals: List[Dict[str, Any]],
    role_assignments: List[Dict[str, Any]],
) -> List[Finding]:
    """
    Flag service principals that hold a HIGH_PRIV_ROLES role.
    Machine identities with elevated permissions are a significant lateral
    movement risk if credentials are compromised.
    """
    findings: List[Finding] = []

    sp_priv: Dict[str, List[str]] = {}
    for ra in role_assignments:
        if ra["principalType"] == "servicePrincipal" and ra["roleName"] in HIGH_PRIV_ROLES:
            sp_priv.setdefault(ra["principalId"], []).append(ra["roleName"])

    sp_map = {sp["id"]: sp for sp in service_principals}

    for sp_id, role_names in sp_priv.items():
        sp = sp_map.get(sp_id)
        name = sp["displayName"] if sp else sp_id
        findings.append(Finding(
            category      = FindingCategory.EXCESSIVE_SP,
            risk          = RiskLevel.HIGH,
            principal_name= name,
            principal_id  = sp_id,
            detail        = f"Service principal holds privileged role(s): {', '.join(role_names)}. "
                            f"Type: {sp.get('spType', 'unknown') if sp else 'unknown'}.",
            recommendation= "Review whether the service principal requires these elevated permissions. "
                            "Apply least-privilege principle; prefer resource-scoped roles over directory roles.",
            evidence      = f"spType: {sp.get('spType', '') if sp else ''} | roles: {', '.join(role_names)}",
            cis_control   = "CIS Control 5.6 — Centralize Account Management",
        ))

    return findings


# ── orchestrator ──────────────────────────────────────────────────

def run_all_checks(
    users: List[Dict],
    role_assignments: List[Dict],
    service_principals: List[Dict],
) -> List[Finding]:
    """Run every check and return a combined, risk-sorted finding list."""
    all_findings: List[Finding] = []

    all_findings.extend(check_overprivileged_inactive(users, role_assignments))
    all_findings.extend(check_guest_with_elevated_roles(users, role_assignments))
    all_findings.extend(check_excessive_service_principals(service_principals, role_assignments))
    all_findings.extend(check_orphaned_accounts(users))
    all_findings.extend(check_stale_role_assignments(users, role_assignments))

    # Sort: High → Medium → Low → Info, then alphabetically by principal
    risk_order = {RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 1, RiskLevel.LOW: 2, RiskLevel.INFO: 3}
    all_findings.sort(key=lambda f: (risk_order[f.risk], f.principal_name))

    return all_findings
