"""
roles.py — Enumerate directory role assignments and Azure RBAC role assignments.

Two separate data sources:
  1. Entra ID / Azure AD directory roles (e.g. Global Administrator)
     → GET /directoryRoles and GET /directoryRoles/{id}/members
  2. Azure RBAC subscription-level role assignments (Owner, Contributor, etc.)
     → Graph does NOT expose ARM RBAC — see docs/aws_extension_notes.md for ARM approach.
     We query via the MS Graph "roleManagement" endpoint for Entra RBAC.
"""
from __future__ import annotations
from typing import List, Dict, Any

from msgraph import GraphServiceClient
from msgraph.generated.models.o_data_errors.o_data_error import ODataError

from .graph_client import handle_odata_error


async def fetch_directory_role_assignments(client: GraphServiceClient) -> List[Dict[str, Any]]:
    """
    Returns a list of {roleId, roleName, principalId, principalType} dicts.
    Iterates over every activated directory role and pages through its members.
    """
    assignments: List[Dict[str, Any]] = []

    try:
        # GET /directoryRoles — only returns *activated* roles in this tenant
        roles_page = await client.directory_roles.get()

        while roles_page:
            if roles_page.value:
                for role in roles_page.value:
                    role_assignments = await _get_role_members(client, role.id, role.display_name)
                    assignments.extend(role_assignments)
            if roles_page.odata_next_link:
                roles_page = await client.directory_roles.with_url(roles_page.odata_next_link).get()
            else:
                break

    except ODataError as e:
        handle_odata_error(e, "fetch_directory_role_assignments")

    print(f"[collector] Fetched {len(assignments)} role assignments across all directory roles")
    return assignments


async def _get_role_members(
    client: GraphServiceClient,
    role_id: str,
    role_name: str,
) -> List[Dict[str, Any]]:
    """Retrieve members of a single directory role."""
    members = []
    try:
        page = await client.directory_roles.by_directory_role_id(role_id).members.get()
        while page:
            if page.value:
                for m in page.value:
                    # odata_type distinguishes users, groups, service principals
                    principal_type = (m.odata_type or "#unknown").lstrip("#").split(".")[-1]
                    members.append({
                        "roleId":        role_id,
                        "roleName":      role_name,
                        "principalId":   m.id,
                        "principalType": principal_type,  # user | group | servicePrincipal
                    })
            if page.odata_next_link:
                page = await client.directory_roles.by_directory_role_id(role_id).members\
                           .with_url(page.odata_next_link).get()
            else:
                break
    except ODataError:
        pass   # role may have zero members; non-fatal
    return members


async def fetch_service_principals(client: GraphServiceClient) -> List[Dict[str, Any]]:
    """
    Return all service principals with their app role assignments.
    Service principals with high-privilege app roles (e.g. Mail.ReadWrite) are
    flagged as excessive-permission findings.
    """
    sps: List[Dict[str, Any]] = []
    try:
        page = await client.service_principals.get()
        while page:
            if page.value:
                for sp in page.value:
                    sps.append({
                        "id":          sp.id,
                        "displayName": sp.display_name or "",
                        "appId":       sp.app_id or "",
                        "enabled":     sp.account_enabled,
                        "spType":      sp.service_principal_type or "",  # Application | ManagedIdentity
                        "createdDateTime": sp.created_date_time.isoformat() if sp.created_date_time else None,
                    })
            if page.odata_next_link:
                page = await client.service_principals.with_url(page.odata_next_link).get()
            else:
                break
    except ODataError as e:
        handle_odata_error(e, "fetch_service_principals")

    print(f"[collector] Fetched {len(sps)} service principals")
    return sps
