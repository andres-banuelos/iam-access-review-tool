"""Microsoft Graph collectors for directory roles and service principals."""

from __future__ import annotations

import logging
from typing import Any

from msgraph import GraphServiceClient
from msgraph.generated.models.o_data_errors.o_data_error import ODataError

from .graph_client import raise_graph_error

LOGGER = logging.getLogger(__name__)


async def fetch_directory_role_assignments(
    client: GraphServiceClient,
) -> list[dict[str, Any]]:
    """Fetch directory role memberships across all activated roles."""
    assignments: list[dict[str, Any]] = []

    try:
        roles_page = await client.directory_roles.get()

        while roles_page:
            if roles_page.value:
                for role in roles_page.value:
                    assignments.extend(
                        await _get_role_members(
                            client=client,
                            role_id=role.id,
                            role_name=role.display_name or "Unknown Role",
                        )
                    )

            if not roles_page.odata_next_link:
                break
            roles_page = await client.directory_roles.with_url(roles_page.odata_next_link).get()

    except ODataError as err:
        raise_graph_error(err, "fetch_directory_role_assignments")

    LOGGER.info("Fetched %s directory role assignments", len(assignments))
    return assignments


async def _get_role_members(
    client: GraphServiceClient,
    role_id: str,
    role_name: str,
) -> list[dict[str, Any]]:
    """Fetch members for a single activated directory role."""
    members: list[dict[str, Any]] = []

    try:
        page = await client.directory_roles.by_directory_role_id(role_id).members.get()

        while page:
            if page.value:
                for member in page.value:
                    principal_type = _normalize_principal_type(member.odata_type)
                    members.append(
                        {
                            "roleId": role_id,
                            "roleName": role_name,
                            "principalId": member.id,
                            "principalType": principal_type,
                        }
                    )

            if not page.odata_next_link:
                break
            page = (
                await client.directory_roles.by_directory_role_id(role_id)
                .members.with_url(page.odata_next_link)
                .get()
            )

    except ODataError as err:
        LOGGER.warning(
            "Skipping role '%s' (%s) because member enumeration failed: %s",
            role_name,
            role_id,
            err,
        )

    return members


async def fetch_service_principals(client: GraphServiceClient) -> list[dict[str, Any]]:
    """Fetch service principals relevant to identity access review analysis."""
    service_principals: list[dict[str, Any]] = []

    try:
        page = await client.service_principals.get()

        while page:
            if page.value:
                for sp in page.value:
                    service_principals.append(
                        {
                            "id": sp.id,
                            "displayName": sp.display_name or "",
                            "appId": sp.app_id or "",
                            "enabled": bool(sp.account_enabled),
                            "spType": sp.service_principal_type or "",
                            "createdDateTime": (
                                sp.created_date_time.isoformat()
                                if sp.created_date_time
                                else None
                            ),
                        }
                    )

            if not page.odata_next_link:
                break
            page = await client.service_principals.with_url(page.odata_next_link).get()

    except ODataError as err:
        raise_graph_error(err, "fetch_service_principals")

    LOGGER.info("Fetched %s service principals", len(service_principals))
    return service_principals



def _normalize_principal_type(odata_type: str | None) -> str:
    """Normalize Graph OData type values to stable analyzer labels."""
    if not odata_type:
        return "unknown"

    normalized = odata_type.lstrip("#").split(".")[-1]
    aliases = {
        "user": "user",
        "servicePrincipal": "servicePrincipal",
        "group": "group",
    }
    return aliases.get(normalized, normalized)
