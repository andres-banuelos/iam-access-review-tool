"""Microsoft Graph user collection and normalization utilities."""

from __future__ import annotations

import logging
from typing import Any

from kiota_abstractions.base_request_configuration import RequestConfiguration
from msgraph import GraphServiceClient
from msgraph.generated.models.user import User
from msgraph.generated.models.o_data_errors.o_data_error import ODataError
from msgraph.generated.users.users_request_builder import UsersRequestBuilder

from .graph_client import raise_graph_error

LOGGER = logging.getLogger(__name__)

USER_SELECT = [
    "id",
    "displayName",
    "userPrincipalName",
    "mail",
    "accountEnabled",
    "createdDateTime",
    "userType",
    "signInActivity",
    "assignedLicenses",
]


async def fetch_all_users(client: GraphServiceClient) -> list[dict[str, Any]]:
    """Fetch and normalize all Entra ID users."""
    users: list[dict[str, Any]] = []

    try:
        query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
            select=USER_SELECT,
            top=999,
            orderby=["displayName"],
        )
        config = RequestConfiguration(query_parameters=query_params)
        page = await client.users.get(request_configuration=config)

        while page:
            if page.value:
                users.extend(_normalize_user(user) for user in page.value)

            if not page.odata_next_link:
                break
            page = await client.users.with_url(page.odata_next_link).get()

    except ODataError as err:
        raise_graph_error(err, "fetch_all_users")

    LOGGER.info("Fetched %s users", len(users))
    return users



def _normalize_user(user: User) -> dict[str, Any]:
    """Convert an SDK user model into an analyzer-friendly dictionary."""
    sign_in = user.sign_in_activity
    last_interactive_sign_in = (
        sign_in.last_sign_in_date_time.isoformat()
        if sign_in and sign_in.last_sign_in_date_time
        else None
    )
    last_non_interactive_sign_in = (
        sign_in.last_non_interactive_sign_in_date_time.isoformat()
        if sign_in and sign_in.last_non_interactive_sign_in_date_time
        else None
    )

    return {
        "id": user.id,
        "displayName": user.display_name or "",
        "userPrincipalName": user.user_principal_name or "",
        "mail": user.mail or "",
        "accountEnabled": bool(user.account_enabled),
        "createdDateTime": user.created_date_time.isoformat() if user.created_date_time else None,
        "userType": user.user_type or "Member",
        "lastInteractiveSignIn": last_interactive_sign_in,
        "lastNonInteractiveSignIn": last_non_interactive_sign_in,
        "hasLicenses": bool(user.assigned_licenses),
    }
