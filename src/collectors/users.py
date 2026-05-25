"""
users.py — Pull all Entra ID users with their last sign-in timestamps.

Graph endpoint: GET /users
Selected properties keep the payload small — only fields we actually analyse.
Sign-in activity requires AuditLog.Read.All and an Entra ID P1/P2 licence.
"""
from __future__ import annotations
import asyncio
from typing import List, Dict, Any

from msgraph import GraphServiceClient
from msgraph.generated.users.users_request_builder import UsersRequestBuilder
from msgraph.generated.models.o_data_errors.o_data_error import ODataError
from kiota_abstractions.base_request_configuration import RequestConfiguration

from .graph_client import handle_odata_error

# Fields to select per user — minimise over-fetching
USER_SELECT = [
    "id", "displayName", "userPrincipalName", "mail",
    "accountEnabled", "createdDateTime", "userType",
    "signInActivity",          # last interactive + non-interactive sign-in
    "assignedLicenses",
]


async def fetch_all_users(client: GraphServiceClient) -> List[Dict[str, Any]]:
    """
    Fetch all users using automatic server-side pagination (Graph pages at 999).
    Returns a flat list of user dicts normalised for downstream analysis.
    """
    users: List[Dict[str, Any]] = []

    try:
        # Build a request with $select to minimise response size
        query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
            select=USER_SELECT,
            top=999,           # maximum allowed by Graph
            orderby=["displayName"],
        )
        config = RequestConfiguration(query_parameters=query_params)

        page = await client.users.get(request_configuration=config)

        while page:
            if page.value:
                for u in page.value:
                    users.append(_normalise_user(u))
            # Follow @odata.nextLink until exhausted
            if page.odata_next_link:
                page = await client.users.with_url(page.odata_next_link).get()
            else:
                break

    except ODataError as e:
        handle_odata_error(e, "fetch_all_users")

    print(f"[collector] Fetched {len(users)} users")
    return users


def _normalise_user(u) -> Dict[str, Any]:
    """Flatten Graph SDK user object → plain dict."""
    # Extract last sign-in datetimes (may be None for brand-new / never-signed-in accounts)
    sign_in = u.sign_in_activity
    last_interactive     = None
    last_non_interactive = None
    if sign_in:
        if sign_in.last_sign_in_date_time:
            last_interactive = sign_in.last_sign_in_date_time.isoformat()
        if sign_in.last_non_interactive_sign_in_date_time:
            last_non_interactive = sign_in.last_non_interactive_sign_in_date_time.isoformat()

    return {
        "id":                    u.id,
        "displayName":           u.display_name or "",
        "userPrincipalName":     u.user_principal_name or "",
        "mail":                  u.mail or "",
        "accountEnabled":        u.account_enabled,
        "createdDateTime":       u.created_date_time.isoformat() if u.created_date_time else None,
        "userType":              u.user_type or "Member",   # Member | Guest
        "lastInteractiveSignIn": last_interactive,
        "lastNonInteractiveSignIn": last_non_interactive,
        "hasLicenses":           bool(u.assigned_licenses),
    }
