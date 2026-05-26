"""Thin Graph client wrapper with consistent error handling and logging."""

from __future__ import annotations

import logging

from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient
from msgraph.generated.models.o_data_errors.o_data_error import ODataError

from src.config import SETTINGS

LOGGER = logging.getLogger(__name__)
SCOPES = ["https://graph.microsoft.com/.default"]


class GraphCollectionError(RuntimeError):
    """Raised when a Microsoft Graph collection request fails."""



def get_graph_client() -> GraphServiceClient:
    """Create and return an authenticated Microsoft Graph client."""
    credential = ClientSecretCredential(
        tenant_id=SETTINGS.tenant_id,
        client_id=SETTINGS.client_id,
        client_secret=SETTINGS.client_secret,
    )
    return GraphServiceClient(credentials=credential, scopes=SCOPES)



def raise_graph_error(err: ODataError, context: str) -> None:
    """Raise a descriptive application error for Graph failures."""
    code = err.error.code if err.error else "unknown"
    message = err.error.message if err.error else str(err)
    guidance = ""

    if code in {"Authorization_RequestDenied", "Forbidden"}:
        guidance = (
            " Check that the app registration has the required Microsoft Graph "
            "application permissions and that admin consent has been granted."
        )

    LOGGER.error("Graph API error during %s: %s - %s", context, code, message)
    raise GraphCollectionError(f"{context} failed: {code}: {message}.{guidance}") from err
