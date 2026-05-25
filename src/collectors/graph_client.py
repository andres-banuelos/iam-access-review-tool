"""
graph_client.py — Thin wrapper around Microsoft Graph SDK.

Uses ClientSecretCredential (app-only flow) with read-only permissions:
  • User.Read.All          — enumerate users + sign-in activity
  • AuditLog.Read.All      — sign-in logs (requires Entra P1/P2)
  • Directory.Read.All     — directory roles, service principals, app registrations

The SDK handles token caching and automatic refresh internally.
"""
from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient
from msgraph.generated.models.o_data_errors.o_data_error import ODataError
import sys

from src.config import TENANT_ID, CLIENT_ID, CLIENT_SECRET

# Graph API requires this scope for app-only access
SCOPES = ["https://graph.microsoft.com/.default"]


def get_graph_client() -> GraphServiceClient:
    """Authenticate as a service principal and return a Graph client."""
    credential = ClientSecretCredential(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
    )
    return GraphServiceClient(credentials=credential, scopes=SCOPES)


def handle_odata_error(err: ODataError, context: str) -> None:
    """Pretty-print Graph API errors so they're actionable during development."""
    code    = err.error.code    if err.error else "unknown"
    message = err.error.message if err.error else str(err)
    print(f"[GraphAPI Error] {context} → {code}: {message}", file=sys.stderr)
    if code in ("Authorization_RequestDenied", "Forbidden"):
        print("  ↳ Check that the app registration has the required Graph permissions "
              "AND that admin consent has been granted.", file=sys.stderr)
    raise err
