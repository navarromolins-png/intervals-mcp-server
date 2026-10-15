"""
OAuth 2.0 authorization server for the Intervals.icu MCP Server.

Implements a minimal single-client OAuth provider that supports the
authorization code + PKCE flow used by Claude.ai and other MCP clients.
No persistent storage is needed: the client_secret is issued as the
access token, so tokens survive server restarts automatically.

Configure via:
  MCP_CLIENT_ID     — OAuth client ID to register in Claude.ai
  MCP_CLIENT_SECRET — OAuth client secret (also used as the access token)
  MCP_SERVER_URL    — Public HTTPS URL of this server (required for OAuth discovery)
"""

import secrets
import time
from typing import Any

from pydantic import AnyHttpUrl, AnyUrl

from fastmcp.server.auth import AccessToken, OAuthProvider
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import InvalidRedirectUriError, OAuthClientInformationFull, OAuthToken

# Authorization codes are valid for 5 minutes.
_AUTH_CODE_TTL_SECONDS = 300


class _FlexibleClient(OAuthClientInformationFull):
    """OAuthClientInformationFull that accepts any redirect URI and scope.

    This is safe for personal deployments because the authorization code
    flow still requires PKCE (code_challenge / code_verifier), so a
    stolen code cannot be exchanged without the original code_verifier.
    """

    def validate_redirect_uri(self, redirect_uri: Any) -> Any:
        if redirect_uri is None:
            raise InvalidRedirectUriError("redirect_uri must be specified")
        return redirect_uri

    def validate_scope(self, requested_scope: Any) -> Any:
        # Accept whatever scope the client requests. This single-client
        # deployment does not enforce scopes (the client_secret is the only
        # credential). The base class would reject any scope — including the
        # empty "scope=" that MCP clients such as Claude.ai send — because the
        # client is registered without scopes, which breaks the auth flow.
        if requested_scope is None:
            return None
        return [s for s in requested_scope.split(" ") if s]


class SingleClientOAuthProvider(OAuthProvider):
    """Minimal OAuth 2.0 authorization server for single-client personal deployments.

    Implements the authorization code + PKCE flow. Auto-approves the
    authorization step (no login screen) and issues the client_secret as
    the access token so no server-side state is needed across restarts.
    """

    def __init__(self, client_id: str, client_secret: str, base_url: AnyHttpUrl | str) -> None:
        # This server is both the authorization server and the resource
        # server, so issuer_url/resource_base_url both point at base_url.
        super().__init__(base_url=base_url, issuer_url=base_url, resource_base_url=base_url)
        self._client_id = client_id
        self._client_secret = client_secret
        self._codes: dict[str, AuthorizationCode] = {}

    async def get_client(self, client_id: str) -> _FlexibleClient | None:
        if client_id != self._client_id:
            return None
        return _FlexibleClient(
            client_id=self._client_id,
            client_secret=self._client_secret,
            # Placeholder satisfies min_length=1; validate_redirect_uri is overridden
            redirect_uris=[AnyUrl("https://placeholder.invalid")],
            grant_types=["authorization_code"],
            response_types=["code"],
            # Must be set explicitly: mcp >= 1.23 defaults this to None and the
            # token endpoint then rejects every request with "Unsupported auth
            # method: None". Clients send the secret in the token request body.
            token_endpoint_auth_method="client_secret_post",
        )

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        raise NotImplementedError("Dynamic client registration is not supported")

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        code = secrets.token_urlsafe(32)
        self._codes[code] = AuthorizationCode(
            code=code,
            client_id=client.client_id or self._client_id,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            code_challenge=params.code_challenge,
            scopes=list(params.scopes or []),
            expires_at=time.time() + _AUTH_CODE_TTL_SECONDS,
        )
        return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code = self._codes.get(authorization_code)
        if code is None:
            return None
        if code.expires_at < time.time():
            del self._codes[authorization_code]
            return None
        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        self._codes.pop(authorization_code.code, None)
        return OAuthToken(access_token=self._client_secret, token_type="Bearer")

    async def load_access_token(self, token: str) -> AccessToken | None:
        if secrets.compare_digest(token, self._client_secret):
            return AccessToken(token=token, client_id=self._client_id, scopes=[])
        return None

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> None:
        return None

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:

      
# --- Accept client_secret_basic as well as client_secret_post ---------------
# Claude.ai sends the client secret in an HTTP Basic Authorization header (and
# may omit client_id from the form body). The SDK only reads the method the
# client is registered with, so Basic requests were rejected with 401. Turn a
# valid Basic header into the equivalent form fields before the SDK checks it.
import base64 as _b64  # noqa: E402
from urllib.parse import unquote as _unquote  # noqa: E402
 
from mcp.server.auth.middleware.client_auth import (  # noqa: E402
    AuthenticationError as _AuthErr,
    ClientAuthenticator as _ClientAuthenticator,
)
from starlette.datastructures import FormData as _FormData  # noqa: E402
 
_sdk_authenticate = _ClientAuthenticator.authenticate_request
 
 
async def _authenticate_post_or_basic(self, request):  # type: ignore[no-untyped-def]
    header = request.headers.get("Authorization", "")
    if header.startswith("Basic "):
        try:
            cid, secret = _b64.b64decode(header[6:]).decode("utf-8").split(":", 1)
        except (ValueError, UnicodeDecodeError):
            raise _AuthErr("Invalid Basic authentication header")
        cid, secret = _unquote(cid), _unquote(secret)
        form = await request.form()
        if form.get("client_id") not in (None, "", cid):
            raise _AuthErr("Client ID mismatch in Basic auth")
        items = [(k, v) for k, v in form.multi_items() if k not in ("client_id", "client_secret")]
        request._form = _FormData(items + [("client_id", cid), ("client_secret", secret)])
    return await _sdk_authenticate(self, request)
 
 
_ClientAuthenticator.authenticate_request = _authenticate_post_or_basic  # type: ignore[method-assign]
 
        raise NotImplementedError("Refresh tokens are not supported")

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        pass
