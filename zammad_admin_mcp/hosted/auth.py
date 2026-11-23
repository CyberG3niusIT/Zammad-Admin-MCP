from __future__ import annotations

import asyncio
import os
import time

import jwt
from mcp.server.auth.provider import AccessToken, TokenVerifier

from . import repository
from .egress import validate_issuer_url


class HostedTokenVerifier(TokenVerifier):
    def __init__(self, resource_url: str, issuer_url: str, allowed_clients: set[str] | None = None):
        self.resource_url = resource_url.rstrip("/")
        self.issuer_url = validate_issuer_url(issuer_url)
        self.allowed_clients = allowed_clients if allowed_clients is not None else {value.strip() for value in os.environ.get("MCP_OAUTH_ALLOWED_CLIENT_IDS", "").split(",") if value.strip()}
        if not self.allowed_clients:
            raise RuntimeError("MCP_OAUTH_ALLOWED_CLIENT_IDS must list the authorized OAuth client IDs")
        self.jwks = jwt.PyJWKClient(self.issuer_url + ".well-known/jwks.json")

    async def verify_token(self, token: str) -> AccessToken | None:
        if token.startswith("zammcp_"):
            row = await repository.resolve_personal_token(token)
            if not row:
                return None
            identity = {"issuer": row["issuer"], "subject": row["subject"], "tenant_id": row["tenant_id"], "auth_method": "pat", "token_id": row["id"]}
            return AccessToken(token=token, client_id="zammad-admin-mcp", subject=row["subject"], claims=identity, scopes=row["scopes"], expires_at=int(row["expires_at"].timestamp()), resource=self.resource_url)
        try:
            signing_key = await asyncio.to_thread(self.jwks.get_signing_key_from_jwt, token)
            claims = jwt.decode(token, signing_key.key, algorithms=["RS256", "ES256"], issuer=self.issuer_url, audience=self.resource_url, options={"require": ["exp", "iat", "sub"]})
        except Exception:
            return None
        issuer = claims.get("iss")
        subject = claims.get("sub")
        client_id = claims.get("azp", claims.get("client_id"))
        scope_claim = claims.get("scope", "")
        if (
            not isinstance(issuer, str) or not isinstance(subject, str)
            or not isinstance(client_id, str)
            or client_id not in self.allowed_clients
            or not isinstance(scope_claim, (str, list))
            or isinstance(scope_claim, list) and any(not isinstance(scope, str) for scope in scope_claim)
        ):
            return None
        identity = await repository.resolve_identity(issuer, subject)
        if not identity:
            return None
        scopes = scope_claim
        if isinstance(scopes, str):
            scopes = scopes.split()
        return AccessToken(token=token, client_id=client_id, subject=subject, claims={"issuer": issuer, "subject": subject, "tenant_id": identity["tenant_id"], "auth_method": "oauth"}, scopes=scopes, expires_at=int(claims["exp"]), resource=self.resource_url)
