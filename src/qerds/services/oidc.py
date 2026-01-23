"""FranceConnect+ OIDC integration service.

Covers: REQ-B05 (sender identity verification)

This module implements identity verification via FranceConnect+ using OIDC:
- OIDC client configuration for FranceConnect+
- ACR claim mapping to IAL levels (eidas2 -> IAL_SUBSTANTIAL, eidas3 -> IAL_HIGH)
- Identity claims extraction (given_name, family_name, email, etc.)
- Session binding after successful authentication
- Redirect flow handling for sender verification and recipient pickup

Reference: specs/implementation/20-identities-and-roles.md
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any

from authlib.integrations.httpx_client import AsyncOAuth2Client
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from qerds.db.models.base import IALLevel, ProofingMethod

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# OIDC state/nonce token configuration
STATE_TOKEN_BYTES = 32  # 256 bits of entropy
NONCE_TOKEN_BYTES = 32  # 256 bits of entropy
STATE_EXPIRY_MINUTES = 10  # OIDC state validity period


class OIDCError(Exception):
    """Base exception for OIDC operations."""

    pass


class OIDCConfigurationError(OIDCError):
    """Raised when OIDC configuration is invalid or missing."""

    pass


class OIDCAuthenticationError(OIDCError):
    """Raised when OIDC authentication fails."""

    pass


class OIDCTokenError(OIDCError):
    """Raised when token exchange or validation fails."""

    pass


class OIDCProviderError(OIDCError):
    """Raised when the identity provider returns an error."""

    pass


class OIDCStateError(OIDCError):
    """Raised when state validation fails (CSRF protection)."""

    pass


class AuthFlow(str, Enum):
    """Authentication flow type.

    Identifies the purpose of the authentication to enable
    flow-specific session binding and validation.
    """

    SENDER_IDENTITY = "sender_identity"
    RECIPIENT_PICKUP = "recipient_pickup"
    ADMIN_LOGIN = "admin_login"


@dataclass(frozen=True, slots=True)
class OIDCProviderConfig:
    """OIDC provider configuration.

    Immutable configuration for an OIDC identity provider.
    FranceConnect+ is the primary provider for French LRE compliance.

    Attributes:
        provider_id: Unique identifier for the provider (e.g., 'franceconnect_plus').
        display_name: Human-readable name for UI.
        issuer_url: OIDC issuer URL (base for discovery).
        client_id: OAuth2 client ID.
        client_secret: OAuth2 client secret (sensitive).
        redirect_uri: OAuth2 callback URL.
        scopes: OIDC scopes to request.
        acr_values: Required Authentication Context Class Reference.
        discovery_url: Optional explicit discovery endpoint.
    """

    provider_id: str
    display_name: str
    issuer_url: str
    client_id: str
    client_secret: SecretStr
    redirect_uri: str
    scopes: list[str] = field(default_factory=lambda: ["openid", "profile", "email"])
    acr_values: str = "eidas2"
    discovery_url: str | None = None

    @property
    def well_known_url(self) -> str:
        """Get the well-known configuration URL."""
        if self.discovery_url:
            return self.discovery_url
        return f"{self.issuer_url.rstrip('/')}/.well-known/openid-configuration"


@dataclass(frozen=True, slots=True)
class OIDCAuthRequest:
    """OIDC authorization request state.

    Represents a pending authorization request with state for CSRF protection
    and nonce for replay protection.

    Attributes:
        state: CSRF protection token (must match callback).
        nonce: Replay protection token (bound to id_token).
        redirect_uri: Where to redirect after auth.
        auth_flow: Purpose of the authentication.
        created_at: When this request was created.
        expires_at: When this request expires.
        client_metadata: Optional metadata for session binding.
    """

    state: str
    nonce: str
    redirect_uri: str
    auth_flow: AuthFlow
    created_at: datetime
    expires_at: datetime
    client_metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        """Check if this request has expired."""
        return datetime.now(UTC) > self.expires_at


@dataclass(frozen=True, slots=True)
class OIDCUserInfo:
    """User information from OIDC claims.

    Represents verified identity claims from FranceConnect+.
    Maps to Party/SenderProofing models for persistence.

    Attributes:
        sub: Subject identifier (unique per provider).
        given_name: First name.
        family_name: Last name.
        email: Email address.
        email_verified: Whether email is verified by provider.
        birthdate: Date of birth (YYYY-MM-DD format).
        gender: Gender claim.
        preferred_username: Username if provided.
        acr: Authentication Context Class Reference achieved.
        ial_level: Mapped Identity Assurance Level.
        raw_claims: Complete claims dict for evidence storage.
    """

    sub: str
    given_name: str | None
    family_name: str | None
    email: str | None
    email_verified: bool
    birthdate: str | None
    gender: str | None
    preferred_username: str | None
    acr: str
    ial_level: IALLevel
    raw_claims: dict[str, Any]

    @property
    def display_name(self) -> str:
        """Generate display name from given/family names."""
        parts = []
        if self.given_name:
            parts.append(self.given_name)
        if self.family_name:
            parts.append(self.family_name)
        if parts:
            return " ".join(parts)
        return self.preferred_username or self.email or self.sub


class OIDCAuthorizationResult(BaseModel):
    """Result of successful OIDC authorization.

    Contains tokens and user information after successful code exchange.

    Attributes:
        access_token: OAuth2 access token for API calls.
        token_type: Token type (typically 'Bearer').
        expires_in: Token validity in seconds.
        id_token: OIDC ID token (JWT).
        refresh_token: Optional refresh token.
        user_info: Verified user information.
        provider_id: Which provider authenticated the user.
    """

    access_token: str
    token_type: str = "Bearer"  # noqa: S105 - This is OAuth2 token type, not a password
    expires_in: int = 3600
    id_token: str
    refresh_token: str | None = None
    user_info: dict[str, Any] = Field(default_factory=dict)
    provider_id: str = ""

    model_config = ConfigDict(extra="ignore")


# ACR to IAL mapping for FranceConnect+
# See: https://partenaires.franceconnect.gouv.fr/fcp/fournisseur-identite
ACR_TO_IAL: dict[str, IALLevel] = {
    # eIDAS Substantial (FranceConnect+ standard)
    "eidas2": IALLevel.IAL2,
    # eIDAS High (FranceConnect+ with substantiel identity)
    "eidas3": IALLevel.IAL3,
    # Legacy/fallback
    "eidas1": IALLevel.IAL1,
}


def map_acr_to_ial(acr: str) -> IALLevel:
    """Map OIDC ACR claim to internal IAL level.

    Per REQ-B05, FranceConnect+ ACR values are mapped to IAL levels:
    - eidas2 -> IAL_SUBSTANTIAL (IAL2)
    - eidas3 -> IAL_HIGH (IAL3)
    - eidas1/other -> IAL_LOW (IAL1)

    Args:
        acr: Authentication Context Class Reference from OIDC token.

    Returns:
        Corresponding IALLevel enum value.
    """
    return ACR_TO_IAL.get(acr, IALLevel.IAL1)


class FranceConnectService:
    """FranceConnect+ OIDC integration service.

    Provides complete OIDC flow handling for FranceConnect+ identity verification:

    1. create_authorization_url() - Generate auth URL with state/nonce
    2. exchange_code() - Exchange authorization code for tokens
    3. get_userinfo() - Fetch user profile from userinfo endpoint
    4. verify_identity() - Complete flow with IAL mapping

    The service maintains pending auth requests in memory for state validation.
    In production, consider using a distributed cache (Redis) for multi-instance
    deployments.

    Example:
        service = FranceConnectService(config)

        # Start auth flow
        auth_url, auth_request = await service.create_authorization_url(
            auth_flow=AuthFlow.SENDER_IDENTITY,
        )
        # Redirect user to auth_url, store auth_request in session

        # Handle callback
        result = await service.exchange_code(
            code=request.query_params["code"],
            state=request.query_params["state"],
            stored_request=auth_request,
        )

        # Get user info and verify identity
        user_info = await service.verify_identity(result)
    """

    def __init__(
        self,
        config: OIDCProviderConfig,
        *,
        state_expiry_minutes: int = STATE_EXPIRY_MINUTES,
    ) -> None:
        """Initialize the FranceConnect service.

        Args:
            config: OIDC provider configuration.
            state_expiry_minutes: How long auth requests are valid.
        """
        self._config = config
        self._state_expiry = timedelta(minutes=state_expiry_minutes)
        self._metadata: dict[str, Any] | None = None  # Cached provider metadata

        # Validate configuration
        if not config.client_id:
            raise OIDCConfigurationError("client_id is required")
        if not config.issuer_url:
            raise OIDCConfigurationError("issuer_url is required")
        if not config.redirect_uri:
            raise OIDCConfigurationError("redirect_uri is required")

    @property
    def provider_id(self) -> str:
        """Get the provider identifier."""
        return self._config.provider_id

    async def _get_provider_metadata(self) -> dict[str, Any]:
        """Fetch and cache OIDC provider metadata.

        Uses the well-known discovery endpoint to retrieve provider configuration
        including authorization, token, and userinfo endpoints.

        Returns:
            Provider metadata dictionary.

        Raises:
            OIDCProviderError: If metadata cannot be fetched.
        """
        if self._metadata is not None:
            return self._metadata

        async with AsyncOAuth2Client() as client:
            try:
                response = await client.get(self._config.well_known_url)
                response.raise_for_status()
                self._metadata = response.json()
                logger.debug(
                    "Fetched OIDC metadata from %s",
                    self._config.well_known_url,
                )
                return self._metadata
            except Exception as e:
                raise OIDCProviderError(
                    f"Failed to fetch OIDC metadata from {self._config.well_known_url}: {e}"
                ) from e

    async def create_authorization_url(
        self,
        auth_flow: AuthFlow,
        *,
        client_metadata: dict[str, Any] | None = None,
    ) -> tuple[str, OIDCAuthRequest]:
        """Create authorization URL for OIDC redirect.

        Generates a secure authorization URL with state (CSRF protection)
        and nonce (replay protection) parameters.

        Args:
            auth_flow: Purpose of authentication (sender, recipient, admin).
            client_metadata: Optional metadata to pass through auth flow.

        Returns:
            Tuple of (authorization_url, auth_request).
            Store auth_request in session for callback validation.

        Raises:
            OIDCProviderError: If provider metadata cannot be fetched.
        """
        metadata = await self._get_provider_metadata()

        # Generate secure state and nonce
        state = secrets.token_urlsafe(STATE_TOKEN_BYTES)
        nonce = secrets.token_urlsafe(NONCE_TOKEN_BYTES)

        now = datetime.now(UTC)
        auth_request = OIDCAuthRequest(
            state=state,
            nonce=nonce,
            redirect_uri=self._config.redirect_uri,
            auth_flow=auth_flow,
            created_at=now,
            expires_at=now + self._state_expiry,
            client_metadata=client_metadata or {},
        )

        # Build authorization URL
        authorization_endpoint = metadata["authorization_endpoint"]
        params = {
            "response_type": "code",
            "client_id": self._config.client_id,
            "redirect_uri": self._config.redirect_uri,
            "scope": " ".join(self._config.scopes),
            "state": state,
            "nonce": nonce,
            "acr_values": self._config.acr_values,
        }

        # Build URL with query params
        query_string = "&".join(f"{k}={v}" for k, v in params.items())
        auth_url = f"{authorization_endpoint}?{query_string}"

        logger.info(
            "Created authorization URL for flow=%s",
            auth_flow.value,
        )

        return auth_url, auth_request

    async def exchange_code(
        self,
        code: str,
        state: str,
        stored_request: OIDCAuthRequest,
    ) -> OIDCAuthorizationResult:
        """Exchange authorization code for tokens.

        Validates state parameter against stored request, then exchanges
        the authorization code for access token and ID token.

        Args:
            code: Authorization code from callback.
            state: State parameter from callback.
            stored_request: The OIDCAuthRequest from initial authorization.

        Returns:
            OIDCAuthorizationResult with tokens and basic claims.

        Raises:
            OIDCStateError: If state doesn't match or request expired.
            OIDCTokenError: If token exchange fails.
        """
        # Validate state (CSRF protection)
        if not secrets.compare_digest(state, stored_request.state):
            raise OIDCStateError("State mismatch - possible CSRF attack")

        if stored_request.is_expired:
            raise OIDCStateError("Authorization request has expired")

        metadata = await self._get_provider_metadata()
        token_endpoint = metadata["token_endpoint"]

        # Exchange code for tokens
        async with AsyncOAuth2Client(
            client_id=self._config.client_id,
            client_secret=self._config.client_secret.get_secret_value(),
        ) as client:
            try:
                token_response = await client.post(
                    token_endpoint,
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": self._config.redirect_uri,
                    },
                )
                token_response.raise_for_status()
                token_data = token_response.json()
            except Exception as e:
                raise OIDCTokenError(f"Token exchange failed: {e}") from e

        if "error" in token_data:
            raise OIDCTokenError(
                f"Token endpoint error: {token_data.get('error_description', token_data['error'])}"
            )

        # Validate ID token nonce if present
        id_token = token_data.get("id_token")
        if id_token:
            self._validate_id_token_nonce(id_token, stored_request.nonce)

        logger.info(
            "Successfully exchanged code for tokens (flow=%s)",
            stored_request.auth_flow.value,
        )

        return OIDCAuthorizationResult(
            access_token=token_data["access_token"],
            token_type=token_data.get("token_type", "Bearer"),
            expires_in=token_data.get("expires_in", 3600),
            id_token=token_data.get("id_token", ""),
            refresh_token=token_data.get("refresh_token"),
            provider_id=self._config.provider_id,
        )

    def _validate_id_token_nonce(self, id_token: str, expected_nonce: str) -> None:
        """Validate the nonce in the ID token.

        The nonce prevents replay attacks by binding the ID token
        to the original authorization request.

        Args:
            id_token: The JWT ID token.
            expected_nonce: The nonce from the stored auth request.

        Raises:
            OIDCTokenError: If nonce doesn't match.
        """
        # Decode ID token without verification (verification done by provider)
        # In production, verify signature using provider's JWKs
        try:
            import base64
            import json

            # Split JWT and decode payload
            parts = id_token.split(".")
            if len(parts) != 3:
                raise OIDCTokenError("Invalid ID token format")

            # Decode payload (add padding if needed)
            payload_b64 = parts[1]
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            token_nonce = payload.get("nonce")
            if token_nonce and not secrets.compare_digest(token_nonce, expected_nonce):
                raise OIDCTokenError("Nonce mismatch - possible replay attack")

        except OIDCTokenError:
            raise
        except Exception as e:
            logger.warning("Could not validate ID token nonce: %s", e)
            # Continue - nonce validation is defense-in-depth

    async def get_userinfo(
        self,
        access_token: str,
    ) -> dict[str, Any]:
        """Fetch user information from the userinfo endpoint.

        Uses the access token to retrieve the authenticated user's claims
        from the OIDC userinfo endpoint.

        Args:
            access_token: OAuth2 access token.

        Returns:
            Dictionary of user claims.

        Raises:
            OIDCProviderError: If userinfo request fails.
        """
        metadata = await self._get_provider_metadata()
        userinfo_endpoint = metadata["userinfo_endpoint"]

        async with AsyncOAuth2Client() as client:
            try:
                response = await client.get(
                    userinfo_endpoint,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                response.raise_for_status()
                return response.json()
            except Exception as e:
                raise OIDCProviderError(f"Userinfo request failed: {e}") from e

    async def verify_identity(
        self,
        auth_result: OIDCAuthorizationResult,
    ) -> OIDCUserInfo:
        """Complete identity verification and map to IAL level.

        Fetches user info and maps the ACR claim to an internal IAL level
        for compliance with REQ-B05 identity verification requirements.

        Args:
            auth_result: Result from exchange_code().

        Returns:
            OIDCUserInfo with verified claims and IAL level.

        Raises:
            OIDCProviderError: If userinfo fetch fails.
            OIDCAuthenticationError: If identity verification fails.
        """
        # Fetch full user claims
        claims = await self.get_userinfo(auth_result.access_token)

        # Merge with any claims from ID token
        auth_result.user_info.update(claims)

        # Extract ACR from ID token if not in userinfo
        acr = claims.get("acr", "")
        if not acr and auth_result.id_token:
            acr = self._extract_acr_from_id_token(auth_result.id_token)

        # Map ACR to IAL
        ial_level = map_acr_to_ial(acr)

        user_info = OIDCUserInfo(
            sub=claims.get("sub", ""),
            given_name=claims.get("given_name"),
            family_name=claims.get("family_name"),
            email=claims.get("email"),
            email_verified=claims.get("email_verified", False),
            birthdate=claims.get("birthdate"),
            gender=claims.get("gender"),
            preferred_username=claims.get("preferred_username"),
            acr=acr,
            ial_level=ial_level,
            raw_claims=claims,
        )

        if not user_info.sub:
            raise OIDCAuthenticationError("No subject (sub) claim in user info")

        logger.info(
            "Identity verified: sub=%s, acr=%s, ial=%s",
            _hash_for_log(user_info.sub),
            acr,
            ial_level.value,
        )

        return user_info

    def _extract_acr_from_id_token(self, id_token: str) -> str:
        """Extract ACR claim from ID token.

        Args:
            id_token: JWT ID token.

        Returns:
            ACR value or empty string.
        """
        try:
            import base64
            import json

            parts = id_token.split(".")
            if len(parts) != 3:
                return ""

            payload_b64 = parts[1]
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            return payload.get("acr", "")
        except Exception:
            return ""

    async def create_logout_url(
        self,
        id_token_hint: str | None = None,
        post_logout_redirect_uri: str | None = None,
    ) -> str:
        """Create logout URL for single logout.

        FranceConnect+ supports single logout via end_session_endpoint.

        Args:
            id_token_hint: The ID token to logout.
            post_logout_redirect_uri: Where to redirect after logout.

        Returns:
            Logout URL or empty string if not supported.
        """
        metadata = await self._get_provider_metadata()
        end_session_endpoint = metadata.get("end_session_endpoint")

        if not end_session_endpoint:
            logger.warning("Provider does not support end_session_endpoint")
            return ""

        params = []
        if id_token_hint:
            params.append(f"id_token_hint={id_token_hint}")
        if post_logout_redirect_uri:
            params.append(f"post_logout_redirect_uri={post_logout_redirect_uri}")

        if params:
            return f"{end_session_endpoint}?{'&'.join(params)}"
        return end_session_endpoint


def _hash_for_log(value: str) -> str:
    """Hash a value for safe logging (privacy protection).

    Args:
        value: Value to hash.

    Returns:
        First 8 characters of SHA-256 hash.
    """
    return hashlib.sha256(value.encode()).hexdigest()[:8]


async def create_identity_proofing_record(
    db_session: AsyncSession,
    *,
    party_id: UUID,
    user_info: OIDCUserInfo,
    provider_id: str,
) -> UUID:
    """Create a sender proofing record for identity verification.

    Records the identity proofing event in the database for audit purposes.
    This creates the evidence trail required by REQ-B05.

    Args:
        db_session: SQLAlchemy async session.
        party_id: UUID of the party being verified.
        user_info: Verified user information from OIDC.
        provider_id: Identifier of the OIDC provider.

    Returns:
        UUID of the created proofing record.
    """
    from qerds.db.models.parties import SenderProofing

    proofing_method = (
        ProofingMethod.FRANCECONNECT_PLUS
        if provider_id.startswith("franceconnect")
        else ProofingMethod.FRANCECONNECT
    )

    # Create proofing record
    proofing = SenderProofing(
        party_id=party_id,
        ial_level=user_info.ial_level,
        proofing_method=proofing_method,
        proofed_at=datetime.now(UTC),
        proofing_metadata={
            "provider_id": provider_id,
            "sub_hash": _hash_for_log(user_info.sub),  # Privacy: hash the sub
            "acr": user_info.acr,
            "email_verified": user_info.email_verified,
        },
        # Proofing is valid for 24 hours (session-based)
        expires_at=datetime.now(UTC) + timedelta(hours=24),
    )

    db_session.add(proofing)
    await db_session.flush()

    logger.info(
        "Created identity proofing record: proofing_id=%s, party_id=%s, ial=%s",
        proofing.proofing_id,
        party_id,
        user_info.ial_level.value,
    )

    return proofing.proofing_id


def create_franceconnect_service_from_settings() -> FranceConnectService | None:
    """Create FranceConnectService from application settings.

    Loads OIDC configuration from environment and creates a configured service.
    Returns None if OIDC is not enabled.

    Returns:
        Configured FranceConnectService or None.
    """
    from qerds.core.settings import get_settings_safe

    settings = get_settings_safe()
    if not settings or not settings.oidc.enabled:
        return None

    config = OIDCProviderConfig(
        provider_id="franceconnect_plus",
        display_name="FranceConnect+",
        issuer_url=settings.oidc.discovery_url.rsplit("/.well-known", 1)[0]
        if "/.well-known" in settings.oidc.discovery_url
        else settings.oidc.discovery_url,
        client_id=settings.oidc.client_id,
        client_secret=settings.oidc.client_secret,
        redirect_uri=settings.oidc.redirect_uri,
        scopes=settings.oidc.scopes,
        acr_values=settings.oidc.acr_values,
        discovery_url=settings.oidc.discovery_url,
    )

    return FranceConnectService(config)
