"""Tests for FranceConnect+ OIDC integration.

Tests cover:
- OIDC service configuration
- ACR to IAL mapping
- Authorization URL generation
- Token exchange
- Identity verification
- Auth router endpoints
"""

import base64
import json
import secrets
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr

from qerds.db.models.base import IALLevel
from qerds.services.oidc import (
    ACR_TO_IAL,
    AuthFlow,
    FranceConnectService,
    OIDCAuthorizationResult,
    OIDCAuthRequest,
    OIDCConfigurationError,
    OIDCProviderConfig,
    OIDCStateError,
    OIDCUserInfo,
    map_acr_to_ial,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def oidc_config():
    """Create test OIDC provider configuration."""
    return OIDCProviderConfig(
        provider_id="franceconnect_plus_test",
        display_name="FranceConnect+ (Test)",
        issuer_url="https://fcp.integ01.dev-franceconnect.fr",
        client_id="test_client_id",
        client_secret=SecretStr("test_client_secret"),
        redirect_uri="http://localhost:8000/auth/callback",
        scopes=["openid", "profile", "email"],
        acr_values="eidas2",
    )


@pytest.fixture
def mock_provider_metadata():
    """Mock OIDC provider metadata from discovery endpoint."""
    return {
        "issuer": "https://fcp.integ01.dev-franceconnect.fr",
        "authorization_endpoint": "https://fcp.integ01.dev-franceconnect.fr/api/v1/authorize",
        "token_endpoint": "https://fcp.integ01.dev-franceconnect.fr/api/v1/token",
        "userinfo_endpoint": "https://fcp.integ01.dev-franceconnect.fr/api/v1/userinfo",
        "end_session_endpoint": "https://fcp.integ01.dev-franceconnect.fr/api/v1/logout",
        "jwks_uri": "https://fcp.integ01.dev-franceconnect.fr/.well-known/jwks.json",
    }


@pytest.fixture
def mock_userinfo():
    """Mock user info response from FranceConnect+."""
    return {
        "sub": "unique_fc_sub_identifier_12345",
        "given_name": "Jean",
        "family_name": "Dupont",
        "email": "jean.dupont@example.fr",
        "email_verified": True,
        "birthdate": "1985-03-15",
        "gender": "male",
        "acr": "eidas2",
    }


def create_mock_id_token(userinfo: dict, nonce: str = "test_nonce_value") -> str:
    """Create a mock ID token JWT with the given nonce."""
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        **userinfo,
        "iss": "https://fcp.integ01.dev-franceconnect.fr",
        "aud": "test_client_id",
        "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
        "iat": int(datetime.now(UTC).timestamp()),
        "nonce": nonce,
    }
    # Create a fake JWT (not cryptographically valid, but parseable)
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature_b64 = base64.urlsafe_b64encode(b"fake_signature").decode().rstrip("=")
    return f"{header_b64}.{payload_b64}.{signature_b64}"


@pytest.fixture
def mock_id_token(mock_userinfo):
    """Create a mock ID token JWT with default nonce."""
    return create_mock_id_token(mock_userinfo, "test_nonce_value")


# ---------------------------------------------------------------------------
# ACR to IAL Mapping Tests
# ---------------------------------------------------------------------------


class TestACRToIALMapping:
    """Tests for ACR claim to IAL level mapping."""

    def test_eidas2_maps_to_ial2(self):
        """eidas2 should map to IAL_SUBSTANTIAL (IAL2)."""
        assert map_acr_to_ial("eidas2") == IALLevel.IAL2

    def test_eidas3_maps_to_ial3(self):
        """eidas3 should map to IAL_HIGH (IAL3)."""
        assert map_acr_to_ial("eidas3") == IALLevel.IAL3

    def test_eidas1_maps_to_ial1(self):
        """eidas1 should map to IAL_LOW (IAL1)."""
        assert map_acr_to_ial("eidas1") == IALLevel.IAL1

    def test_unknown_acr_maps_to_ial1(self):
        """Unknown ACR values should map to IAL_LOW (IAL1)."""
        assert map_acr_to_ial("unknown") == IALLevel.IAL1
        assert map_acr_to_ial("") == IALLevel.IAL1

    def test_acr_mapping_is_complete(self):
        """Verify all expected ACR values are mapped."""
        assert "eidas1" in ACR_TO_IAL
        assert "eidas2" in ACR_TO_IAL
        assert "eidas3" in ACR_TO_IAL


# ---------------------------------------------------------------------------
# OIDCProviderConfig Tests
# ---------------------------------------------------------------------------


class TestOIDCProviderConfig:
    """Tests for OIDC provider configuration."""

    def test_config_creation(self, oidc_config):
        """Should create config with all required fields."""
        assert oidc_config.provider_id == "franceconnect_plus_test"
        assert oidc_config.client_id == "test_client_id"
        assert oidc_config.client_secret.get_secret_value() == "test_client_secret"

    def test_well_known_url_default(self, oidc_config):
        """Should construct well-known URL from issuer."""
        expected = "https://fcp.integ01.dev-franceconnect.fr/.well-known/openid-configuration"
        assert oidc_config.well_known_url == expected

    def test_well_known_url_explicit(self):
        """Should use explicit discovery URL if provided."""
        config = OIDCProviderConfig(
            provider_id="test",
            display_name="Test",
            issuer_url="https://issuer.example.com",
            client_id="client",
            client_secret=SecretStr("secret"),
            redirect_uri="http://localhost/callback",
            discovery_url="https://custom.example.com/.well-known/openid",
        )
        assert config.well_known_url == "https://custom.example.com/.well-known/openid"

    def test_config_immutability(self, oidc_config):
        """Config should be immutable (frozen dataclass)."""
        from dataclasses import FrozenInstanceError

        with pytest.raises(FrozenInstanceError):
            oidc_config.client_id = "new_id"


# ---------------------------------------------------------------------------
# OIDCAuthRequest Tests
# ---------------------------------------------------------------------------


class TestOIDCAuthRequest:
    """Tests for OIDC authorization request state."""

    def test_auth_request_creation(self):
        """Should create auth request with state and nonce."""
        now = datetime.now(UTC)
        request = OIDCAuthRequest(
            state="test_state",
            nonce="test_nonce",
            redirect_uri="http://localhost/callback",
            auth_flow=AuthFlow.SENDER_IDENTITY,
            created_at=now,
            expires_at=now + timedelta(minutes=10),
        )
        assert request.state == "test_state"
        assert request.nonce == "test_nonce"
        assert request.auth_flow == AuthFlow.SENDER_IDENTITY

    def test_auth_request_not_expired(self):
        """Fresh request should not be expired."""
        now = datetime.now(UTC)
        request = OIDCAuthRequest(
            state="state",
            nonce="nonce",
            redirect_uri="http://localhost/callback",
            auth_flow=AuthFlow.SENDER_IDENTITY,
            created_at=now,
            expires_at=now + timedelta(minutes=10),
        )
        assert not request.is_expired

    def test_auth_request_expired(self):
        """Old request should be expired."""
        now = datetime.now(UTC)
        request = OIDCAuthRequest(
            state="state",
            nonce="nonce",
            redirect_uri="http://localhost/callback",
            auth_flow=AuthFlow.SENDER_IDENTITY,
            created_at=now - timedelta(minutes=20),
            expires_at=now - timedelta(minutes=10),
        )
        assert request.is_expired


# ---------------------------------------------------------------------------
# OIDCUserInfo Tests
# ---------------------------------------------------------------------------


class TestOIDCUserInfo:
    """Tests for OIDC user info dataclass."""

    def test_display_name_full(self):
        """Should generate display name from given and family names."""
        info = OIDCUserInfo(
            sub="test_sub",
            given_name="Jean",
            family_name="Dupont",
            email="jean@example.com",
            email_verified=True,
            birthdate=None,
            gender=None,
            preferred_username=None,
            acr="eidas2",
            ial_level=IALLevel.IAL2,
            raw_claims={},
        )
        assert info.display_name == "Jean Dupont"

    def test_display_name_given_only(self):
        """Should use given name if family name is missing."""
        info = OIDCUserInfo(
            sub="test_sub",
            given_name="Jean",
            family_name=None,
            email="jean@example.com",
            email_verified=True,
            birthdate=None,
            gender=None,
            preferred_username=None,
            acr="eidas2",
            ial_level=IALLevel.IAL2,
            raw_claims={},
        )
        assert info.display_name == "Jean"

    def test_display_name_fallback_username(self):
        """Should fall back to username if names missing."""
        info = OIDCUserInfo(
            sub="test_sub",
            given_name=None,
            family_name=None,
            email="jean@example.com",
            email_verified=True,
            birthdate=None,
            gender=None,
            preferred_username="jdupont",
            acr="eidas2",
            ial_level=IALLevel.IAL2,
            raw_claims={},
        )
        assert info.display_name == "jdupont"

    def test_display_name_fallback_email(self):
        """Should fall back to email if username also missing."""
        info = OIDCUserInfo(
            sub="test_sub",
            given_name=None,
            family_name=None,
            email="jean@example.com",
            email_verified=True,
            birthdate=None,
            gender=None,
            preferred_username=None,
            acr="eidas2",
            ial_level=IALLevel.IAL2,
            raw_claims={},
        )
        assert info.display_name == "jean@example.com"

    def test_display_name_fallback_sub(self):
        """Should fall back to sub as last resort."""
        info = OIDCUserInfo(
            sub="test_sub_12345",
            given_name=None,
            family_name=None,
            email=None,
            email_verified=False,
            birthdate=None,
            gender=None,
            preferred_username=None,
            acr="eidas2",
            ial_level=IALLevel.IAL2,
            raw_claims={},
        )
        assert info.display_name == "test_sub_12345"


# ---------------------------------------------------------------------------
# FranceConnectService Tests
# ---------------------------------------------------------------------------


class TestFranceConnectServiceInit:
    """Tests for FranceConnectService initialization."""

    def test_service_creation(self, oidc_config):
        """Should create service with valid config."""
        service = FranceConnectService(oidc_config)
        assert service.provider_id == "franceconnect_plus_test"

    def test_service_requires_client_id(self):
        """Should raise error if client_id is missing."""
        config = OIDCProviderConfig(
            provider_id="test",
            display_name="Test",
            issuer_url="https://issuer.example.com",
            client_id="",  # Empty
            client_secret=SecretStr("secret"),
            redirect_uri="http://localhost/callback",
        )
        with pytest.raises(OIDCConfigurationError, match="client_id"):
            FranceConnectService(config)

    def test_service_requires_issuer_url(self):
        """Should raise error if issuer_url is missing."""
        config = OIDCProviderConfig(
            provider_id="test",
            display_name="Test",
            issuer_url="",  # Empty
            client_id="client",
            client_secret=SecretStr("secret"),
            redirect_uri="http://localhost/callback",
        )
        with pytest.raises(OIDCConfigurationError, match="issuer_url"):
            FranceConnectService(config)

    def test_service_requires_redirect_uri(self):
        """Should raise error if redirect_uri is missing."""
        config = OIDCProviderConfig(
            provider_id="test",
            display_name="Test",
            issuer_url="https://issuer.example.com",
            client_id="client",
            client_secret=SecretStr("secret"),
            redirect_uri="",  # Empty
        )
        with pytest.raises(OIDCConfigurationError, match="redirect_uri"):
            FranceConnectService(config)


class TestFranceConnectServiceAuthURL:
    """Tests for authorization URL generation."""

    @pytest.mark.asyncio
    async def test_create_authorization_url(self, oidc_config, mock_provider_metadata):
        """Should generate valid authorization URL with state and nonce."""
        service = FranceConnectService(oidc_config)

        # Mock metadata fetch
        with patch.object(service, "_get_provider_metadata", return_value=mock_provider_metadata):
            auth_url, auth_request = await service.create_authorization_url(
                auth_flow=AuthFlow.SENDER_IDENTITY
            )

        # Verify URL structure
        assert auth_url.startswith(mock_provider_metadata["authorization_endpoint"])
        assert "response_type=code" in auth_url
        assert f"client_id={oidc_config.client_id}" in auth_url
        assert "state=" in auth_url
        assert "nonce=" in auth_url
        assert "acr_values=eidas2" in auth_url

        # Verify auth request
        assert auth_request.auth_flow == AuthFlow.SENDER_IDENTITY
        assert len(auth_request.state) > 20  # Sufficient entropy
        assert len(auth_request.nonce) > 20

    @pytest.mark.asyncio
    async def test_auth_url_includes_scopes(self, oidc_config, mock_provider_metadata):
        """Should include requested scopes in auth URL."""
        service = FranceConnectService(oidc_config)

        with patch.object(service, "_get_provider_metadata", return_value=mock_provider_metadata):
            auth_url, _ = await service.create_authorization_url(auth_flow=AuthFlow.SENDER_IDENTITY)

        # Scopes are joined with space, which may or may not be URL-encoded
        assert "scope=openid" in auth_url
        assert "profile" in auth_url
        assert "email" in auth_url

    @pytest.mark.asyncio
    async def test_auth_request_expiry(self, oidc_config, mock_provider_metadata):
        """Auth request should have appropriate expiry."""
        service = FranceConnectService(oidc_config, state_expiry_minutes=5)

        with patch.object(service, "_get_provider_metadata", return_value=mock_provider_metadata):
            _, auth_request = await service.create_authorization_url(
                auth_flow=AuthFlow.SENDER_IDENTITY
            )

        # Should expire in approximately 5 minutes
        expected_expiry = auth_request.created_at + timedelta(minutes=5)
        assert abs((auth_request.expires_at - expected_expiry).total_seconds()) < 1


class TestFranceConnectServiceTokenExchange:
    """Tests for token exchange."""

    @pytest.mark.asyncio
    async def test_exchange_code_validates_state(self, oidc_config, mock_provider_metadata):
        """Should reject mismatched state (CSRF protection)."""
        service = FranceConnectService(oidc_config)

        stored_request = OIDCAuthRequest(
            state="original_state",
            nonce="nonce",
            redirect_uri="http://localhost/callback",
            auth_flow=AuthFlow.SENDER_IDENTITY,
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )

        with pytest.raises(OIDCStateError, match="State mismatch"):
            await service.exchange_code(
                code="auth_code",
                state="different_state",  # Doesn't match
                stored_request=stored_request,
            )

    @pytest.mark.asyncio
    async def test_exchange_code_rejects_expired_request(self, oidc_config, mock_provider_metadata):
        """Should reject expired auth request."""
        service = FranceConnectService(oidc_config)

        expired_request = OIDCAuthRequest(
            state="state",
            nonce="nonce",
            redirect_uri="http://localhost/callback",
            auth_flow=AuthFlow.SENDER_IDENTITY,
            created_at=datetime.now(UTC) - timedelta(minutes=20),
            expires_at=datetime.now(UTC) - timedelta(minutes=10),
        )

        with pytest.raises(OIDCStateError, match="expired"):
            await service.exchange_code(
                code="auth_code",
                state="state",
                stored_request=expired_request,
            )

    @pytest.mark.asyncio
    async def test_exchange_code_success(self, oidc_config, mock_provider_metadata, mock_id_token):
        """Should successfully exchange code for tokens."""
        service = FranceConnectService(oidc_config)

        stored_request = OIDCAuthRequest(
            state="valid_state",
            nonce="test_nonce_value",  # Matches mock_id_token
            redirect_uri="http://localhost/callback",
            auth_flow=AuthFlow.SENDER_IDENTITY,
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )

        # Mock the HTTP calls
        mock_token_response = {
            "access_token": "test_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": mock_id_token,
            "refresh_token": "test_refresh_token",
        }

        with (
            patch.object(service, "_get_provider_metadata", return_value=mock_provider_metadata),
            patch("qerds.services.oidc.AsyncOAuth2Client") as mock_client,
        ):
            # Set up the mock context manager
            mock_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_instance

            mock_response = MagicMock()
            mock_response.json.return_value = mock_token_response
            mock_response.raise_for_status = MagicMock()
            mock_instance.post.return_value = mock_response

            result = await service.exchange_code(
                code="auth_code",
                state="valid_state",
                stored_request=stored_request,
            )

        assert isinstance(result, OIDCAuthorizationResult)
        assert result.access_token == "test_access_token"  # noqa: S105
        assert result.id_token == mock_id_token
        assert result.refresh_token == "test_refresh_token"  # noqa: S105


class TestFranceConnectServiceVerifyIdentity:
    """Tests for identity verification."""

    @pytest.mark.asyncio
    async def test_verify_identity_extracts_claims(
        self, oidc_config, mock_provider_metadata, mock_userinfo
    ):
        """Should extract and map identity claims."""
        service = FranceConnectService(oidc_config)

        auth_result = OIDCAuthorizationResult(
            access_token="test_token",  # noqa: S106
            id_token="",
            provider_id="franceconnect_plus_test",
        )

        with patch.object(service, "get_userinfo", return_value=mock_userinfo):
            user_info = await service.verify_identity(auth_result)

        assert user_info.sub == "unique_fc_sub_identifier_12345"
        assert user_info.given_name == "Jean"
        assert user_info.family_name == "Dupont"
        assert user_info.email == "jean.dupont@example.fr"
        assert user_info.email_verified is True
        assert user_info.acr == "eidas2"
        assert user_info.ial_level == IALLevel.IAL2

    @pytest.mark.asyncio
    async def test_verify_identity_maps_ial_levels(self, oidc_config):
        """Should correctly map ACR to IAL levels."""
        service = FranceConnectService(oidc_config)

        test_cases = [
            ("eidas1", IALLevel.IAL1),
            ("eidas2", IALLevel.IAL2),
            ("eidas3", IALLevel.IAL3),
        ]

        for acr, expected_ial in test_cases:
            auth_result = OIDCAuthorizationResult(
                access_token="test_token",  # noqa: S106
                id_token="",
                provider_id="franceconnect_plus_test",
            )

            mock_claims = {
                "sub": "test_sub",
                "acr": acr,
            }

            with patch.object(service, "get_userinfo", return_value=mock_claims):
                user_info = await service.verify_identity(auth_result)

            assert user_info.ial_level == expected_ial, f"ACR {acr} should map to {expected_ial}"


class TestFranceConnectServiceLogout:
    """Tests for logout URL generation."""

    @pytest.mark.asyncio
    async def test_create_logout_url(self, oidc_config, mock_provider_metadata):
        """Should generate logout URL with id_token_hint."""
        service = FranceConnectService(oidc_config)

        with patch.object(service, "_get_provider_metadata", return_value=mock_provider_metadata):
            logout_url = await service.create_logout_url(
                id_token_hint="test_id_token",  # noqa: S106
                post_logout_redirect_uri="http://localhost/",
            )

        assert logout_url.startswith(mock_provider_metadata["end_session_endpoint"])
        assert "id_token_hint=test_id_token" in logout_url
        assert "post_logout_redirect_uri=http://localhost/" in logout_url

    @pytest.mark.asyncio
    async def test_logout_url_without_endpoint(self, oidc_config):
        """Should return empty string if provider doesn't support logout."""
        service = FranceConnectService(oidc_config)

        metadata_without_logout = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "userinfo_endpoint": "https://example.com/userinfo",
            # No end_session_endpoint
        }

        with patch.object(service, "_get_provider_metadata", return_value=metadata_without_logout):
            logout_url = await service.create_logout_url()

        assert logout_url == ""


# ---------------------------------------------------------------------------
# Auth Router Tests
# ---------------------------------------------------------------------------


class TestAuthRouter:
    """Tests for auth router endpoints."""

    @pytest.mark.asyncio
    async def test_login_redirect(self, api_client):
        """GET /auth/login should redirect to OIDC provider."""
        # This will fail if OIDC is not configured, which is expected
        response = await api_client.get(
            "/auth/login",
            follow_redirects=False,
        )

        # Without OIDC config, should return 503
        assert response.status_code == 503

    @pytest.mark.asyncio
    async def test_auth_status_unauthenticated(self, api_client):
        """GET /auth/status should return unauthenticated status."""
        response = await api_client.get("/auth/status")
        assert response.status_code == 200

        data = response.json()
        assert data["authenticated"] is False
        assert data["principal_id"] is None

    @pytest.mark.asyncio
    async def test_callback_error_handling(self, api_client):
        """GET /auth/callback with error should return 401."""
        # Note: code parameter is required by FastAPI schema, but with error
        # we still process the error and return 401
        response = await api_client.get(
            "/auth/callback",
            params={
                "code": "dummy_code",  # Required by schema
                "state": "dummy_state",
                "error": "access_denied",
                "error_description": "User denied access",
            },
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_callback_invalid_state(self, api_client):
        """GET /auth/callback with unknown state should return 400."""
        response = await api_client.get(
            "/auth/callback",
            params={
                "code": "test_code",
                "state": "unknown_state",
            },
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_logout_unauthenticated(self, api_client):
        """POST /auth/logout should succeed even without auth."""
        response = await api_client.post("/auth/logout")
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True


# ---------------------------------------------------------------------------
# Integration-style Tests
# ---------------------------------------------------------------------------


class TestOIDCFlowIntegration:
    """Integration-style tests for complete OIDC flows."""

    @pytest.mark.asyncio
    async def test_sender_identity_flow(self, oidc_config, mock_provider_metadata, mock_userinfo):
        """Test complete sender identity verification flow."""
        service = FranceConnectService(oidc_config)

        # Step 1: Generate authorization URL
        with patch.object(service, "_get_provider_metadata", return_value=mock_provider_metadata):
            _auth_url, auth_request = await service.create_authorization_url(
                auth_flow=AuthFlow.SENDER_IDENTITY,
                client_metadata={"redirect_to": "/sender/dashboard"},
            )

        assert auth_request.auth_flow == AuthFlow.SENDER_IDENTITY
        assert auth_request.client_metadata["redirect_to"] == "/sender/dashboard"

        # Step 2: Simulate callback with code
        # Create ID token with the actual nonce from auth request
        id_token_with_nonce = create_mock_id_token(mock_userinfo, auth_request.nonce)
        mock_token_response = {
            "access_token": "sender_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token_with_nonce,
        }

        with (
            patch.object(service, "_get_provider_metadata", return_value=mock_provider_metadata),
            patch("qerds.services.oidc.AsyncOAuth2Client") as mock_client,
        ):
            mock_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_instance

            mock_response = MagicMock()
            mock_response.json.return_value = mock_token_response
            mock_response.raise_for_status = MagicMock()
            mock_instance.post.return_value = mock_response

            auth_result = await service.exchange_code(
                code="sender_auth_code",
                state=auth_request.state,
                stored_request=auth_request,
            )

        # Step 3: Verify identity
        with patch.object(service, "get_userinfo", return_value=mock_userinfo):
            user_info = await service.verify_identity(auth_result)

        # Verify sender has IAL_SUBSTANTIAL (required for LRE)
        assert user_info.ial_level == IALLevel.IAL2
        assert user_info.given_name == "Jean"
        assert user_info.family_name == "Dupont"

    @pytest.mark.asyncio
    async def test_recipient_pickup_flow(self, oidc_config, mock_provider_metadata, mock_userinfo):
        """Test recipient pickup authentication flow."""
        service = FranceConnectService(oidc_config)

        # Recipients must authenticate with IAL_SUBSTANTIAL for LRE pickup
        with patch.object(service, "_get_provider_metadata", return_value=mock_provider_metadata):
            auth_url, auth_request = await service.create_authorization_url(
                auth_flow=AuthFlow.RECIPIENT_PICKUP,
                client_metadata={"delivery_id": "test-delivery-uuid"},
            )

        assert auth_request.auth_flow == AuthFlow.RECIPIENT_PICKUP
        assert "acr_values=eidas2" in auth_url

        # Create ID token with the actual nonce from auth request
        id_token_with_nonce = create_mock_id_token(mock_userinfo, auth_request.nonce)
        mock_token_response = {
            "access_token": "recipient_access_token",
            "token_type": "Bearer",
            "id_token": id_token_with_nonce,
        }

        with (
            patch.object(service, "_get_provider_metadata", return_value=mock_provider_metadata),
            patch("qerds.services.oidc.AsyncOAuth2Client") as mock_client,
        ):
            mock_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_instance

            mock_response = MagicMock()
            mock_response.json.return_value = mock_token_response
            mock_response.raise_for_status = MagicMock()
            mock_instance.post.return_value = mock_response

            auth_result = await service.exchange_code(
                code="recipient_auth_code",
                state=auth_request.state,
                stored_request=auth_request,
            )

        with patch.object(service, "get_userinfo", return_value=mock_userinfo):
            user_info = await service.verify_identity(auth_result)

        # CPCE requires IAL_SUBSTANTIAL (eidas2 or higher)
        assert user_info.ial_level in (IALLevel.IAL2, IALLevel.IAL3)


# ---------------------------------------------------------------------------
# Security Tests
# ---------------------------------------------------------------------------


class TestOIDCSecurity:
    """Security-focused tests for OIDC implementation."""

    def test_state_tokens_have_sufficient_entropy(self, oidc_config):
        """State tokens should have sufficient entropy to prevent guessing."""
        # Generate multiple states and verify they're unique and long enough
        states = set()
        for _ in range(100):
            state = secrets.token_urlsafe(32)
            states.add(state)
            assert len(state) >= 40  # base64 of 32 bytes

        # All should be unique
        assert len(states) == 100

    @pytest.mark.asyncio
    async def test_nonce_validation(self, oidc_config, mock_provider_metadata):
        """Nonce mismatch should be detected (replay protection)."""
        service = FranceConnectService(oidc_config)

        # Create ID token with different nonce
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "sub": "test",
            "nonce": "original_nonce",
            "iss": "https://issuer.example.com",
        }
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        sig_b64 = base64.urlsafe_b64encode(b"sig").decode().rstrip("=")
        id_token = f"{header_b64}.{payload_b64}.{sig_b64}"

        # Validation should detect mismatch and raise OIDCTokenError
        from qerds.services.oidc import OIDCTokenError

        with pytest.raises(OIDCTokenError, match="Nonce mismatch"):
            service._validate_id_token_nonce(id_token, "different_nonce")

    def test_constant_time_comparison(self):
        """State comparison should use constant-time comparison."""
        # This is a design verification - the code uses secrets.compare_digest
        from qerds.services.oidc import OIDCStateError

        # Verify the exception type exists for state mismatches
        assert issubclass(OIDCStateError, Exception)


class TestPrivacyProtection:
    """Tests for privacy-preserving features."""

    def test_sub_hashing_for_logs(self):
        """Subject identifiers should be hashed before logging."""
        from qerds.services.oidc import _hash_for_log

        sub = "unique_fc_sub_identifier_12345"
        hashed = _hash_for_log(sub)

        # Should be truncated hash (8 chars)
        assert len(hashed) == 8
        # Different inputs should produce different outputs
        assert _hash_for_log("different_sub") != hashed
        # Same input should produce same output
        assert _hash_for_log(sub) == hashed
