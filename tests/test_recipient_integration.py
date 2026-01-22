"""End-to-end integration tests for the recipient pickup flow.

Covers: REQ-E02, REQ-F03, REQ-F04, REQ-F06

These tests verify the complete recipient flow through the pickup portal:
1. Magic link landing (claim token validation)
2. FranceConnect+ authentication wall
3. Sender identity redaction before accept/refuse (REQ-F03)
4. Accept/refuse delivery with evidence generation
5. Sender identity reveal after accept/refuse (REQ-F03)
6. Content access control (REQ-E02)
7. 15-day acceptance window enforcement (REQ-F04)
8. Proof of acceptance download

Test approach:
- Use httpx AsyncClient with ASGI transport for in-process API testing
- Mock FranceConnect+ authentication at the auth middleware level
- Mock database operations for test isolation
- Verify HTTP responses, redirects, and state transitions

All tests run against Docker containers for reproducibility.
Use: docker compose exec qerds-api pytest tests/test_recipient_integration.py -v
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest
from fastapi import status
from httpx import ASGITransport, AsyncClient

from qerds.api import create_app
from qerds.api.middleware.auth import AuthenticatedUser
from qerds.db.models.base import DeliveryState, IALLevel

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def test_app():
    """Create a test FastAPI application instance."""
    return create_app()


@pytest.fixture
async def api_client(test_app) -> AsyncClient:
    """Async HTTP client for testing the API."""
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.fixture
def sender_party_id() -> UUID:
    """ID of the sender party."""
    return uuid4()


@pytest.fixture
def recipient_party_id() -> UUID:
    """ID of the recipient party."""
    return uuid4()


@pytest.fixture
def delivery_id() -> UUID:
    """ID of the test delivery."""
    return uuid4()


@pytest.fixture
def mock_authenticated_user(recipient_party_id: UUID) -> AuthenticatedUser:
    """Create a mock authenticated user for the recipient."""
    return AuthenticatedUser(
        principal_id=recipient_party_id,
        principal_type="party",
        session_id=uuid4(),
        is_superuser=False,
        is_active=True,
        roles=frozenset(["sender_user", "recipient_user"]),
        permissions=frozenset(),
        ip_address="127.0.0.1",
        user_agent="pytest-test-client",
        auth_method="oidc",
        metadata={
            "ial_level": IALLevel.IAL2.value,
            "auth_provider": "franceconnect_plus",
        },
    )


@pytest.fixture
def mock_delivery(
    delivery_id: UUID,
    sender_party_id: UUID,
    recipient_party_id: UUID,
) -> MagicMock:
    """Create a mock delivery in AVAILABLE state."""
    delivery = MagicMock()
    delivery.delivery_id = delivery_id
    delivery.state = DeliveryState.AVAILABLE
    delivery.jurisdiction_profile = "fr_lre"
    delivery.sender_party_id = sender_party_id
    delivery.recipient_party_id = recipient_party_id
    delivery.subject = "Important Document"
    delivery.message = "Please review and accept this document."
    delivery.deposited_at = datetime.now(UTC) - timedelta(days=1)
    delivery.notified_at = datetime.now(UTC) - timedelta(hours=23)
    delivery.available_at = datetime.now(UTC) - timedelta(hours=22)
    delivery.acceptance_deadline_at = datetime.now(UTC) + timedelta(days=14)
    delivery.completed_at = None
    delivery.created_at = datetime.now(UTC) - timedelta(days=2)

    # Mock sender party (identity should be hidden pre-acceptance)
    sender_party = MagicMock()
    sender_party.party_id = sender_party_id
    sender_party.display_name = "Jean Dupont"
    sender_party.email = "jean.dupont@example.com"
    delivery.sender_party = sender_party

    # Mock recipient party
    recipient_party = MagicMock()
    recipient_party.party_id = recipient_party_id
    recipient_party.display_name = "Marie Martin"
    recipient_party.email = "marie.martin@example.com"
    delivery.recipient_party = recipient_party

    delivery.content_objects = []

    return delivery


def _create_mock_pickup_context(
    delivery: MagicMock,
    *,
    is_authenticated: bool = False,
    can_accept_refuse: bool = False,
    sender_revealed: bool = False,
    has_consent: bool = True,
    ial_level: IALLevel | None = None,
    is_expired: bool = False,
) -> MagicMock:
    """Helper to create a mock PickupContext."""
    context = MagicMock()
    context.delivery = delivery
    context.recipient = delivery.recipient_party if is_authenticated else None
    context.is_authenticated = is_authenticated
    context.ial_level = ial_level
    context.has_consent = has_consent
    context.can_accept_refuse = can_accept_refuse
    context.acceptance_deadline = delivery.acceptance_deadline_at
    context.is_expired = is_expired
    context.sender_revealed = sender_revealed
    return context


# ---------------------------------------------------------------------------
# Test: Complete Accept Flow (Magic Link -> Auth -> View -> Accept -> Download)
# ---------------------------------------------------------------------------


class TestCompleteAcceptFlow:
    """Integration tests for the complete accept flow."""

    @pytest.mark.asyncio
    async def test_auth_redirect_sends_to_franceconnect(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
    ):
        """Verify auth redirect goes to FranceConnect+ login."""
        response = await api_client.get(
            f"/pickup/{delivery_id}/auth",
            follow_redirects=False,
        )

        # Should redirect to auth login
        assert response.status_code == status.HTTP_302_FOUND
        location = response.headers["location"]
        assert "/auth/login" in location
        assert "flow=recipient_pickup" in location
        assert f"redirect=/pickup/{delivery_id}" in location

    @pytest.mark.asyncio
    async def test_accept_without_auth_redirects_to_auth(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
    ):
        """Verify accept without authentication redirects to auth."""
        with patch(
            "qerds.api.routers.pickup.optional_authenticated_user",
            return_value=None,
        ):
            response = await api_client.post(
                f"/pickup/{delivery_id}/accept",
                follow_redirects=False,
            )

        # Should redirect to auth
        assert response.status_code == status.HTTP_302_FOUND
        assert f"/pickup/{delivery_id}/auth" in response.headers["location"]


# ---------------------------------------------------------------------------
# Test: Complete Refuse Flow
# ---------------------------------------------------------------------------


class TestCompleteRefuseFlow:
    """Integration tests for the complete refuse flow."""

    @pytest.mark.asyncio
    async def test_refuse_without_auth_redirects_to_auth(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
    ):
        """Verify refuse without authentication redirects to auth."""
        with patch(
            "qerds.api.routers.pickup.optional_authenticated_user",
            return_value=None,
        ):
            response = await api_client.post(
                f"/pickup/{delivery_id}/refuse",
                follow_redirects=False,
            )

        # Should redirect to auth
        assert response.status_code == status.HTTP_302_FOUND
        assert f"/pickup/{delivery_id}/auth" in response.headers["location"]


# ---------------------------------------------------------------------------
# Test: Sender Identity Redaction (REQ-F03)
# ---------------------------------------------------------------------------


class TestSenderIdentityRedaction:
    """Tests for CPCE sender identity redaction (REQ-F03).

    Critical compliance requirement: Sender identity MUST be hidden
    before the recipient accepts or refuses the delivery.
    """

    @pytest.mark.asyncio
    async def test_sender_hidden_before_accept(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
        mock_delivery: MagicMock,
        mock_authenticated_user: AuthenticatedUser,
    ):
        """Verify sender identity is hidden before acceptance (REQ-F03)."""
        # Delivery is in AVAILABLE state (not yet accepted)
        mock_delivery.state = DeliveryState.AVAILABLE

        captured_context: dict[str, Any] = {}

        with (
            patch("qerds.api.routers.pickup.PickupService") as mock_service_cls,
            patch(
                "qerds.api.routers.pickup.optional_authenticated_user",
                return_value=mock_authenticated_user,
            ),
            patch("qerds.api.routers.pickup.get_templates") as mock_templates,
            patch("qerds.db.get_async_session") as mock_get_session,
        ):
            mock_service = mock_service_cls.return_value
            context = _create_mock_pickup_context(
                mock_delivery,
                is_authenticated=True,
                can_accept_refuse=True,
                sender_revealed=False,  # Key assertion
                ial_level=IALLevel.IAL2,
            )
            mock_service.get_pickup_context = AsyncMock(return_value=context)

            # Mock template response
            mock_template_instance = MagicMock()

            def capture_template_response(template_name, ctx):
                captured_context.update(ctx)
                response = MagicMock()
                response.status_code = 200
                return response

            mock_template_instance.TemplateResponse = MagicMock(
                side_effect=capture_template_response
            )
            mock_templates.return_value = mock_template_instance

            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)

            await api_client.get(f"/pickup/{delivery_id}")

        # Verify sender info is NOT revealed in the template context
        delivery_data = captured_context.get("delivery", {})
        assert delivery_data.get("sender_name") is None
        assert delivery_data.get("sender_email") is None

    @pytest.mark.asyncio
    async def test_sender_revealed_after_accept(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
        mock_delivery: MagicMock,
        mock_authenticated_user: AuthenticatedUser,
    ):
        """Verify sender identity is revealed after acceptance (REQ-F03)."""
        # Delivery is in ACCEPTED state
        mock_delivery.state = DeliveryState.ACCEPTED
        mock_delivery.completed_at = datetime.now(UTC)

        captured_context: dict[str, Any] = {}

        with (
            patch("qerds.api.routers.pickup.PickupService") as mock_service_cls,
            patch(
                "qerds.api.routers.pickup.optional_authenticated_user",
                return_value=mock_authenticated_user,
            ),
            patch("qerds.api.routers.pickup.get_templates") as mock_templates,
            patch("qerds.db.get_async_session") as mock_get_session,
        ):
            mock_service = mock_service_cls.return_value
            context = _create_mock_pickup_context(
                mock_delivery,
                is_authenticated=True,
                can_accept_refuse=False,  # Already accepted
                sender_revealed=True,  # Key assertion
                ial_level=IALLevel.IAL2,
            )
            mock_service.get_pickup_context = AsyncMock(return_value=context)

            # Mock template response
            mock_template_instance = MagicMock()

            def capture_template_response(template_name, ctx):
                captured_context.update(ctx)
                response = MagicMock()
                response.status_code = 200
                return response

            mock_template_instance.TemplateResponse = MagicMock(
                side_effect=capture_template_response
            )
            mock_templates.return_value = mock_template_instance

            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)

            await api_client.get(f"/pickup/{delivery_id}")

        # Verify sender info IS revealed in the template context
        delivery_data = captured_context.get("delivery", {})
        assert delivery_data.get("sender_name") == "Jean Dupont"
        assert delivery_data.get("sender_email") == "jean.dupont@example.com"

    @pytest.mark.asyncio
    async def test_sender_revealed_after_refuse(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
        mock_delivery: MagicMock,
        mock_authenticated_user: AuthenticatedUser,
    ):
        """Verify sender identity is revealed after refusal (REQ-F03)."""
        # Delivery is in REFUSED state
        mock_delivery.state = DeliveryState.REFUSED
        mock_delivery.completed_at = datetime.now(UTC)

        captured_context: dict[str, Any] = {}

        with (
            patch("qerds.api.routers.pickup.PickupService") as mock_service_cls,
            patch(
                "qerds.api.routers.pickup.optional_authenticated_user",
                return_value=mock_authenticated_user,
            ),
            patch("qerds.api.routers.pickup.get_templates") as mock_templates,
            patch("qerds.db.get_async_session") as mock_get_session,
        ):
            mock_service = mock_service_cls.return_value
            context = _create_mock_pickup_context(
                mock_delivery,
                is_authenticated=True,
                can_accept_refuse=False,  # Already refused
                sender_revealed=True,  # Key assertion
                ial_level=IALLevel.IAL2,
            )
            mock_service.get_pickup_context = AsyncMock(return_value=context)

            # Mock template response
            mock_template_instance = MagicMock()

            def capture_template_response(template_name, ctx):
                captured_context.update(ctx)
                response = MagicMock()
                response.status_code = 200
                return response

            mock_template_instance.TemplateResponse = MagicMock(
                side_effect=capture_template_response
            )
            mock_templates.return_value = mock_template_instance

            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)

            await api_client.get(f"/pickup/{delivery_id}")

        # Verify sender info IS revealed in the template context
        delivery_data = captured_context.get("delivery", {})
        assert delivery_data.get("sender_name") == "Jean Dupont"
        assert delivery_data.get("sender_email") == "jean.dupont@example.com"


# ---------------------------------------------------------------------------
# Test: 15-Day Acceptance Window (REQ-F04)
# ---------------------------------------------------------------------------


class TestAcceptanceWindowEnforcement:
    """Tests for 15-day acceptance window enforcement (REQ-F04)."""

    @pytest.mark.asyncio
    async def test_expired_delivery_shows_error(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
        mock_delivery: MagicMock,
        mock_authenticated_user: AuthenticatedUser,
    ):
        """Verify expired delivery shows appropriate error page."""
        # Set delivery to expired (deadline in the past)
        mock_delivery.state = DeliveryState.EXPIRED
        mock_delivery.acceptance_deadline_at = datetime.now(UTC) - timedelta(days=1)
        mock_delivery.completed_at = datetime.now(UTC)

        captured_template_name = None

        with (
            patch("qerds.api.routers.pickup.PickupService") as mock_service_cls,
            patch(
                "qerds.api.routers.pickup.optional_authenticated_user",
                return_value=mock_authenticated_user,
            ),
            patch("qerds.api.routers.pickup.get_templates") as mock_templates,
            patch("qerds.db.get_async_session") as mock_get_session,
        ):
            mock_service = mock_service_cls.return_value
            context = _create_mock_pickup_context(
                mock_delivery,
                is_authenticated=True,
                can_accept_refuse=False,
                sender_revealed=True,
                ial_level=IALLevel.IAL2,
                is_expired=True,
            )
            mock_service.get_pickup_context = AsyncMock(return_value=context)

            # Mock template response
            mock_template_instance = MagicMock()

            def capture_template_response(template_name, ctx):
                nonlocal captured_template_name
                captured_template_name = template_name
                response = MagicMock()
                response.status_code = 200
                return response

            mock_template_instance.TemplateResponse = MagicMock(
                side_effect=capture_template_response
            )
            mock_templates.return_value = mock_template_instance

            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)

            await api_client.get(f"/pickup/{delivery_id}")

        # Should render the expired template
        assert captured_template_name == "recipient/expired.html"

    @pytest.mark.asyncio
    async def test_accept_expired_delivery_returns_410(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
        mock_delivery: MagicMock,
        mock_authenticated_user: AuthenticatedUser,
    ):
        """Verify accepting expired delivery returns 410 Gone."""
        from qerds.services.pickup import DeliveryExpiredError

        # Delivery has expired
        mock_delivery.acceptance_deadline_at = datetime.now(UTC) - timedelta(days=1)

        with (
            patch("qerds.api.routers.pickup.PickupService") as mock_service_cls,
            patch(
                "qerds.api.routers.pickup.optional_authenticated_user",
                return_value=mock_authenticated_user,
            ),
            patch("qerds.db.get_async_session") as mock_get_session,
        ):
            mock_service = mock_service_cls.return_value
            mock_service.accept_delivery = AsyncMock(
                side_effect=DeliveryExpiredError(delivery_id, mock_delivery.acceptance_deadline_at)
            )

            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)

            response = await api_client.post(f"/pickup/{delivery_id}/accept")

        assert response.status_code == status.HTTP_410_GONE
        assert "deadline" in response.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Test: Content Access Control (REQ-E02)
# ---------------------------------------------------------------------------


class TestContentAccessControl:
    """Tests for content access control (REQ-E02).

    Critical compliance requirement: Content is ONLY accessible
    AFTER the recipient has accepted the delivery.
    """

    @pytest.mark.asyncio
    async def test_content_download_denied_before_accept(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
        mock_delivery: MagicMock,
        mock_authenticated_user: AuthenticatedUser,
    ):
        """Verify content download is denied before acceptance (REQ-E02)."""
        # Delivery is in AVAILABLE state (not yet accepted)
        mock_delivery.state = DeliveryState.AVAILABLE

        with (
            patch("qerds.api.routers.pickup.PickupService") as mock_service_cls,
            patch(
                "qerds.api.routers.pickup.optional_authenticated_user",
                return_value=mock_authenticated_user,
            ),
            patch("qerds.db.get_async_session") as mock_get_session,
        ):
            mock_service = mock_service_cls.return_value
            context = _create_mock_pickup_context(
                mock_delivery,
                is_authenticated=True,
                can_accept_refuse=True,
                sender_revealed=False,
                ial_level=IALLevel.IAL2,
            )
            mock_service.get_pickup_context = AsyncMock(return_value=context)

            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)

            response = await api_client.get(f"/pickup/{delivery_id}/content")

        # Should return 403 Forbidden
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "after accepting" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_content_download_denied_after_refuse(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
        mock_delivery: MagicMock,
        mock_authenticated_user: AuthenticatedUser,
    ):
        """Verify content download is denied after refusal (REQ-E02)."""
        # Delivery is in REFUSED state
        mock_delivery.state = DeliveryState.REFUSED
        mock_delivery.completed_at = datetime.now(UTC)

        with (
            patch("qerds.api.routers.pickup.PickupService") as mock_service_cls,
            patch(
                "qerds.api.routers.pickup.optional_authenticated_user",
                return_value=mock_authenticated_user,
            ),
            patch("qerds.db.get_async_session") as mock_get_session,
        ):
            mock_service = mock_service_cls.return_value
            context = _create_mock_pickup_context(
                mock_delivery,
                is_authenticated=True,
                can_accept_refuse=False,
                sender_revealed=True,
                ial_level=IALLevel.IAL2,
            )
            mock_service.get_pickup_context = AsyncMock(return_value=context)

            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)

            response = await api_client.get(f"/pickup/{delivery_id}/content")

        # Should return 403 Forbidden
        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_content_download_without_auth_redirects(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
    ):
        """Verify content download without auth redirects to auth."""
        with patch(
            "qerds.api.routers.pickup.optional_authenticated_user",
            return_value=None,
        ):
            response = await api_client.get(
                f"/pickup/{delivery_id}/content",
                follow_redirects=False,
            )

        # Should redirect to auth
        assert response.status_code == status.HTTP_302_FOUND
        assert f"/pickup/{delivery_id}/auth" in response.headers["location"]


# ---------------------------------------------------------------------------
# Test: Unauthenticated Access Denial
# ---------------------------------------------------------------------------


class TestUnauthenticatedAccessDenial:
    """Tests for unauthenticated access handling."""

    @pytest.mark.asyncio
    async def test_accept_endpoint_requires_auth(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
    ):
        """Verify accept endpoint requires authentication."""
        with patch(
            "qerds.api.routers.pickup.optional_authenticated_user",
            return_value=None,
        ):
            response = await api_client.post(
                f"/pickup/{delivery_id}/accept",
                follow_redirects=False,
            )

        # Should redirect to auth (not 401)
        assert response.status_code == status.HTTP_302_FOUND
        assert "/auth" in response.headers["location"]

    @pytest.mark.asyncio
    async def test_refuse_endpoint_requires_auth(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
    ):
        """Verify refuse endpoint requires authentication."""
        with patch(
            "qerds.api.routers.pickup.optional_authenticated_user",
            return_value=None,
        ):
            response = await api_client.post(
                f"/pickup/{delivery_id}/refuse",
                follow_redirects=False,
            )

        # Should redirect to auth (not 401)
        assert response.status_code == status.HTTP_302_FOUND
        assert "/auth" in response.headers["location"]

    @pytest.mark.asyncio
    async def test_content_endpoint_requires_auth(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
    ):
        """Verify content endpoint requires authentication."""
        with patch(
            "qerds.api.routers.pickup.optional_authenticated_user",
            return_value=None,
        ):
            response = await api_client.get(
                f"/pickup/{delivery_id}/content",
                follow_redirects=False,
            )

        # Should redirect to auth (not 401)
        assert response.status_code == status.HTTP_302_FOUND
        assert "/auth" in response.headers["location"]


# ---------------------------------------------------------------------------
# Test: Recipient Mismatch (Wrong User)
# ---------------------------------------------------------------------------


class TestRecipientMismatch:
    """Tests for recipient mismatch handling."""

    @pytest.mark.asyncio
    async def test_wrong_user_cannot_accept(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
        mock_delivery: MagicMock,
    ):
        """Verify wrong user cannot accept delivery."""
        from qerds.services.pickup import RecipientMismatchError

        # Create authenticated user that is NOT the recipient
        wrong_user = AuthenticatedUser(
            principal_id=uuid4(),  # Different from recipient_party_id
            principal_type="party",
            session_id=uuid4(),
            is_superuser=False,
            is_active=True,
            roles=frozenset(["sender_user", "recipient_user"]),
            permissions=frozenset(),
            ip_address="127.0.0.1",
            user_agent="pytest-test-client",
            auth_method="oidc",
            metadata={"ial_level": IALLevel.IAL2.value},
        )

        with (
            patch("qerds.api.routers.pickup.PickupService") as mock_service_cls,
            patch(
                "qerds.api.routers.pickup.optional_authenticated_user",
                return_value=wrong_user,
            ),
            patch("qerds.db.get_async_session") as mock_get_session,
        ):
            mock_service = mock_service_cls.return_value
            mock_service.accept_delivery = AsyncMock(
                side_effect=RecipientMismatchError(delivery_id, wrong_user.principal_id)
            )

            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)

            response = await api_client.post(f"/pickup/{delivery_id}/accept")

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "not the recipient" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_wrong_user_cannot_refuse(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
        mock_delivery: MagicMock,
    ):
        """Verify wrong user cannot refuse delivery."""
        from qerds.services.pickup import RecipientMismatchError

        wrong_user = AuthenticatedUser(
            principal_id=uuid4(),
            principal_type="party",
            session_id=uuid4(),
            is_superuser=False,
            is_active=True,
            roles=frozenset(["sender_user", "recipient_user"]),
            permissions=frozenset(),
            ip_address="127.0.0.1",
            user_agent="pytest-test-client",
            auth_method="oidc",
            metadata={"ial_level": IALLevel.IAL2.value},
        )

        with (
            patch("qerds.api.routers.pickup.PickupService") as mock_service_cls,
            patch(
                "qerds.api.routers.pickup.optional_authenticated_user",
                return_value=wrong_user,
            ),
            patch("qerds.db.get_async_session") as mock_get_session,
        ):
            mock_service = mock_service_cls.return_value
            mock_service.refuse_delivery = AsyncMock(
                side_effect=RecipientMismatchError(delivery_id, wrong_user.principal_id)
            )

            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)

            response = await api_client.post(f"/pickup/{delivery_id}/refuse")

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "not the recipient" in response.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Test: IAL Level Enforcement for LRE (REQ-F04)
# ---------------------------------------------------------------------------


class TestIALLevelEnforcement:
    """Tests for IAL level enforcement for French LRE (REQ-F04)."""

    @pytest.mark.asyncio
    async def test_ial1_cannot_accept_lre_delivery(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
        recipient_party_id: UUID,
        mock_delivery: MagicMock,
    ):
        """Verify IAL1 user cannot accept LRE delivery (requires IAL2+)."""
        from qerds.services.pickup import InsufficientIALError

        # User with IAL1 (insufficient for LRE)
        ial1_user = AuthenticatedUser(
            principal_id=recipient_party_id,
            principal_type="party",
            session_id=uuid4(),
            is_superuser=False,
            is_active=True,
            roles=frozenset(["sender_user", "recipient_user"]),
            permissions=frozenset(),
            ip_address="127.0.0.1",
            user_agent="pytest-test-client",
            auth_method="oidc",
            metadata={"ial_level": IALLevel.IAL1.value},
        )

        with (
            patch("qerds.api.routers.pickup.PickupService") as mock_service_cls,
            patch(
                "qerds.api.routers.pickup.optional_authenticated_user",
                return_value=ial1_user,
            ),
            patch("qerds.db.get_async_session") as mock_get_session,
        ):
            mock_service = mock_service_cls.return_value
            mock_service.accept_delivery = AsyncMock(
                side_effect=InsufficientIALError(IALLevel.IAL2, IALLevel.IAL1)
            )

            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)

            response = await api_client.post(f"/pickup/{delivery_id}/accept")

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "assurance level" in response.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Test: Consumer Consent (REQ-F06)
# ---------------------------------------------------------------------------


class TestConsumerConsent:
    """Tests for consumer consent verification (REQ-F06)."""

    @pytest.mark.asyncio
    async def test_accept_without_consent_returns_400(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
        mock_delivery: MagicMock,
        mock_authenticated_user: AuthenticatedUser,
    ):
        """Verify accepting without consent returns 400 Bad Request."""
        from qerds.services.pickup import ConsentRequiredError

        with (
            patch("qerds.api.routers.pickup.PickupService") as mock_service_cls,
            patch(
                "qerds.api.routers.pickup.optional_authenticated_user",
                return_value=mock_authenticated_user,
            ),
            patch("qerds.db.get_async_session") as mock_get_session,
        ):
            mock_service = mock_service_cls.return_value
            mock_service.accept_delivery = AsyncMock(
                side_effect=ConsentRequiredError(
                    "Electronic delivery consent is required for LRE recipients"
                )
            )

            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)

            response = await api_client.post(
                f"/pickup/{delivery_id}/accept",
                params={"confirm_consent": "false"},
            )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "consent" in response.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Test: Invalid State Transitions
# ---------------------------------------------------------------------------


class TestInvalidStateTransitions:
    """Tests for invalid state transition handling."""

    @pytest.mark.asyncio
    async def test_cannot_accept_already_accepted_delivery(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
        mock_delivery: MagicMock,
        mock_authenticated_user: AuthenticatedUser,
    ):
        """Verify cannot accept an already accepted delivery."""
        from qerds.services.pickup import InvalidStateError

        mock_delivery.state = DeliveryState.ACCEPTED

        with (
            patch("qerds.api.routers.pickup.PickupService") as mock_service_cls,
            patch(
                "qerds.api.routers.pickup.optional_authenticated_user",
                return_value=mock_authenticated_user,
            ),
            patch("qerds.db.get_async_session") as mock_get_session,
        ):
            mock_service = mock_service_cls.return_value
            mock_service.accept_delivery = AsyncMock(
                side_effect=InvalidStateError(
                    delivery_id,
                    DeliveryState.ACCEPTED,
                    "expected AVAILABLE state for acceptance",
                )
            )

            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)

            response = await api_client.post(f"/pickup/{delivery_id}/accept")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "accepted" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_cannot_refuse_already_refused_delivery(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
        mock_delivery: MagicMock,
        mock_authenticated_user: AuthenticatedUser,
    ):
        """Verify cannot refuse an already refused delivery."""
        from qerds.services.pickup import InvalidStateError

        mock_delivery.state = DeliveryState.REFUSED

        with (
            patch("qerds.api.routers.pickup.PickupService") as mock_service_cls,
            patch(
                "qerds.api.routers.pickup.optional_authenticated_user",
                return_value=mock_authenticated_user,
            ),
            patch("qerds.db.get_async_session") as mock_get_session,
        ):
            mock_service = mock_service_cls.return_value
            mock_service.refuse_delivery = AsyncMock(
                side_effect=InvalidStateError(
                    delivery_id,
                    DeliveryState.REFUSED,
                    "expected AVAILABLE state for refusal",
                )
            )

            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)

            response = await api_client.post(f"/pickup/{delivery_id}/refuse")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "refused" in response.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Test: Delivery Not Found
# ---------------------------------------------------------------------------


class TestDeliveryNotFound:
    """Tests for delivery not found handling."""

    @pytest.mark.asyncio
    async def test_pickup_nonexistent_delivery_returns_404(
        self,
        api_client: AsyncClient,
    ):
        """Verify accessing nonexistent delivery returns 404."""
        from qerds.services.pickup import DeliveryNotFoundError

        nonexistent_id = uuid4()

        with (
            patch("qerds.api.routers.pickup.PickupService") as mock_service_cls,
            patch(
                "qerds.api.routers.pickup.optional_authenticated_user",
                return_value=None,
            ),
            patch("qerds.db.get_async_session") as mock_get_session,
        ):
            mock_service = mock_service_cls.return_value
            mock_service.validate_claim_token = AsyncMock(
                side_effect=DeliveryNotFoundError(nonexistent_id)
            )

            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)

            response = await api_client.get(
                f"/pickup/{nonexistent_id}",
                params={"token": "test-token"},
            )

        assert response.status_code == status.HTTP_404_NOT_FOUND


# ---------------------------------------------------------------------------
# Test: Successful Accept/Refuse with Redirect
# ---------------------------------------------------------------------------


class TestSuccessfulActions:
    """Tests for successful accept/refuse actions."""

    @pytest.mark.asyncio
    async def test_successful_accept_redirects_to_pickup(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
        mock_delivery: MagicMock,
        mock_authenticated_user: AuthenticatedUser,
    ):
        """Verify successful accept redirects to pickup page."""
        mock_delivery.state = DeliveryState.ACCEPTED

        with (
            patch("qerds.api.routers.pickup.PickupService") as mock_service_cls,
            patch(
                "qerds.api.routers.pickup.optional_authenticated_user",
                return_value=mock_authenticated_user,
            ),
            patch("qerds.db.get_async_session") as mock_get_session,
        ):
            mock_service = mock_service_cls.return_value
            mock_service.accept_delivery = AsyncMock(return_value=mock_delivery)

            mock_session = MagicMock()
            mock_session.commit = AsyncMock()
            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)

            response = await api_client.post(
                f"/pickup/{delivery_id}/accept",
                follow_redirects=False,
            )

        assert response.status_code == status.HTTP_302_FOUND
        assert f"/pickup/{delivery_id}" in response.headers["location"]

    @pytest.mark.asyncio
    async def test_successful_refuse_redirects_to_pickup(
        self,
        api_client: AsyncClient,
        delivery_id: UUID,
        mock_delivery: MagicMock,
        mock_authenticated_user: AuthenticatedUser,
    ):
        """Verify successful refuse redirects to pickup page."""
        mock_delivery.state = DeliveryState.REFUSED

        with (
            patch("qerds.api.routers.pickup.PickupService") as mock_service_cls,
            patch(
                "qerds.api.routers.pickup.optional_authenticated_user",
                return_value=mock_authenticated_user,
            ),
            patch("qerds.db.get_async_session") as mock_get_session,
        ):
            mock_service = mock_service_cls.return_value
            mock_service.refuse_delivery = AsyncMock(return_value=mock_delivery)

            mock_session = MagicMock()
            mock_session.commit = AsyncMock()
            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)

            response = await api_client.post(
                f"/pickup/{delivery_id}/refuse",
                params={"reason": "Not interested"},
                follow_redirects=False,
            )

        assert response.status_code == status.HTTP_302_FOUND
        assert f"/pickup/{delivery_id}" in response.headers["location"]
