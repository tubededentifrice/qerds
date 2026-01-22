"""Smoke tests to verify test infrastructure works.

These tests verify that the basic test infrastructure is functioning:
- Package imports work
- API can be instantiated
- Async tests work
- Fixtures are available
"""

import pytest
from httpx import AsyncClient


class TestPackageImports:
    """Verify that core packages can be imported."""

    def test_import_qerds(self):
        """Test that the main package can be imported."""
        import qerds

        assert qerds.__version__ is not None
        assert qerds.__version__ == "0.1.0"

    def test_import_api_module(self):
        """Test that the API module can be imported."""
        from qerds.api import main

        assert main.app is not None

    def test_import_db_module(self):
        """Test that the database module can be imported."""
        from qerds import db

        assert db is not None


class TestAsyncInfrastructure:
    """Verify that async test infrastructure works."""

    @pytest.mark.asyncio
    async def test_async_works(self):
        """Test that async tests work."""
        import asyncio

        await asyncio.sleep(0.001)
        assert True

    @pytest.mark.asyncio
    async def test_async_with_fixture(self, api_client: AsyncClient):
        """Test that async fixtures work correctly."""
        assert api_client is not None
        assert isinstance(api_client, AsyncClient)


class TestAPIEndpoints:
    """Verify that API endpoints are accessible."""

    @pytest.mark.asyncio
    async def test_health_endpoint(self, api_client: AsyncClient):
        """Test the health check endpoint."""
        response = await api_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"


class TestFixturesAvailable:
    """Verify that test fixtures are available and correctly typed."""

    def test_sender_party_fixture(self, sender_party: dict):
        """Test that sender_party fixture is available."""
        assert sender_party is not None
        assert "party_id" in sender_party
        assert sender_party["party_type"] == "natural_person"
        assert "email" in sender_party

    def test_recipient_party_fixture(self, recipient_party: dict):
        """Test that recipient_party fixture is available."""
        assert recipient_party is not None
        assert "party_id" in recipient_party
        assert recipient_party["party_type"] == "natural_person"
        assert "email" in recipient_party

    def test_corporate_sender_fixture(self, corporate_sender: dict):
        """Test that corporate_sender fixture is available."""
        assert corporate_sender is not None
        assert corporate_sender["party_type"] == "legal_person"
        assert "organization_name" in corporate_sender

    def test_admin_user_fixture(self, admin_user: dict):
        """Test that admin_user fixture is available."""
        assert admin_user is not None
        assert "admin" in admin_user["roles"]

    def test_operator_user_fixture(self, operator_user: dict):
        """Test that operator_user fixture is available."""
        assert operator_user is not None
        assert "operator" in operator_user["roles"]


class TestFactories:
    """Verify that test factories work correctly."""

    def test_create_delivery(self):
        """Test that delivery factory creates valid data."""
        from tests.factories import create_delivery

        delivery = create_delivery()
        assert "delivery_id" in delivery
        assert delivery["state"] == "draft"
        assert "sender_party_id" in delivery
        assert "recipient_party_id" in delivery

    def test_create_delivery_with_params(self):
        """Test that delivery factory accepts parameters."""
        from tests.factories import create_delivery

        delivery = create_delivery(
            state="submitted",
            jurisdiction="franceconnect",
        )
        assert delivery["state"] == "submitted"
        assert delivery["jurisdiction_profile"] == "franceconnect"

    def test_create_evidence_event(self):
        """Test that evidence event factory creates valid data."""
        from tests.factories import create_evidence_event

        event = create_evidence_event(delivery_id="test-delivery-id")
        assert "event_id" in event
        assert event["delivery_id"] == "test-delivery-id"
        assert event["event_type"] == "EVT_DEPOSITED"

    def test_create_content_blob(self):
        """Test that content blob factory creates valid data."""
        from tests.factories import create_content_blob

        blob = create_content_blob(delivery_id="test-delivery-id")
        assert "blob_id" in blob
        assert blob["delivery_id"] == "test-delivery-id"
        assert blob["filename"] == "document.pdf"
        assert "sha256_hash" in blob

    def test_create_party(self):
        """Test that party factory creates valid data."""
        from tests.factories import create_party

        party = create_party()
        assert "party_id" in party
        assert party["party_type"] == "natural_person"
        assert "email" in party
        assert "given_name" in party

    def test_create_party_legal_person(self):
        """Test that party factory can create legal persons."""
        from tests.factories import create_party

        party = create_party(party_type="legal_person")
        assert party["party_type"] == "legal_person"
        assert "organization_name" in party

    def test_create_audit_log_entry(self):
        """Test that audit log factory creates valid data."""
        from tests.factories import create_audit_log_entry

        entry = create_audit_log_entry(action="create")
        assert "entry_id" in entry
        assert entry["action"] == "create"
        assert "timestamp" in entry
