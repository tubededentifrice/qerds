"""Tests for object storage integration.

Tests cover:
- Upload and download with integrity verification
- Content-addressed storage
- Bucket management (create, list)
- Error handling (not found, integrity failures)
- Presigned URL generation
- Copy operations
- Health checks

Uses moto for S3 mocking to enable fast unit tests without Docker.
Integration tests against real MinIO are marked with @pytest.mark.integration.
"""

import hashlib
from unittest.mock import MagicMock

import pytest
from moto import mock_aws

from qerds.services.storage import (
    BucketNotFoundError,
    Buckets,
    IntegrityError,
    ObjectMetadata,
    ObjectNotFoundError,
    ObjectStoreClient,
    StorageError,
    UploadResult,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_s3_client():
    """Create a mocked S3 client using moto.

    Note: We use endpoint_url=None to let moto intercept all requests.
    The moto library patches boto3 at the connection level, but custom
    endpoint_url bypasses this. For unit tests, we omit the endpoint.
    """
    with mock_aws():
        # Create a client without endpoint_url so moto can intercept
        import boto3
        from botocore.config import Config

        config = Config(
            connect_timeout=5.0,
            read_timeout=30.0,
            retries={"max_attempts": 3, "mode": "standard"},
            signature_version="s3v4",
        )

        s3_client = boto3.client(
            "s3",
            aws_access_key_id="test_access_key",
            aws_secret_access_key="test_secret_key",  # noqa: S106
            region_name="us-east-1",
            config=config,
        )

        # Create our wrapper but inject the mocked client directly
        client = ObjectStoreClient(
            endpoint_url="http://mocked",  # Not actually used
            access_key="test_access_key",
            secret_key="test_secret_key",  # noqa: S106
            region="us-east-1",
        )
        # Replace the internal client with moto-mocked one
        client._client = s3_client
        yield client


@pytest.fixture
def mock_s3_client_with_buckets(mock_s3_client):
    """Create a mocked S3 client with standard buckets created."""
    mock_s3_client.ensure_standard_buckets()
    return mock_s3_client


@pytest.fixture
def sample_content():
    """Sample content for upload/download tests."""
    return b"This is test content for QERDS storage integration."


@pytest.fixture
def sample_content_digest(sample_content):
    """SHA-256 digest of sample content."""
    return hashlib.sha256(sample_content).hexdigest()


# ---------------------------------------------------------------------------
# Buckets Enum Tests
# ---------------------------------------------------------------------------
class TestBucketsEnum:
    """Tests for Buckets enum."""

    def test_bucket_values(self):
        """Test that all expected bucket names are defined."""
        assert Buckets.CONTENT.value == "qerds-content"
        assert Buckets.EVIDENCE.value == "qerds-evidence"
        assert Buckets.AUDIT.value == "qerds-audit"

    def test_bucket_count(self):
        """Test that we have exactly 3 buckets defined."""
        assert len(Buckets) == 3


# ---------------------------------------------------------------------------
# UploadResult Tests
# ---------------------------------------------------------------------------
class TestUploadResult:
    """Tests for UploadResult dataclass."""

    def test_upload_result_creation(self):
        """Test creating an UploadResult."""
        result = UploadResult(
            key="test/key.txt",
            bucket="test-bucket",
            sha256_digest="abc123",
            size_bytes=1024,
            etag='"etag123"',
            version_id="v1",
        )
        assert result.key == "test/key.txt"
        assert result.bucket == "test-bucket"
        assert result.sha256_digest == "abc123"
        assert result.size_bytes == 1024
        assert result.etag == '"etag123"'
        assert result.version_id == "v1"

    def test_upload_result_is_frozen(self):
        """Test that UploadResult is immutable."""
        result = UploadResult(
            key="test/key.txt",
            bucket="test-bucket",
            sha256_digest="abc123",
            size_bytes=1024,
            etag='"etag123"',
        )
        with pytest.raises(AttributeError):
            result.key = "modified"


# ---------------------------------------------------------------------------
# ObjectMetadata Tests
# ---------------------------------------------------------------------------
class TestObjectMetadata:
    """Tests for ObjectMetadata dataclass."""

    def test_object_metadata_creation(self):
        """Test creating an ObjectMetadata instance."""
        metadata = ObjectMetadata(
            key="test/key.txt",
            bucket="test-bucket",
            size_bytes=2048,
            content_type="text/plain",
            sha256_digest="def456",
            etag='"etag456"',
            last_modified="2026-01-22T10:00:00Z",
            version_id="v2",
            custom_metadata={"author": "test"},
        )
        assert metadata.key == "test/key.txt"
        assert metadata.size_bytes == 2048
        assert metadata.custom_metadata == {"author": "test"}


# ---------------------------------------------------------------------------
# Exception Tests
# ---------------------------------------------------------------------------
class TestStorageExceptions:
    """Tests for storage exception classes."""

    def test_storage_error_attributes(self):
        """Test StorageError has context attributes."""
        error = StorageError(
            "Test error",
            bucket="test-bucket",
            key="test-key",
            operation="upload",
        )
        assert error.message == "Test error"
        assert error.bucket == "test-bucket"
        assert error.key == "test-key"
        assert error.operation == "upload"
        assert str(error) == "Test error"

    def test_object_not_found_error(self):
        """Test ObjectNotFoundError is a StorageError."""
        error = ObjectNotFoundError("Not found", bucket="b", key="k")
        assert isinstance(error, StorageError)

    def test_bucket_not_found_error(self):
        """Test BucketNotFoundError is a StorageError."""
        error = BucketNotFoundError("Not found", bucket="b")
        assert isinstance(error, StorageError)

    def test_integrity_error(self):
        """Test IntegrityError is a StorageError."""
        error = IntegrityError("Digest mismatch", bucket="b", key="k")
        assert isinstance(error, StorageError)


# ---------------------------------------------------------------------------
# ObjectStoreClient Initialization Tests
# ---------------------------------------------------------------------------
class TestObjectStoreClientInit:
    """Tests for ObjectStoreClient initialization."""

    def test_client_initialization(self):
        """Test client can be initialized with credentials."""
        with mock_aws():
            client = ObjectStoreClient(
                endpoint_url="http://localhost:9000",
                access_key="access",
                secret_key="secret",  # noqa: S106
                region="eu-west-1",
            )
            assert client._endpoint_url == "http://localhost:9000"
            assert client._region == "eu-west-1"

    def test_from_settings(self):
        """Test creating client from S3Settings."""
        mock_settings = MagicMock()
        mock_settings.endpoint = "http://minio:9000"
        mock_settings.access_key.get_secret_value.return_value = "access"
        mock_settings.secret_key.get_secret_value.return_value = "secret"
        mock_settings.region = "us-west-2"

        with mock_aws():
            client = ObjectStoreClient.from_settings(mock_settings)
            assert client._endpoint_url == "http://minio:9000"
            assert client._region == "us-west-2"


# ---------------------------------------------------------------------------
# Bucket Management Tests
# ---------------------------------------------------------------------------
class TestBucketManagement:
    """Tests for bucket creation and management."""

    def test_ensure_bucket_creates_new(self, mock_s3_client):
        """Test that ensure_bucket creates a new bucket."""
        created = mock_s3_client.ensure_bucket("test-new-bucket")
        assert created is True

    def test_ensure_bucket_existing(self, mock_s3_client):
        """Test that ensure_bucket returns False for existing bucket."""
        mock_s3_client.ensure_bucket("test-bucket")
        created = mock_s3_client.ensure_bucket("test-bucket")
        assert created is False

    def test_ensure_bucket_with_enum(self, mock_s3_client):
        """Test that ensure_bucket works with Buckets enum."""
        created = mock_s3_client.ensure_bucket(Buckets.CONTENT)
        assert created is True

    def test_ensure_standard_buckets(self, mock_s3_client):
        """Test that ensure_standard_buckets creates all standard buckets."""
        results = mock_s3_client.ensure_standard_buckets()

        assert len(results) == 3
        assert results["qerds-content"] is True
        assert results["qerds-evidence"] is True
        assert results["qerds-audit"] is True

    def test_ensure_standard_buckets_idempotent(self, mock_s3_client):
        """Test that ensure_standard_buckets is idempotent."""
        mock_s3_client.ensure_standard_buckets()
        results = mock_s3_client.ensure_standard_buckets()

        # All should exist now
        assert all(created is False for created in results.values())


# ---------------------------------------------------------------------------
# Upload Tests
# ---------------------------------------------------------------------------
class TestUpload:
    """Tests for upload operations."""

    def test_upload_basic(self, mock_s3_client_with_buckets, sample_content, sample_content_digest):
        """Test basic upload with integrity verification."""
        result = mock_s3_client_with_buckets.upload(
            bucket=Buckets.CONTENT,
            key="test/document.txt",
            data=sample_content,
            content_type="text/plain",
        )

        assert result.key == "test/document.txt"
        assert result.bucket == "qerds-content"
        assert result.sha256_digest == sample_content_digest
        assert result.size_bytes == len(sample_content)
        assert result.etag is not None

    def test_upload_with_metadata(self, mock_s3_client_with_buckets, sample_content):
        """Test upload with custom metadata."""
        result = mock_s3_client_with_buckets.upload(
            bucket=Buckets.EVIDENCE,
            key="evidence/bundle-123.json",
            data=sample_content,
            content_type="application/json",
            metadata={"delivery-id": "123", "sealed": "true"},
        )

        assert result.key == "evidence/bundle-123.json"
        assert result.bucket == "qerds-evidence"

    def test_upload_with_string_bucket(self, mock_s3_client_with_buckets, sample_content):
        """Test upload with string bucket name."""
        result = mock_s3_client_with_buckets.upload(
            bucket="qerds-content",
            key="test/file.bin",
            data=sample_content,
        )

        assert result.bucket == "qerds-content"

    def test_upload_to_nonexistent_bucket(self, mock_s3_client, sample_content):
        """Test upload to non-existent bucket raises BucketNotFoundError."""
        with pytest.raises(BucketNotFoundError) as exc_info:
            mock_s3_client.upload(
                bucket="nonexistent-bucket",
                key="test.txt",
                data=sample_content,
            )
        assert exc_info.value.bucket == "nonexistent-bucket"
        assert exc_info.value.operation == "upload"

    def test_upload_empty_content(self, mock_s3_client_with_buckets):
        """Test uploading empty content."""
        result = mock_s3_client_with_buckets.upload(
            bucket=Buckets.CONTENT,
            key="empty.txt",
            data=b"",
        )

        assert result.size_bytes == 0
        # SHA-256 of empty string
        assert result.sha256_digest == hashlib.sha256(b"").hexdigest()


# ---------------------------------------------------------------------------
# Content-Addressed Upload Tests
# ---------------------------------------------------------------------------
class TestContentAddressedUpload:
    """Tests for content-addressed storage."""

    def test_upload_content_addressed(
        self, mock_s3_client_with_buckets, sample_content, sample_content_digest
    ):
        """Test content-addressed upload uses digest as key."""
        result = mock_s3_client_with_buckets.upload_content_addressed(
            bucket=Buckets.CONTENT,
            data=sample_content,
        )

        assert result.key == sample_content_digest
        assert result.sha256_digest == sample_content_digest

    def test_upload_content_addressed_with_prefix(
        self, mock_s3_client_with_buckets, sample_content, sample_content_digest
    ):
        """Test content-addressed upload with prefix."""
        result = mock_s3_client_with_buckets.upload_content_addressed(
            bucket=Buckets.CONTENT,
            data=sample_content,
            prefix="blobs/",
        )

        assert result.key == f"blobs/{sample_content_digest}"


# ---------------------------------------------------------------------------
# Download Tests
# ---------------------------------------------------------------------------
class TestDownload:
    """Tests for download operations."""

    def test_download_basic(
        self, mock_s3_client_with_buckets, sample_content, sample_content_digest
    ):
        """Test basic download with integrity verification."""
        # Upload first
        mock_s3_client_with_buckets.upload(
            bucket=Buckets.CONTENT,
            key="test/document.txt",
            data=sample_content,
        )

        # Download
        data, metadata = mock_s3_client_with_buckets.download(
            bucket=Buckets.CONTENT,
            key="test/document.txt",
        )

        assert data == sample_content
        assert metadata.key == "test/document.txt"
        assert metadata.bucket == "qerds-content"
        assert metadata.sha256_digest == sample_content_digest

    def test_download_without_integrity_check(self, mock_s3_client_with_buckets, sample_content):
        """Test download with integrity verification disabled."""
        mock_s3_client_with_buckets.upload(
            bucket=Buckets.CONTENT,
            key="test/file.bin",
            data=sample_content,
        )

        data, _metadata = mock_s3_client_with_buckets.download(
            bucket=Buckets.CONTENT,
            key="test/file.bin",
            verify_integrity=False,
        )

        assert data == sample_content

    def test_download_with_expected_digest(
        self, mock_s3_client_with_buckets, sample_content, sample_content_digest
    ):
        """Test download with explicitly provided expected digest."""
        mock_s3_client_with_buckets.upload(
            bucket=Buckets.CONTENT,
            key="test/file.bin",
            data=sample_content,
        )

        data, _metadata = mock_s3_client_with_buckets.download(
            bucket=Buckets.CONTENT,
            key="test/file.bin",
            expected_digest=sample_content_digest,
        )

        assert data == sample_content

    def test_download_integrity_failure(self, mock_s3_client_with_buckets, sample_content):
        """Test download fails when expected digest doesn't match."""
        mock_s3_client_with_buckets.upload(
            bucket=Buckets.CONTENT,
            key="test/file.bin",
            data=sample_content,
        )

        with pytest.raises(IntegrityError) as exc_info:
            mock_s3_client_with_buckets.download(
                bucket=Buckets.CONTENT,
                key="test/file.bin",
                expected_digest="invalid_digest_that_will_not_match",
            )
        assert "integrity check failed" in exc_info.value.message.lower()
        assert exc_info.value.operation == "download"

    def test_download_nonexistent_object(self, mock_s3_client_with_buckets):
        """Test download of non-existent object raises ObjectNotFoundError."""
        with pytest.raises(ObjectNotFoundError) as exc_info:
            mock_s3_client_with_buckets.download(
                bucket=Buckets.CONTENT,
                key="nonexistent.txt",
            )
        assert exc_info.value.key == "nonexistent.txt"
        assert exc_info.value.operation == "download"

    def test_download_from_nonexistent_bucket(self, mock_s3_client):
        """Test download from non-existent bucket raises BucketNotFoundError."""
        with pytest.raises(BucketNotFoundError) as exc_info:
            mock_s3_client.download(
                bucket="nonexistent-bucket",
                key="file.txt",
            )
        assert exc_info.value.bucket == "nonexistent-bucket"


# ---------------------------------------------------------------------------
# Delete Tests
# ---------------------------------------------------------------------------
class TestDelete:
    """Tests for delete operations."""

    def test_delete_existing_object(self, mock_s3_client_with_buckets, sample_content):
        """Test deleting an existing object."""
        mock_s3_client_with_buckets.upload(
            bucket=Buckets.CONTENT,
            key="to-delete.txt",
            data=sample_content,
        )

        result = mock_s3_client_with_buckets.delete(
            bucket=Buckets.CONTENT,
            key="to-delete.txt",
        )

        assert result is True

        # Verify object is deleted
        assert mock_s3_client_with_buckets.exists(Buckets.CONTENT, "to-delete.txt") is False

    def test_delete_nonexistent_object_is_idempotent(self, mock_s3_client_with_buckets):
        """Test deleting non-existent object succeeds (S3 is idempotent)."""
        result = mock_s3_client_with_buckets.delete(
            bucket=Buckets.CONTENT,
            key="never-existed.txt",
        )
        assert result is True


# ---------------------------------------------------------------------------
# Exists Tests
# ---------------------------------------------------------------------------
class TestExists:
    """Tests for existence checks."""

    def test_exists_returns_true_for_existing(self, mock_s3_client_with_buckets, sample_content):
        """Test exists returns True for existing objects."""
        mock_s3_client_with_buckets.upload(
            bucket=Buckets.CONTENT,
            key="exists.txt",
            data=sample_content,
        )

        assert mock_s3_client_with_buckets.exists(Buckets.CONTENT, "exists.txt") is True

    def test_exists_returns_false_for_nonexistent(self, mock_s3_client_with_buckets):
        """Test exists returns False for non-existent objects."""
        assert mock_s3_client_with_buckets.exists(Buckets.CONTENT, "nope.txt") is False


# ---------------------------------------------------------------------------
# Get Metadata Tests
# ---------------------------------------------------------------------------
class TestGetMetadata:
    """Tests for metadata retrieval."""

    def test_get_metadata_existing_object(
        self, mock_s3_client_with_buckets, sample_content, sample_content_digest
    ):
        """Test getting metadata for existing object."""
        mock_s3_client_with_buckets.upload(
            bucket=Buckets.CONTENT,
            key="with-metadata.txt",
            data=sample_content,
            content_type="text/plain",
            metadata={"custom-key": "custom-value"},
        )

        metadata = mock_s3_client_with_buckets.get_metadata(Buckets.CONTENT, "with-metadata.txt")

        assert metadata.key == "with-metadata.txt"
        assert metadata.bucket == "qerds-content"
        assert metadata.size_bytes == len(sample_content)
        assert metadata.sha256_digest == sample_content_digest
        assert "custom-key" in (metadata.custom_metadata or {})

    def test_get_metadata_nonexistent_object(self, mock_s3_client_with_buckets):
        """Test getting metadata for non-existent object raises error."""
        with pytest.raises(ObjectNotFoundError):
            mock_s3_client_with_buckets.get_metadata(Buckets.CONTENT, "nope.txt")


# ---------------------------------------------------------------------------
# List Objects Tests
# ---------------------------------------------------------------------------
class TestListObjects:
    """Tests for listing objects."""

    def test_list_objects_empty_bucket(self, mock_s3_client_with_buckets):
        """Test listing objects in empty bucket."""
        objects = mock_s3_client_with_buckets.list_objects(Buckets.CONTENT)
        assert objects == []

    def test_list_objects_with_content(self, mock_s3_client_with_buckets, sample_content):
        """Test listing objects returns uploaded objects."""
        # Upload multiple objects
        mock_s3_client_with_buckets.upload(Buckets.CONTENT, "a.txt", sample_content)
        mock_s3_client_with_buckets.upload(Buckets.CONTENT, "b.txt", sample_content)
        mock_s3_client_with_buckets.upload(Buckets.CONTENT, "c.txt", sample_content)

        objects = mock_s3_client_with_buckets.list_objects(Buckets.CONTENT)

        assert len(objects) == 3
        keys = {obj.key for obj in objects}
        assert keys == {"a.txt", "b.txt", "c.txt"}

    def test_list_objects_with_prefix(self, mock_s3_client_with_buckets, sample_content):
        """Test listing objects with prefix filter."""
        mock_s3_client_with_buckets.upload(Buckets.CONTENT, "dir1/a.txt", sample_content)
        mock_s3_client_with_buckets.upload(Buckets.CONTENT, "dir1/b.txt", sample_content)
        mock_s3_client_with_buckets.upload(Buckets.CONTENT, "dir2/c.txt", sample_content)

        objects = mock_s3_client_with_buckets.list_objects(Buckets.CONTENT, prefix="dir1/")

        assert len(objects) == 2
        keys = {obj.key for obj in objects}
        assert keys == {"dir1/a.txt", "dir1/b.txt"}

    def test_list_objects_nonexistent_bucket(self, mock_s3_client):
        """Test listing objects in non-existent bucket raises error."""
        with pytest.raises(BucketNotFoundError):
            mock_s3_client.list_objects("nonexistent-bucket")


# ---------------------------------------------------------------------------
# Presigned URL Tests
# ---------------------------------------------------------------------------
class TestPresignedUrls:
    """Tests for presigned URL generation."""

    def test_generate_presigned_url_get(self, mock_s3_client_with_buckets, sample_content):
        """Test generating presigned URL for download."""
        mock_s3_client_with_buckets.upload(Buckets.CONTENT, "doc.txt", sample_content)

        url = mock_s3_client_with_buckets.generate_presigned_url(
            bucket=Buckets.CONTENT,
            key="doc.txt",
            expires_in=3600,
        )

        assert url is not None
        assert "doc.txt" in url
        assert "X-Amz-Signature" in url or "Signature" in url

    def test_generate_presigned_url_put(self, mock_s3_client_with_buckets):
        """Test generating presigned URL for upload."""
        url = mock_s3_client_with_buckets.generate_presigned_url(
            bucket=Buckets.CONTENT,
            key="new-upload.txt",
            operation="put_object",
        )

        assert url is not None
        assert "new-upload.txt" in url

    def test_generate_presigned_url_custom_expiration(
        self, mock_s3_client_with_buckets, sample_content
    ):
        """Test presigned URL with custom expiration."""
        mock_s3_client_with_buckets.upload(Buckets.CONTENT, "temp.txt", sample_content)

        url = mock_s3_client_with_buckets.generate_presigned_url(
            bucket=Buckets.CONTENT,
            key="temp.txt",
            expires_in=60,  # 1 minute
        )

        assert url is not None
        # Check expiration is in the URL parameters
        assert "Expires" in url or "X-Amz-Expires" in url


# ---------------------------------------------------------------------------
# Copy Tests
# ---------------------------------------------------------------------------
class TestCopy:
    """Tests for copy operations."""

    def test_copy_within_bucket(self, mock_s3_client_with_buckets, sample_content):
        """Test copying object within same bucket."""
        mock_s3_client_with_buckets.upload(Buckets.CONTENT, "source.txt", sample_content)

        metadata = mock_s3_client_with_buckets.copy(
            source_bucket=Buckets.CONTENT,
            source_key="source.txt",
            dest_bucket=Buckets.CONTENT,
            dest_key="copy.txt",
        )

        assert metadata.key == "copy.txt"
        assert mock_s3_client_with_buckets.exists(Buckets.CONTENT, "copy.txt")
        # Original should still exist
        assert mock_s3_client_with_buckets.exists(Buckets.CONTENT, "source.txt")

    def test_copy_between_buckets(self, mock_s3_client_with_buckets, sample_content):
        """Test copying object between buckets."""
        mock_s3_client_with_buckets.upload(Buckets.CONTENT, "original.txt", sample_content)

        metadata = mock_s3_client_with_buckets.copy(
            source_bucket=Buckets.CONTENT,
            source_key="original.txt",
            dest_bucket=Buckets.EVIDENCE,
            dest_key="archived.txt",
        )

        assert metadata.bucket == "qerds-evidence"
        assert mock_s3_client_with_buckets.exists(Buckets.EVIDENCE, "archived.txt")

    def test_copy_nonexistent_source(self, mock_s3_client_with_buckets):
        """Test copying non-existent source raises error."""
        with pytest.raises(ObjectNotFoundError):
            mock_s3_client_with_buckets.copy(
                source_bucket=Buckets.CONTENT,
                source_key="nonexistent.txt",
                dest_bucket=Buckets.EVIDENCE,
                dest_key="dest.txt",
            )


# ---------------------------------------------------------------------------
# Health Check Tests
# ---------------------------------------------------------------------------
class TestHealthCheck:
    """Tests for health check functionality."""

    def test_health_check_success(self, mock_s3_client_with_buckets):
        """Test health check returns status when healthy."""
        health = mock_s3_client_with_buckets.health_check()

        assert health["healthy"] is True
        # Endpoint in mock is 'http://mocked' due to test fixture
        assert "endpoint" in health
        assert "buckets" in health
        assert health["bucket_count"] == 3


# ---------------------------------------------------------------------------
# SHA-256 Computation Tests
# ---------------------------------------------------------------------------
class TestSha256Computation:
    """Tests for SHA-256 digest computation."""

    def test_compute_sha256_basic(self, mock_s3_client):
        """Test SHA-256 computation for basic content."""
        content = b"test content"
        expected = hashlib.sha256(content).hexdigest()

        result = mock_s3_client._compute_sha256(content)

        assert result == expected
        assert len(result) == 64  # SHA-256 hex is 64 chars

    def test_compute_sha256_empty(self, mock_s3_client):
        """Test SHA-256 computation for empty content."""
        expected = hashlib.sha256(b"").hexdigest()
        result = mock_s3_client._compute_sha256(b"")
        assert result == expected

    def test_compute_sha256_large_content(self, mock_s3_client):
        """Test SHA-256 computation for larger content."""
        # 1MB of data
        content = b"x" * (1024 * 1024)
        expected = hashlib.sha256(content).hexdigest()

        result = mock_s3_client._compute_sha256(content)

        assert result == expected


# ---------------------------------------------------------------------------
# Integration Tests (require Docker/MinIO)
# ---------------------------------------------------------------------------
@pytest.mark.integration
class TestIntegrationWithMinIO:
    """Integration tests that require a running MinIO instance.

    Run with: docker compose up minio && pytest -m integration
    """

    @pytest.fixture
    def minio_client(self, s3_endpoint, s3_credentials):
        """Create a real MinIO client from test fixtures."""
        return ObjectStoreClient(
            endpoint_url=s3_endpoint,
            access_key=s3_credentials["aws_access_key_id"],
            secret_key=s3_credentials["aws_secret_access_key"],
            region="us-east-1",
        )

    def test_integration_full_workflow(self, minio_client):
        """Test full upload/download/delete workflow against real MinIO."""
        # Ensure test bucket exists
        minio_client.ensure_bucket("qerds-integration-test")

        content = b"Integration test content"
        key = "integration-test/test.txt"

        try:
            # Upload
            upload_result = minio_client.upload(
                bucket="qerds-integration-test",
                key=key,
                data=content,
                content_type="text/plain",
            )
            assert upload_result.sha256_digest == hashlib.sha256(content).hexdigest()

            # Download with verification
            downloaded, _metadata = minio_client.download(
                bucket="qerds-integration-test",
                key=key,
            )
            assert downloaded == content

            # Check exists
            assert minio_client.exists("qerds-integration-test", key) is True

        finally:
            # Cleanup
            minio_client.delete("qerds-integration-test", key)
