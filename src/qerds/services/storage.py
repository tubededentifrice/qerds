"""Object store integration for content and evidence storage.

This module provides an S3-compatible client wrapper for storing:
- Content blobs (encrypted documents/attachments)
- Evidence bundles (sealed evidence records)
- Audit packs (compliance exports)

Per REQ-E01, content must be encrypted at rest. This module handles
integrity verification (SHA256) on upload/download but delegates
encryption to the caller.

Example:
    from qerds.services.storage import ObjectStoreClient, Buckets
    from qerds.core.settings import get_settings

    settings = get_settings()
    client = ObjectStoreClient.from_settings(settings.s3)

    # Upload content with integrity check
    result = await client.upload(
        bucket=Buckets.CONTENT,
        key="delivery-123/document.pdf.enc",
        data=encrypted_content,
        content_type="application/octet-stream",
    )
    print(f"Stored with digest: {result.sha256_digest}")

    # Download with integrity verification
    data, metadata = await client.download(
        bucket=Buckets.CONTENT,
        key="delivery-123/document.pdf.enc",
    )
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client

    from qerds.core.config import S3Settings

logger = logging.getLogger(__name__)


class Buckets(str, Enum):
    """Standard bucket names for QERDS storage domains.

    These bucket names align with the storage domains defined in
    specs/implementation/70-storage-and-retention.md:
    - CONTENT: Encrypted content blobs (documents, attachments)
    - EVIDENCE: Sealed evidence bundles with verification data
    - AUDIT: Audit packs and compliance exports
    """

    CONTENT = "qerds-content"
    EVIDENCE = "qerds-evidence"
    AUDIT = "qerds-audit"


@dataclass(frozen=True)
class UploadResult:
    """Result of an upload operation.

    Attributes:
        key: The object key in the bucket.
        bucket: The bucket name.
        sha256_digest: SHA-256 hex digest of the uploaded content.
        size_bytes: Size of the uploaded content in bytes.
        etag: S3 ETag (usually MD5 of content, quoted).
        version_id: Object version ID if versioning is enabled.
    """

    key: str
    bucket: str
    sha256_digest: str
    size_bytes: int
    etag: str
    version_id: str | None = None


@dataclass(frozen=True)
class ObjectMetadata:
    """Metadata for a stored object.

    Attributes:
        key: The object key in the bucket.
        bucket: The bucket name.
        size_bytes: Size of the object in bytes.
        content_type: MIME type of the content.
        sha256_digest: SHA-256 digest if stored in metadata.
        etag: S3 ETag.
        last_modified: Last modification timestamp as ISO string.
        version_id: Object version ID if versioning is enabled.
        custom_metadata: Additional user-defined metadata.
    """

    key: str
    bucket: str
    size_bytes: int
    content_type: str
    sha256_digest: str | None
    etag: str
    last_modified: str
    version_id: str | None = None
    custom_metadata: dict[str, str] | None = None


class StorageError(Exception):
    """Base exception for storage operations.

    Attributes:
        message: Human-readable error description.
        bucket: The bucket involved in the operation.
        key: The object key involved (if applicable).
        operation: The operation that failed.
    """

    def __init__(
        self,
        message: str,
        *,
        bucket: str | None = None,
        key: str | None = None,
        operation: str | None = None,
    ) -> None:
        """Initialize storage error with context.

        Args:
            message: Error description.
            bucket: Bucket name (if applicable).
            key: Object key (if applicable).
            operation: Operation name (e.g., 'upload', 'download').
        """
        self.message = message
        self.bucket = bucket
        self.key = key
        self.operation = operation
        super().__init__(message)


class ObjectNotFoundError(StorageError):
    """Raised when an object does not exist."""


class BucketNotFoundError(StorageError):
    """Raised when a bucket does not exist."""


class IntegrityError(StorageError):
    """Raised when content integrity verification fails."""


class ObjectStoreClient:
    """S3-compatible object storage client with integrity verification.

    This client wraps boto3 to provide:
    - Automatic bucket creation if missing
    - SHA-256 integrity verification on upload/download
    - Content-addressed storage support
    - Presigned URL generation for direct access

    The client uses synchronous boto3 under the hood. For high-throughput
    async workloads, consider using aiobotocore in the future.
    """

    # Metadata key for storing SHA-256 digest
    DIGEST_METADATA_KEY = "x-amz-meta-sha256-digest"

    def __init__(
        self,
        endpoint_url: str,
        access_key: str,
        secret_key: str,
        region: str = "us-east-1",
        *,
        connect_timeout: float = 5.0,
        read_timeout: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        """Initialize the object store client.

        Args:
            endpoint_url: S3-compatible endpoint URL (e.g., http://localhost:9000).
            access_key: S3 access key ID.
            secret_key: S3 secret access key.
            region: AWS region (use us-east-1 for MinIO).
            connect_timeout: Connection timeout in seconds.
            read_timeout: Read timeout in seconds.
            max_retries: Maximum retry attempts for transient failures.
        """
        self._endpoint_url = endpoint_url
        self._region = region

        # Configure boto3 with timeouts and retries
        config = Config(
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            retries={"max_attempts": max_retries, "mode": "standard"},
            signature_version="s3v4",
        )

        self._client: S3Client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
            config=config,
        )

        logger.debug(
            "Initialized ObjectStoreClient for endpoint=%s region=%s",
            endpoint_url,
            region,
        )

    @classmethod
    def from_settings(cls, settings: S3Settings) -> ObjectStoreClient:
        """Create client from S3Settings configuration.

        Args:
            settings: S3Settings instance from config.

        Returns:
            Configured ObjectStoreClient instance.
        """
        return cls(
            endpoint_url=settings.endpoint,
            access_key=settings.access_key.get_secret_value(),
            secret_key=settings.secret_key.get_secret_value(),
            region=settings.region,
        )

    def _compute_sha256(self, data: bytes) -> str:
        """Compute SHA-256 hex digest of data.

        Args:
            data: Bytes to hash.

        Returns:
            Lowercase hex digest string.
        """
        return hashlib.sha256(data).hexdigest()

    def ensure_bucket(self, bucket: str | Buckets) -> bool:
        """Ensure a bucket exists, creating it if necessary.

        Args:
            bucket: Bucket name or Buckets enum value.

        Returns:
            True if bucket was created, False if it already existed.

        Raises:
            StorageError: If bucket creation fails.
        """
        bucket_name = bucket.value if isinstance(bucket, Buckets) else bucket

        try:
            self._client.head_bucket(Bucket=bucket_name)
            logger.debug("Bucket %s already exists", bucket_name)
            return False
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "404":
                # Bucket does not exist, create it
                try:
                    # MinIO and most S3-compatible stores handle region differently
                    # For us-east-1, don't specify LocationConstraint
                    if self._region == "us-east-1":
                        self._client.create_bucket(Bucket=bucket_name)
                    else:
                        self._client.create_bucket(
                            Bucket=bucket_name,
                            CreateBucketConfiguration={"LocationConstraint": self._region},
                        )
                    logger.info("Created bucket: %s", bucket_name)
                    return True
                except ClientError as create_error:
                    raise StorageError(
                        f"Failed to create bucket: {create_error}",
                        bucket=bucket_name,
                        operation="create_bucket",
                    ) from create_error
            else:
                raise StorageError(
                    f"Failed to check bucket existence: {e}",
                    bucket=bucket_name,
                    operation="head_bucket",
                ) from e

    def ensure_standard_buckets(self) -> dict[str, bool]:
        """Ensure all standard QERDS buckets exist.

        Creates any missing buckets from the Buckets enum.

        Returns:
            Dict mapping bucket name to whether it was created (True) or
            already existed (False).
        """
        results = {}
        for bucket in Buckets:
            results[bucket.value] = self.ensure_bucket(bucket)
        return results

    def upload(
        self,
        bucket: str | Buckets,
        key: str,
        data: bytes,
        *,
        content_type: str = "application/octet-stream",
        metadata: dict[str, str] | None = None,
    ) -> UploadResult:
        """Upload content to object storage with integrity verification.

        The SHA-256 digest is computed and stored in object metadata for
        later verification during download.

        Args:
            bucket: Target bucket name or Buckets enum value.
            key: Object key (path within bucket).
            data: Content bytes to upload.
            content_type: MIME type of the content.
            metadata: Additional custom metadata to store.

        Returns:
            UploadResult with digest and storage details.

        Raises:
            StorageError: If upload fails.
            BucketNotFoundError: If bucket does not exist.
        """
        bucket_name = bucket.value if isinstance(bucket, Buckets) else bucket

        # Compute integrity digest before upload
        sha256_digest = self._compute_sha256(data)
        size_bytes = len(data)

        # Prepare metadata with digest
        upload_metadata = {
            "sha256-digest": sha256_digest,
        }
        if metadata:
            upload_metadata.update(metadata)

        try:
            response = self._client.put_object(
                Bucket=bucket_name,
                Key=key,
                Body=data,
                ContentType=content_type,
                Metadata=upload_metadata,
            )

            etag = response.get("ETag", "")
            version_id = response.get("VersionId")

            logger.debug(
                "Uploaded %s/%s (%d bytes, sha256=%s)",
                bucket_name,
                key,
                size_bytes,
                sha256_digest[:16] + "...",
            )

            return UploadResult(
                key=key,
                bucket=bucket_name,
                sha256_digest=sha256_digest,
                size_bytes=size_bytes,
                etag=etag,
                version_id=version_id,
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchBucket":
                raise BucketNotFoundError(
                    f"Bucket does not exist: {bucket_name}",
                    bucket=bucket_name,
                    key=key,
                    operation="upload",
                ) from e
            raise StorageError(
                f"Upload failed: {e}",
                bucket=bucket_name,
                key=key,
                operation="upload",
            ) from e

    def upload_content_addressed(
        self,
        bucket: str | Buckets,
        data: bytes,
        *,
        prefix: str = "",
        content_type: str = "application/octet-stream",
        metadata: dict[str, str] | None = None,
    ) -> UploadResult:
        """Upload content using its SHA-256 digest as the key.

        Content-addressed storage ensures deduplication and provides
        built-in integrity verification via the key itself.

        Args:
            bucket: Target bucket name or Buckets enum value.
            data: Content bytes to upload.
            prefix: Optional prefix for the key (e.g., "blobs/").
            content_type: MIME type of the content.
            metadata: Additional custom metadata to store.

        Returns:
            UploadResult with the content-addressed key.

        Raises:
            StorageError: If upload fails.
        """
        sha256_digest = self._compute_sha256(data)
        key = f"{prefix}{sha256_digest}" if prefix else sha256_digest

        return self.upload(
            bucket=bucket,
            key=key,
            data=data,
            content_type=content_type,
            metadata=metadata,
        )

    def download(
        self,
        bucket: str | Buckets,
        key: str,
        *,
        verify_integrity: bool = True,
        expected_digest: str | None = None,
    ) -> tuple[bytes, ObjectMetadata]:
        """Download content from object storage with integrity verification.

        By default, verifies the SHA-256 digest stored in metadata matches
        the downloaded content. If expected_digest is provided, it takes
        precedence over the stored metadata.

        Args:
            bucket: Source bucket name or Buckets enum value.
            key: Object key to download.
            verify_integrity: Whether to verify SHA-256 digest.
            expected_digest: Expected SHA-256 digest (overrides metadata).

        Returns:
            Tuple of (content bytes, ObjectMetadata).

        Raises:
            ObjectNotFoundError: If object does not exist.
            IntegrityError: If digest verification fails.
            StorageError: If download fails.
        """
        bucket_name = bucket.value if isinstance(bucket, Buckets) else bucket

        try:
            response = self._client.get_object(Bucket=bucket_name, Key=key)

            data = response["Body"].read()
            stored_digest = response.get("Metadata", {}).get("sha256-digest")
            content_type = response.get("ContentType", "application/octet-stream")
            etag = response.get("ETag", "")
            last_modified = response.get("LastModified")
            version_id = response.get("VersionId")

            # Build metadata object
            metadata = ObjectMetadata(
                key=key,
                bucket=bucket_name,
                size_bytes=len(data),
                content_type=content_type,
                sha256_digest=stored_digest,
                etag=etag,
                last_modified=last_modified.isoformat() if last_modified else "",
                version_id=version_id,
                custom_metadata=response.get("Metadata"),
            )

            # Verify integrity if requested
            if verify_integrity:
                computed_digest = self._compute_sha256(data)
                digest_to_check = expected_digest or stored_digest

                if digest_to_check and computed_digest != digest_to_check:
                    raise IntegrityError(
                        f"Content integrity check failed: expected {digest_to_check[:16]}..., "
                        f"got {computed_digest[:16]}...",
                        bucket=bucket_name,
                        key=key,
                        operation="download",
                    )

            logger.debug(
                "Downloaded %s/%s (%d bytes)",
                bucket_name,
                key,
                len(data),
            )

            return data, metadata

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchKey":
                raise ObjectNotFoundError(
                    f"Object does not exist: {bucket_name}/{key}",
                    bucket=bucket_name,
                    key=key,
                    operation="download",
                ) from e
            if error_code == "NoSuchBucket":
                raise BucketNotFoundError(
                    f"Bucket does not exist: {bucket_name}",
                    bucket=bucket_name,
                    key=key,
                    operation="download",
                ) from e
            raise StorageError(
                f"Download failed: {e}",
                bucket=bucket_name,
                key=key,
                operation="download",
            ) from e

    def delete(
        self,
        bucket: str | Buckets,
        key: str,
    ) -> bool:
        """Delete an object from storage.

        Note: S3 delete is idempotent - deleting a non-existent object
        does not raise an error. This method returns True if the delete
        was acknowledged.

        Args:
            bucket: Bucket name or Buckets enum value.
            key: Object key to delete.

        Returns:
            True if delete was acknowledged.

        Raises:
            StorageError: If delete fails.
        """
        bucket_name = bucket.value if isinstance(bucket, Buckets) else bucket

        try:
            self._client.delete_object(Bucket=bucket_name, Key=key)
            logger.debug("Deleted %s/%s", bucket_name, key)
            return True

        except ClientError as e:
            raise StorageError(
                f"Delete failed: {e}",
                bucket=bucket_name,
                key=key,
                operation="delete",
            ) from e

    def exists(
        self,
        bucket: str | Buckets,
        key: str,
    ) -> bool:
        """Check if an object exists.

        Args:
            bucket: Bucket name or Buckets enum value.
            key: Object key to check.

        Returns:
            True if object exists, False otherwise.

        Raises:
            StorageError: If check fails for reasons other than not found.
        """
        bucket_name = bucket.value if isinstance(bucket, Buckets) else bucket

        try:
            self._client.head_object(Bucket=bucket_name, Key=key)
            return True
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "404":
                return False
            raise StorageError(
                f"Existence check failed: {e}",
                bucket=bucket_name,
                key=key,
                operation="exists",
            ) from e

    def get_metadata(
        self,
        bucket: str | Buckets,
        key: str,
    ) -> ObjectMetadata:
        """Get object metadata without downloading content.

        Args:
            bucket: Bucket name or Buckets enum value.
            key: Object key.

        Returns:
            ObjectMetadata for the object.

        Raises:
            ObjectNotFoundError: If object does not exist.
            StorageError: If metadata retrieval fails.
        """
        bucket_name = bucket.value if isinstance(bucket, Buckets) else bucket

        try:
            response = self._client.head_object(Bucket=bucket_name, Key=key)

            return ObjectMetadata(
                key=key,
                bucket=bucket_name,
                size_bytes=response.get("ContentLength", 0),
                content_type=response.get("ContentType", "application/octet-stream"),
                sha256_digest=response.get("Metadata", {}).get("sha256-digest"),
                etag=response.get("ETag", ""),
                last_modified=(
                    response["LastModified"].isoformat() if response.get("LastModified") else ""
                ),
                version_id=response.get("VersionId"),
                custom_metadata=response.get("Metadata"),
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "404":
                raise ObjectNotFoundError(
                    f"Object does not exist: {bucket_name}/{key}",
                    bucket=bucket_name,
                    key=key,
                    operation="get_metadata",
                ) from e
            raise StorageError(
                f"Metadata retrieval failed: {e}",
                bucket=bucket_name,
                key=key,
                operation="get_metadata",
            ) from e

    def list_objects(
        self,
        bucket: str | Buckets,
        prefix: str = "",
        *,
        max_keys: int = 1000,
    ) -> list[ObjectMetadata]:
        """List objects in a bucket with optional prefix filter.

        Args:
            bucket: Bucket name or Buckets enum value.
            prefix: Key prefix to filter by.
            max_keys: Maximum number of keys to return.

        Returns:
            List of ObjectMetadata for matching objects.

        Raises:
            BucketNotFoundError: If bucket does not exist.
            StorageError: If listing fails.
        """
        bucket_name = bucket.value if isinstance(bucket, Buckets) else bucket
        objects: list[ObjectMetadata] = []

        try:
            paginator = self._client.get_paginator("list_objects_v2")
            page_iterator = paginator.paginate(
                Bucket=bucket_name,
                Prefix=prefix,
                PaginationConfig={"MaxItems": max_keys},
            )

            for page in page_iterator:
                for obj in page.get("Contents", []):
                    objects.append(
                        ObjectMetadata(
                            key=obj["Key"],
                            bucket=bucket_name,
                            size_bytes=obj.get("Size", 0),
                            content_type="",  # Not available in list response
                            sha256_digest=None,  # Not available in list response
                            etag=obj.get("ETag", ""),
                            last_modified=(
                                obj["LastModified"].isoformat() if obj.get("LastModified") else ""
                            ),
                        )
                    )

            return objects

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchBucket":
                raise BucketNotFoundError(
                    f"Bucket does not exist: {bucket_name}",
                    bucket=bucket_name,
                    operation="list_objects",
                ) from e
            raise StorageError(
                f"List objects failed: {e}",
                bucket=bucket_name,
                operation="list_objects",
            ) from e

    def generate_presigned_url(
        self,
        bucket: str | Buckets,
        key: str,
        *,
        expires_in: int = 3600,
        operation: str = "get_object",
    ) -> str:
        """Generate a presigned URL for direct object access.

        Presigned URLs allow temporary direct access to objects without
        requiring authentication through the application.

        Args:
            bucket: Bucket name or Buckets enum value.
            key: Object key.
            expires_in: URL expiration time in seconds (default: 1 hour).
            operation: S3 operation ('get_object' or 'put_object').

        Returns:
            Presigned URL string.

        Raises:
            StorageError: If URL generation fails.
        """
        bucket_name = bucket.value if isinstance(bucket, Buckets) else bucket

        try:
            url = self._client.generate_presigned_url(
                ClientMethod=operation,
                Params={"Bucket": bucket_name, "Key": key},
                ExpiresIn=expires_in,
            )
            logger.debug(
                "Generated presigned URL for %s/%s (expires in %ds)",
                bucket_name,
                key,
                expires_in,
            )
            return url

        except ClientError as e:
            raise StorageError(
                f"Presigned URL generation failed: {e}",
                bucket=bucket_name,
                key=key,
                operation="generate_presigned_url",
            ) from e

    def copy(
        self,
        source_bucket: str | Buckets,
        source_key: str,
        dest_bucket: str | Buckets,
        dest_key: str,
    ) -> ObjectMetadata:
        """Copy an object within or between buckets.

        Args:
            source_bucket: Source bucket name or Buckets enum.
            source_key: Source object key.
            dest_bucket: Destination bucket name or Buckets enum.
            dest_key: Destination object key.

        Returns:
            ObjectMetadata for the new copy.

        Raises:
            ObjectNotFoundError: If source object does not exist.
            StorageError: If copy fails.
        """
        src_bucket = source_bucket.value if isinstance(source_bucket, Buckets) else source_bucket
        dst_bucket = dest_bucket.value if isinstance(dest_bucket, Buckets) else dest_bucket

        try:
            copy_source = {"Bucket": src_bucket, "Key": source_key}
            self._client.copy_object(
                Bucket=dst_bucket,
                Key=dest_key,
                CopySource=copy_source,
            )

            logger.debug(
                "Copied %s/%s to %s/%s",
                src_bucket,
                source_key,
                dst_bucket,
                dest_key,
            )

            # Return metadata for the new object
            return self.get_metadata(dst_bucket, dest_key)

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchKey":
                raise ObjectNotFoundError(
                    f"Source object does not exist: {src_bucket}/{source_key}",
                    bucket=src_bucket,
                    key=source_key,
                    operation="copy",
                ) from e
            raise StorageError(
                f"Copy failed: {e}",
                bucket=dst_bucket,
                key=dest_key,
                operation="copy",
            ) from e

    def health_check(self) -> dict[str, Any]:
        """Perform a health check on the object store connection.

        Returns:
            Dict with health status and bucket information.

        Raises:
            StorageError: If health check fails.
        """
        try:
            response = self._client.list_buckets()
            buckets = [b["Name"] for b in response.get("Buckets", [])]

            return {
                "healthy": True,
                "endpoint": self._endpoint_url,
                "buckets": buckets,
                "bucket_count": len(buckets),
            }

        except ClientError as e:
            raise StorageError(
                f"Health check failed: {e}",
                operation="health_check",
            ) from e
