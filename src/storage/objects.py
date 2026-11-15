"""Object storage for models, signatures and reports (S3 API: MinIO or AWS).

Keys are immutable: writing a key that already exists succeeds only if the bytes are
identical. Release keys contain the content hash, so a release can never be silently
replaced by different bytes."""
import hashlib
import os
from typing import Protocol


class ImmutableKeyError(Exception):
    pass


class ObjectStore(Protocol):
    def put_immutable(self, key: str, data: bytes) -> None: ...
    def get(self, key: str) -> bytes: ...


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class MemoryStore:
    """For tests. Same rules as S3Store."""

    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def put_immutable(self, key: str, data: bytes) -> None:
        if key in self.objects and self.objects[key] != data:
            raise ImmutableKeyError(f"{key} already exists with different content")
        self.objects[key] = data

    def get(self, key: str) -> bytes:
        return self.objects[key]


class S3Store:
    def __init__(self, endpoint: str, bucket: str, access_key: str, secret_key: str):
        import boto3  # imported here so the rest of the app does not need it

        self.bucket = bucket
        self.client = boto3.client(
            "s3", endpoint_url=endpoint, aws_access_key_id=access_key,
            aws_secret_access_key=secret_key, region_name="us-east-1",
        )

    def ensure_bucket(self) -> None:
        try:
            self.client.head_bucket(Bucket=self.bucket)
        except Exception:
            self.client.create_bucket(Bucket=self.bucket)

    def put_immutable(self, key: str, data: bytes) -> None:
        try:
            existing = self.client.get_object(Bucket=self.bucket, Key=key)["Body"].read()
        except self.client.exceptions.NoSuchKey:
            self.client.put_object(Bucket=self.bucket, Key=key, Body=data)
            return
        if existing != data:
            raise ImmutableKeyError(f"{key} already exists with different content")

    def get(self, key: str) -> bytes:
        return self.client.get_object(Bucket=self.bucket, Key=key)["Body"].read()


def store_from_env() -> S3Store:
    needed = ("MLSHIELD_S3_ENDPOINT", "MLSHIELD_S3_BUCKET", "MLSHIELD_S3_ACCESS_KEY", "MLSHIELD_S3_SECRET_KEY")
    missing = [n for n in needed if not os.environ.get(n)]
    if missing:
        raise RuntimeError(f"object storage is not configured, missing: {', '.join(missing)}")
    return S3Store(*(os.environ[n] for n in needed))
