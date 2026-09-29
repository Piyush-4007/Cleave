"""Builds a boto3 Session for scanning.

Two connect modes (both local-first — no credential ever leaves the machine):
  * "login"  — use the machine's ambient AWS credentials (what boto3's default chain
               finds: an `aws configure` profile, an `aws sso login` session, an instance
               role, env vars). This is the one-click "connect with my AWS login" path.
  * "role"   — assume a read-only role by ARN (the CleaveAudit / Option A path). Cleave
               holds no key; it assumes a role the user created and pasted.
"""
import boto3
from .config import settings


def build_session_for(role_arn: str | None = None) -> boto3.Session:
    """Session for a scan. With `role_arn`, assume that role; without it, use ambient creds."""
    base_kwargs = {"region_name": settings.aws_region}
    if settings.aws_profile:
        base_kwargs["profile_name"] = settings.aws_profile
    base = boto3.Session(**base_kwargs)

    if not role_arn:
        return base

    creds = base.client("sts").assume_role(
        RoleArn=role_arn, RoleSessionName="cleave-scan",
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=settings.aws_region,
    )


def build_session() -> boto3.Session:
    """The default scan session, from settings (CLEAVE_ROLE_ARN if set, else ambient)."""
    return build_session_for(settings.cleave_role_arn or None)
