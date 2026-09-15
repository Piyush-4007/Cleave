"""Builds a boto3 Session that has assumed the read-only CleaveAudit role.
Cleave NEVER holds write credentials — it only ever assumes this role."""
import boto3
from .config import settings


def build_session() -> boto3.Session:
    """Return a boto3 Session for scanning.

    If CLEAVE_ROLE_ARN is set, assume it (the product path). Otherwise fall back
    to the ambient credentials (useful in early dev before the role exists).
    """
    base_kwargs = {"region_name": settings.aws_region}
    if settings.aws_profile:
        base_kwargs["profile_name"] = settings.aws_profile
    base = boto3.Session(**base_kwargs)

    if not settings.cleave_role_arn:
        return base

    sts = base.client("sts")
    creds = sts.assume_role(
        RoleArn=settings.cleave_role_arn,
        RoleSessionName="cleave-scan",
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=settings.aws_region,
    )
