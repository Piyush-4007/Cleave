"""Importing this package registers all collectors (via each module's @collector)."""
from . import iam, s3, ec2, vpc, lambda_, rds, secrets, kms  # noqa: F401
