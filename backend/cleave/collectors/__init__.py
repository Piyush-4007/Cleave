"""Importing this package registers all collectors (via each module's @collector)."""
from . import (iam, s3, ec2, vpc, lambda_, rds, secrets, kms, cloudtrail,  # noqa: F401
               workloads, messaging)  # noqa: F401
