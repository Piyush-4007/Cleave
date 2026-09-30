"""Central config — every value comes from the environment (see .env.example).
Rule 11 of the handbook: config from environment, never hard-coded."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # AWS
    cleave_role_arn: str = ""
    aws_region: str = "us-east-1"
    aws_profile: str = ""
    cleave_output_dir: str = "/data/raw"
    # Credential-in-content scanning reads S3 object *bodies* (s3:GetObject), which the
    # default read-only role (SecurityAudit + ViewOnlyAccess) does NOT grant. Off by
    # default: the user opts in by adding s3:GetObject to the role AND setting this true.
    # See docs/opt-in-credscan.md.
    cleave_credscan: bool = False
    # Scan concurrency: threads per fan-out (regions, IAM principals, S3 buckets). The scan
    # is network-bound, so this mostly trades wall-clock for API rate. 1 = fully serial.
    cleave_scan_workers: int = 16

    # API / desktop. Where the analysis graph comes from: "neo4j" (the compose stack; falls
    # back to the raw dump if Neo4j is down) or "memory" (raw dump only — the desktop app,
    # which ships no Neo4j). A non-empty token makes every route except /health require an
    # X-Cleave-Token header; the desktop shell sets a random one per launch so no other
    # local web page can drive a scan with the user's AWS credentials.
    cleave_graph_store: str = "neo4j"
    cleave_api_token: str = ""
    cleave_cors_origins: str = "http://localhost:3000,http://localhost:5173"
    # Scan history (SQLite). Blank = cleave.db beside the raw-dump folder.
    cleave_db_path: str = ""

    # Neo4j
    neo4j_uri: str = "bolt://neo4j:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""

    # Postgres
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_user: str = "cleave"
    postgres_password: str = ""
    postgres_db: str = "cleave"

    # Redis
    redis_url: str = "redis://redis:6379/0"


settings = Settings()
