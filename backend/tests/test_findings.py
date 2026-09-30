"""Findings layer: every check fires on a minimal bad account and stays silent on a good one,
and the engine ranks by reachability first.

Each case is (check, records that must trigger it, records that must not). Records are
collector-shaped, so this also pins the fields each check depends on.
"""
import datetime as dt
import json
import pathlib
import pytest

from cleave.findings import load_catalog, run_checks, summarize, tag_and_rank
from cleave.findings.checks import CHECKS
from cleave.paths.analysis import analyze
from cleave.paths.graphview import graph_from_records

NOW = dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc)
A = "arn:aws:iam::111122223333:"
FIX = pathlib.Path(__file__).parent / "path_fixtures"


def fired(records, check, now=NOW):
    return [f for f in run_checks(graph_from_records(records), now=now) if f["check"] == check]


def row(user, **kw):
    base = {"user": user, "arn": f"{A}user/{user}" if user != "<root_account>" else f"{A}root",
            "user_creation_time": "2025-01-01T00:00:00+00:00", "password_enabled": False,
            "password_last_used": None, "mfa_active": False,
            "access_key_1_active": False, "access_key_1_last_rotated": None,
            "access_key_1_last_used_date": None, "access_key_2_active": False,
            "access_key_2_last_rotated": None, "access_key_2_last_used_date": None}
    return {**base, **kw}


def report(*rows):
    return {"_type": "IamCredentialReport", "_id": "account:credential-report",
            "GeneratedTime": NOW.isoformat(), "Rows": list(rows)}


def summary(**kw):
    return {"_type": "IamAccountSummary", "_id": "account:summary",
            "Summary": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0, **kw}}


def user(name, attached=(), inline=None):
    return {"_type": "IamUser", "_id": f"{A}user/{name}", "UserName": name,
            "AttachedPolicies": list(attached), "Groups": [], "InlinePolicies": inline or {}}


def policy(name, doc, aws=False):
    arn = f"arn:aws:iam::aws:policy/{name}" if aws else f"{A}policy/{name}"
    return {"_type": "IamPolicy", "_id": arn, "PolicyName": name, "Document": doc}


STAR = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
ESC = {"Statement": [{"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}]}


def role(name, trust):
    return {"_type": "IamRole", "_id": f"{A}role/{name}", "RoleName": name, "AttachedPolicies": [],
            "InlinePolicies": {}, "TrustPolicy": {"Statement": [
                {"Effect": "Allow", "Action": "sts:AssumeRole", **trust}]}}


def bucket(name, **kw):
    full = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True}
    return {"_type": "S3Bucket", "_id": f"arn:aws:s3:::{name}", "Name": name, "Region": "us-east-1",
            "PublicAccessBlock": full, "Encryption": {"Rules": [{}]}, "Acl": [], "Policy": None,
            "Tags": {}, **kw}


def instance(iid="i-1", **kw):
    return {"_type": "Ec2Instance", "_id": iid, "InstanceId": iid, "Region": "us-east-1",
            "State": "running", "ImdsHttpTokens": "required", "SecurityGroups": [],
            "PublicIpAddress": None, "IamInstanceProfile": None, **kw}


def sg(gid="sg-1", name="web", ingress=(), egress=()):
    return {"_type": "SecurityGroup", "_id": gid, "GroupId": gid, "GroupName": name,
            "Region": "us-east-1", "VpcId": "vpc-1", "IngressRules": list(ingress),
            "EgressRules": list(egress)}


def rule(proto, lo=None, hi=None, cidr="0.0.0.0/0"):
    r = {"IpProtocol": proto, "IpRanges": [{"CidrIp": cidr}], "Ipv6Ranges": []}
    if lo is not None:
        r.update(FromPort=lo, ToPort=hi if hi is not None else lo)
    return r


def fn(name="f", **kw):
    return {"_type": "LambdaFunction", "_id": f"arn:aws:lambda:us-east-1:111122223333:function:{name}",
            "FunctionName": name, "Region": "us-east-1", "Runtime": "python3.12", "Role": None,
            "FunctionUrlAuthType": None, "EnvVars": {}, **kw}


def rds(**kw):
    return {"_type": "RdsInstance", "_id": "arn:aws:rds:us-east-1:111122223333:db:d",
            "DBInstanceIdentifier": "d", "Region": "us-east-1", "PubliclyAccessible": False,
            "StorageEncrypted": True, "DeletionProtection": True, "Tags": {}, **kw}


def key(**kw):
    return {"_type": "KmsKey", "_id": "arn:aws:kms:us-east-1:111122223333:key/k", "KeyId": "k",
            "Region": "us-east-1", "KeyManager": "CUSTOMER", "KeyState": "Enabled",
            "KeySpec": "SYMMETRIC_DEFAULT", "KeyRotationEnabled": True, "Policy": {}, **kw}


def trail(**kw):
    return {"_type": "CloudTrailTrail", "_id": "arn:aws:cloudtrail:us-east-1:111122223333:trail/t",
            "Name": "t", "HomeRegion": "us-east-1", "IsMultiRegionTrail": True, "IsLogging": True,
            "LogFileValidationEnabled": True, "KmsKeyId": "k", **kw}


CT_OK = {"_type": "CloudTrailStatus", "_id": "account:cloudtrail", "Trails": 1}
PUBLIC_STMT = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]}
OLD = "2025-01-01T00:00:00+00:00"   # > 90 days before NOW
RECENT = "2026-09-25T00:00:00+00:00"

CASES = [
    ("IAM.ROOT_MFA", [summary(AccountMFAEnabled=0)], [summary()]),
    ("IAM.ROOT_KEYS", [summary(AccountAccessKeysPresent=1)], [summary()]),
    ("IAM.ROOT_RECENTLY_USED", [report(row("<root_account>", password_last_used=RECENT))],
     [report(row("<root_account>", password_last_used=OLD))]),
    ("IAM.USER_NO_MFA", [report(row("bob", password_enabled=True))],
     [report(row("bob", password_enabled=True, mfa_active=True), row("api", password_enabled=False))]),
    ("IAM.CREDENTIALS_UNUSED", [report(row("bob", access_key_1_active=True, access_key_1_last_rotated=OLD))],
     [report(row("bob", access_key_1_active=True, access_key_1_last_rotated=OLD,
                 access_key_1_last_used_date=RECENT))]),
    ("IAM.KEY_NOT_ROTATED", [report(row("bob", access_key_1_active=True, access_key_1_last_rotated=OLD))],
     [report(row("bob", access_key_1_active=True, access_key_1_last_rotated=RECENT),
             row("old-but-off", access_key_1_active=False, access_key_1_last_rotated=OLD))]),
    ("IAM.MULTIPLE_ACTIVE_KEYS", [report(row("bob", access_key_1_active=True, access_key_2_active=True))],
     [report(row("bob", access_key_1_active=True))]),
    ("IAM.NO_PASSWORD_POLICY", [{"_type": "IamPasswordPolicy", "_id": "account:password-policy", "Policy": None}],
     [{"_type": "IamPasswordPolicy", "_id": "account:password-policy",
       "Policy": {"MinimumPasswordLength": 14, "PasswordReusePrevention": 24}}]),
    ("IAM.WEAK_PASSWORD_POLICY", [{"_type": "IamPasswordPolicy", "_id": "account:password-policy",
                                   "Policy": {"MinimumPasswordLength": 8}}],
     [{"_type": "IamPasswordPolicy", "_id": "account:password-policy",
       "Policy": {"MinimumPasswordLength": 14, "PasswordReusePrevention": 24}}]),
    ("IAM.USER_DIRECT_POLICY", [user("bob", attached=[f"{A}policy/p"])], [user("bob")]),
    ("IAM.FULL_ADMIN_POLICY", [user("bob", attached=[f"{A}policy/god"]), policy("god", STAR)],
     [user("bob", attached=["arn:aws:iam::aws:policy/AdministratorAccess"]),
      policy("AdministratorAccess", STAR, aws=True), policy("unattached", STAR)]),
    ("IAM.ESCALATION_PRIMITIVE", [user("bob", attached=[f"{A}policy/esc"]), policy("esc", ESC)],
     [user("bob", attached=[f"{A}policy/god"]), policy("god", STAR)]),
    ("IAM.ROLE_TRUSTS_ANYONE", [role("open", {"Principal": "*"})],
     [role("svc", {"Principal": {"Service": "lambda.amazonaws.com"}})]),
    ("IAM.ROLE_CROSS_ACCOUNT_NO_EXTERNAL_ID", [role("x", {"Principal": {"AWS": "arn:aws:iam::999988887777:root"}})],
     [role("x", {"Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                 "Condition": {"StringEquals": {"sts:ExternalId": "abc"}}}),
      role("same", {"Principal": {"AWS": f"{A}root"}})]),
    ("S3.PUBLIC_BUCKET", [bucket("pub", PublicAccessBlock=None, Policy=PUBLIC_STMT)], [bucket("priv")]),
    ("S3.BLOCK_PUBLIC_ACCESS_OFF", [bucket("b", PublicAccessBlock=None)], [bucket("b")]),
    ("S3.NO_DEFAULT_ENCRYPTION", [bucket("b", Encryption=None)], [bucket("b")]),
    ("EC2.IMDSV1_ALLOWED", [instance(ImdsHttpTokens="optional")], [instance()]),
    ("EC2.PUBLIC_IP", [instance(PublicIpAddress="3.3.3.3")], [instance()]),
    ("EC2.EBS_UNENCRYPTED", [{"_type": "EbsVolume", "_id": "vol-1", "VolumeId": "vol-1", "Region": "us-east-1",
                              "Encrypted": False, "AttachedTo": []}],
     [{"_type": "EbsVolume", "_id": "vol-1", "VolumeId": "vol-1", "Region": "us-east-1",
       "Encrypted": True, "AttachedTo": []}]),
    ("EC2.EBS_DEFAULT_ENCRYPTION_OFF", [{"_type": "EbsDefaults", "_id": "account:ebs-defaults:us-east-1",
                                         "Region": "us-east-1", "EncryptionByDefault": False}],
     [{"_type": "EbsDefaults", "_id": "account:ebs-defaults:us-east-1", "Region": "us-east-1",
       "EncryptionByDefault": True}]),
    ("VPC.SG_ALL_TRAFFIC_OPEN", [sg(ingress=[rule("-1")])], [sg(ingress=[rule("-1", cidr="10.0.0.0/8")])]),
    ("VPC.SG_ADMIN_PORTS_OPEN", [sg(ingress=[rule("tcp", 20, 25)])],
     [sg(ingress=[rule("tcp", 443)]), sg("sg-2", ingress=[rule("tcp", 22, cidr="10.0.0.0/8")]),
      sg("sg-3", ingress=[rule("-1")])]),   # all-open is reported once, as SG_ALL_TRAFFIC_OPEN
    ("VPC.SG_DATABASE_PORTS_OPEN", [sg(ingress=[rule("tcp", 5432)])], [sg(ingress=[rule("tcp", 80)])]),
    ("VPC.DEFAULT_SG_NOT_RESTRICTED", [sg(name="default", egress=[rule("-1")])],
     [sg(name="default"), sg(name="web", egress=[rule("-1")])]),
    ("VPC.NACL_ADMIN_PORTS_OPEN",
     [{"_type": "NetworkAcl", "_id": "acl-1", "Region": "us-east-1", "Entries": [
         {"RuleNumber": 100, "Egress": False, "RuleAction": "allow", "Protocol": "-1", "CidrBlock": "0.0.0.0/0"}]}],
     [{"_type": "NetworkAcl", "_id": "acl-1", "Region": "us-east-1", "Entries": [
         {"RuleNumber": 100, "Egress": False, "RuleAction": "allow", "Protocol": "6",
          "PortRange": {"From": 443, "To": 443}, "CidrBlock": "0.0.0.0/0"}]}]),
    ("LAMBDA.URL_NO_AUTH", [fn(FunctionUrlAuthType="NONE")], [fn(FunctionUrlAuthType="AWS_IAM")]),
    ("LAMBDA.SECRET_IN_ENV", [fn(EnvVars={"DB_PASSWORD": "hunter2"})], [fn(EnvVars={"LOG_LEVEL": "info"})]),
    ("LAMBDA.DEPRECATED_RUNTIME", [fn(Runtime="python3.7")], [fn()]),
    ("RDS.PUBLIC", [rds(PubliclyAccessible=True)], [rds()]),
    ("RDS.UNENCRYPTED", [rds(StorageEncrypted=False)], [rds()]),
    ("RDS.NO_DELETION_PROTECTION", [rds(DeletionProtection=False)], [rds()]),
    ("SECRETS.PUBLIC_POLICY", [{"_type": "SecretsManagerSecret", "_id": "arn:s", "Name": "s", "Region": "us-east-1",
                                "ResourcePolicy": PUBLIC_STMT}],
     [{"_type": "SecretsManagerSecret", "_id": "arn:s", "Name": "s", "Region": "us-east-1", "ResourcePolicy": None}]),
    ("KMS.PUBLIC_POLICY", [key(Policy=PUBLIC_STMT)], [key()]),
    ("KMS.NO_ROTATION", [key(KeyRotationEnabled=False)],
     [key(), key(KeyRotationEnabled=False, KeySpec="RSA_2048")]),
    ("CLOUDTRAIL.NOT_ENABLED", [CT_OK], [CT_OK, trail()]),
    ("CLOUDTRAIL.NO_LOG_VALIDATION", [CT_OK, trail(LogFileValidationEnabled=False)], [CT_OK, trail()]),
    ("CLOUDTRAIL.NOT_KMS_ENCRYPTED", [CT_OK, trail(KmsKeyId=None)], [CT_OK, trail()]),
]


def test_every_check_has_a_catalog_entry_and_a_test_case():
    cat = load_catalog()
    assert set(CHECKS) == set(cat), "checks and catalog.json must match one-to-one"
    tested = {c[0] for c in CASES} | {"CRED.KEY_IN_S3"}   # CRED is covered via a path fixture below
    assert tested == set(CHECKS)
    for cid, meta in cat.items():
        assert meta["severity"] in ("critical", "high", "medium", "low", "info"), cid
        assert meta["title"] and meta["remediation"], cid


@pytest.mark.parametrize("check,bad,good", CASES, ids=[c[0] for c in CASES])
def test_check_fires_on_bad_and_not_on_good(check, bad, good):
    hits = fired(bad, check)
    assert hits, f"{check} did not fire"
    assert all(h["evidence"] for h in hits)
    assert fired(good, check) == [], f"{check} fired on a compliant account"


def test_unknown_is_not_a_finding():
    """No record = could not read = unknown. Silence, never a false 'misconfigured'."""
    assert run_checks(graph_from_records([]), now=NOW) == []


def test_secret_values_never_appear_in_evidence():
    hits = fired([fn(EnvVars={"DB_PASSWORD": "hunter2", "X": "AKIAABCDEFGHIJKLMNOP"})], "LAMBDA.SECRET_IN_ENV")
    ev = hits[0]["evidence"]
    assert "DB_PASSWORD" in ev and "X" in ev
    assert "hunter2" not in ev and "AKIA" not in ev


def test_severity_override_carries_a_reason():
    plain = fired([instance(ImdsHttpTokens="optional")], "EC2.IMDSV1_ALLOWED")[0]
    carrying = fired([instance(ImdsHttpTokens="optional", IamInstanceProfile=f"{A}instance-profile/p")],
                     "EC2.IMDSV1_ALLOWED")[0]
    assert plain["severity"] == "medium" and plain["severity_reason"] is None
    assert carrying["severity"] == "high" and carrying["severity_reason"]


def test_deterministic_given_the_report_time():
    """Age checks measure against the credential report's own timestamp, not the wall clock."""
    recs = [report(row("bob", access_key_1_active=True, access_key_1_last_rotated=OLD))]
    a = run_checks(graph_from_records(recs))
    b = run_checks(graph_from_records(recs))
    assert a == b and [f["check"] for f in a] == ["IAM.CREDENTIALS_UNUSED", "IAM.KEY_NOT_ROTATED"]


# ---- reachability tagging on ground-truth fixtures ------------------------------------------

def _analyzed(name):
    fx = json.loads((FIX / name).read_text())
    g = graph_from_records(fx["records"], fx.get("cred_findings", []))
    a = analyze(g)
    return a, {f["check"] + "|" + f["resource"]: f for f in a["findings"]}


def test_findings_on_the_phase0_path_are_tagged_and_ranked_first():
    """iam_privesc_by_attachment: kerrigan's directly-attached policy is on the one real path."""
    a, by = _analyzed("02-iam_privesc_by_attachment.json")
    kerrigan = "arn:aws:iam::111122223333:user/kerrigan"
    f = by[f"IAM.USER_DIRECT_POLICY|{kerrigan}"]
    assert f["reachability"] == "on_path" and f["paths"] == [a["paths"][0]["id"]]
    tags = [x["reachability"] for x in a["findings"]]
    assert tags == sorted(tags, key=["on_path", "entry_point", "account", "not_reachable"].index)


def test_credential_in_s3_finding_is_on_its_path():
    a, by = _analyzed("03-public-bucket-credential-to-admin.json")
    cred = [f for k, f in by.items() if k.startswith("CRED.KEY_IN_S3|")]
    assert cred and all(f["reachability"] == "on_path" for f in cred)
    assert any(k.startswith("S3.PUBLIC_BUCKET|") and f["reachability"] == "on_path" for k, f in by.items())


def test_summary_counts_add_up():
    a, _ = _analyzed("06-overlapping-paths-shared-cut.json")
    s = a["findings_summary"]
    assert sum(s["by_severity"].values()) == sum(s["by_reachability"].values()) == s["total"] == len(a["findings"])
