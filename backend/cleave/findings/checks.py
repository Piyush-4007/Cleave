"""The checks: deterministic, per-resource security findings (the Nessus-style layer).

Collectors read, checks judge (constraint 3): every check here reads collected records
off the graph and yields hits; nothing calls AWS. Titles, base severities, CIS references
and fixes live in catalog.json, so the wording and weights can change without touching
logic.

Each check yields `Hit`s: the resource, the evidence (the collected fact that triggered
it, quoted, so a reviewer can verify it by hand), and the graph nodes the finding concerns.
Those nodes are how the engine later decides "on an attack path" or "not reachable".

Time-based checks measure against `ctx.now`, which is the credential report's own
generation time when there is one. The same scan therefore always yields the same
findings, and the determinism rule holds.
"""
from __future__ import annotations
import datetime as _dt
import re
from dataclasses import dataclass, field
from typing import Callable, Iterator

from ..paths.endpoints import bucket_public_reason

CHECKS: dict[str, Callable[["Ctx"], Iterator["Hit"]]] = {}


def check(check_id: str):
    def deco(fn):
        CHECKS[check_id] = fn
        return fn
    return deco


@dataclass
class Hit:
    resource: str                     # graph uid (or "account" for account-wide facts)
    evidence: str                     # the collected fact that triggered it
    nodes: list[str] = field(default_factory=list)   # graph nodes this concerns
    name: str | None = None           # display name
    region: str | None = None
    severity: str | None = None       # override of the catalog severity, with a reason
    severity_reason: str | None = None


def _parse_ts(v) -> _dt.datetime | None:
    if v in (None, "", "N/A"):
        return None
    if isinstance(v, _dt.datetime):
        d = v
    else:
        try:
            d = _dt.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        except ValueError:
            return None
    return d if d.tzinfo else d.replace(tzinfo=_dt.timezone.utc)


class Ctx:
    """Read-only view of one scan for the checks."""

    def __init__(self, g, now: _dt.datetime | None = None):
        self.g = g
        self.by_type: dict[str, list[tuple[str, dict]]] = {}
        for uid, d in g.nodes(data=True):
            self.by_type.setdefault(d.get("label"), []).append((uid, d.get("record") or {}))
        for v in self.by_type.values():
            v.sort(key=lambda t: t[0])  # deterministic order
        report = self.one("IamCredentialReport")
        self.now = now or _parse_ts((report or {}).get("GeneratedTime")) \
            or _dt.datetime.now(_dt.timezone.utc)

    def of(self, label: str) -> list[tuple[str, dict]]:
        return self.by_type.get(label, [])

    def one(self, label: str) -> dict | None:
        items = self.of(label)
        return items[0][1] if items else None

    def days_since(self, v) -> float | None:
        t = _parse_ts(v)
        return None if t is None else (self.now - t).total_seconds() / 86400

    def report_rows(self) -> list[dict]:
        return (self.one("IamCredentialReport") or {}).get("Rows") or []


def _statements(doc) -> list[dict]:
    st = (doc or {}).get("Statement", []) if isinstance(doc, dict) else []
    return [s for s in ([st] if isinstance(st, dict) else st) if isinstance(s, dict)]


def _principal_values(pr) -> list[str]:
    if pr == "*":
        return ["*"]
    out = []
    for v in (pr or {}).values() if isinstance(pr, dict) else []:
        out += v if isinstance(v, list) else [v]
    return [str(x) for x in out]


def _public_statements(doc):
    """Allow statements naming Principal '*' (or AWS '*'): (statement, has_condition)."""
    for st in _statements(doc):
        if st.get("Effect") == "Allow" and "*" in _principal_values(st.get("Principal")):
            yield st, bool(st.get("Condition"))


# ---- IAM: root and credential hygiene (credential report / account summary) ------------

@check("IAM.ROOT_MFA")
def root_mfa(ctx):
    s = (ctx.one("IamAccountSummary") or {}).get("Summary") or {}
    if s.get("AccountMFAEnabled") == 0:
        yield Hit("account", "AccountSummary.AccountMFAEnabled = 0", name="root user")


@check("IAM.ROOT_KEYS")
def root_keys(ctx):
    s = (ctx.one("IamAccountSummary") or {}).get("Summary") or {}
    if (s.get("AccountAccessKeysPresent") or 0) > 0:
        yield Hit("account", f"AccountSummary.AccountAccessKeysPresent = {s['AccountAccessKeysPresent']}",
                  name="root user")


@check("IAM.ROOT_RECENTLY_USED")
def root_recent(ctx):
    root = next((r for r in ctx.report_rows() if r.get("user") == "<root_account>"), None)
    if not root:
        return
    for k in ("password_last_used", "access_key_1_last_used_date", "access_key_2_last_used_date"):
        d = ctx.days_since(root.get(k))
        if d is not None and d <= 90:
            yield Hit("account", f"credential report: root {k} = {root[k]} ({d:.0f} days ago)",
                      name="root user")
            return


def _user_rows(ctx):
    for r in ctx.report_rows():
        if r.get("user") != "<root_account>" and r.get("arn"):
            yield r


@check("IAM.USER_NO_MFA")
def user_no_mfa(ctx):
    for r in _user_rows(ctx):
        if r.get("password_enabled") is True and r.get("mfa_active") is False:
            yield Hit(r["arn"], "credential report: password_enabled = true, mfa_active = false",
                      nodes=[r["arn"]], name=r["user"])


@check("IAM.CREDENTIALS_UNUSED")
def creds_unused(ctx):
    for r in _user_rows(ctx):
        why = []
        if r.get("password_enabled") is True:
            last = r.get("password_last_used")
            d = ctx.days_since(last) if last else ctx.days_since(r.get("user_creation_time"))
            if d is not None and d > 45:
                why.append(f"console password {'last used ' + str(int(d)) + ' days ago' if last else 'never used'}")
        for n in (1, 2):
            if r.get(f"access_key_{n}_active") is True:
                last = r.get(f"access_key_{n}_last_used_date")
                d = ctx.days_since(last) if last else ctx.days_since(r.get(f"access_key_{n}_last_rotated"))
                if d is not None and d > 45:
                    why.append(f"access key {n} {'last used ' + str(int(d)) + ' days ago' if last else 'never used'}")
        if why:
            yield Hit(r["arn"], "credential report: " + "; ".join(why), nodes=[r["arn"]], name=r["user"])


@check("IAM.KEY_NOT_ROTATED")
def key_not_rotated(ctx):
    for r in _user_rows(ctx):
        for n in (1, 2):
            d = ctx.days_since(r.get(f"access_key_{n}_last_rotated"))
            if r.get(f"access_key_{n}_active") is True and d is not None and d > 90:
                yield Hit(r["arn"], f"credential report: access key {n} created {int(d)} days ago",
                          nodes=[r["arn"]], name=r["user"])


@check("IAM.MULTIPLE_ACTIVE_KEYS")
def multiple_keys(ctx):
    for r in _user_rows(ctx):
        if r.get("access_key_1_active") is True and r.get("access_key_2_active") is True:
            yield Hit(r["arn"], "credential report: access_key_1_active and access_key_2_active",
                      nodes=[r["arn"]], name=r["user"])


@check("IAM.NO_PASSWORD_POLICY")
def no_password_policy(ctx):
    rec = ctx.one("IamPasswordPolicy")
    if rec is not None and rec.get("Policy") is None:
        yield Hit("account", "GetAccountPasswordPolicy: NoSuchEntity", name="account password policy")


@check("IAM.WEAK_PASSWORD_POLICY")
def weak_password_policy(ctx):
    pol = (ctx.one("IamPasswordPolicy") or {}).get("Policy")
    if not pol:
        return
    why = []
    if (pol.get("MinimumPasswordLength") or 0) < 14:
        why.append(f"MinimumPasswordLength = {pol.get('MinimumPasswordLength')}")
    if (pol.get("PasswordReusePrevention") or 0) < 24:
        why.append(f"PasswordReusePrevention = {pol.get('PasswordReusePrevention')}")
    if why:
        yield Hit("account", "; ".join(why), name="account password policy")


@check("IAM.USER_DIRECT_POLICY")
def user_direct_policy(ctx):
    for uid, r in ctx.of("IamUser"):
        attached, inline = r.get("AttachedPolicies") or [], list((r.get("InlinePolicies") or {}))
        if attached or inline:
            parts = [p.split("/")[-1] for p in attached] + [f"{n} (inline)" for n in inline]
            yield Hit(uid, "attached to the user: " + ", ".join(parts), nodes=[uid],
                      name=r.get("UserName"))


def _admin_grants(ctx):
    """(policy uid, full_admin, holders) for every attached policy with a GRANTS_ADMIN edge."""
    g = ctx.g
    for pol, tgt, d in g.edges(data=True):
        if tgt != "admin":
            continue
        cand = next((c for c in d["candidates"] if c["rel"] == "GRANTS_ADMIN"), None)
        if not cand:
            continue
        holders = sorted(h for h, _, hd in g.in_edges(pol, data=True)
                         if any(c["rel"] == "HAS_ATTACHED" for c in hd["candidates"]))
        if holders:
            yield pol, bool(cand.get("full_admin")), holders, cand.get("reason", "")


def _short(uid: str) -> str:
    return uid.split("#inline/")[-1] if "#inline/" in uid else uid.split("/")[-1]


@check("IAM.FULL_ADMIN_POLICY")
def full_admin_policy(ctx):
    for pol, full, holders, _ in sorted(_admin_grants(ctx)):
        if full and not pol.startswith("arn:aws:iam::aws:policy/"):
            yield Hit(pol, f"grants Action '*' on Resource '*'; attached to "
                      f"{', '.join(_short(h) for h in holders)}", nodes=[pol, *holders], name=_short(pol))


@check("IAM.ESCALATION_PRIMITIVE")
def escalation_primitive(ctx):
    for pol, full, holders, reason in sorted(_admin_grants(ctx)):
        if not full:
            yield Hit(pol, f"{reason}; attached to {', '.join(_short(h) for h in holders)}",
                      nodes=[pol, *holders], name=_short(pol))


@check("IAM.ROLE_TRUSTS_ANYONE")
def role_trusts_anyone(ctx):
    for uid, r in ctx.of("IamRole"):
        for st, cond in _public_statements(r.get("TrustPolicy")):
            yield Hit(uid, "trust policy: Allow sts:AssumeRole to Principal '*'"
                      + (" (with conditions)" if cond else " (no conditions)"),
                      nodes=[uid], name=r.get("RoleName"),
                      severity=None if not cond else "medium",
                      severity_reason=None if not cond else "conditions may restrict who can assume it; verify them")
            break


@check("IAM.ROLE_CROSS_ACCOUNT_NO_EXTERNAL_ID")
def role_cross_account(ctx):
    for uid, r in ctx.of("IamRole"):
        if "/aws-service-role/" in uid:
            continue
        own = uid.split(":")[4] if uid.count(":") >= 5 else None
        for st in _statements(r.get("TrustPolicy")):
            if st.get("Effect") != "Allow":
                continue
            aws = (st.get("Principal") or {}).get("AWS") if isinstance(st.get("Principal"), dict) else None
            for p in ([aws] if isinstance(aws, str) else aws or []):
                acct = p if re.fullmatch(r"\d{12}", str(p)) else (str(p).split(":")[4] if str(p).count(":") >= 5 else None)
                if acct and own and acct != own and "sts:externalid" not in str(st.get("Condition", "")).lower():
                    yield Hit(uid, f"trust policy allows account {acct} with no sts:ExternalId condition",
                              nodes=[uid], name=r.get("RoleName"))
                    break


# ---- credentials exposed in content ----------------------------------------------------

@check("CRED.KEY_IN_S3")
def key_in_s3(ctx):
    for b, owner, d in sorted(ctx.g.edges(data=True), key=lambda e: (e[0], e[1])):
        for c in d["candidates"]:
            if c["rel"] == "CONTAINS_CREDENTIAL":
                yield Hit(b, c.get("reason") or "access key id found in object content",
                          nodes=[b, owner], name=b.split(":::")[-1])


# ---- S3 ----------------------------------------------------------------------------------

@check("S3.PUBLIC_BUCKET")
def s3_public(ctx):
    for uid, r in ctx.of("S3Bucket"):
        why = bucket_public_reason(r)
        if why:
            yield Hit(uid, why, nodes=[uid], name=r.get("Name"), region=r.get("Region"))


@check("S3.BLOCK_PUBLIC_ACCESS_OFF")
def s3_pab(ctx):
    keys = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    for uid, r in ctx.of("S3Bucket"):
        pab = r.get("PublicAccessBlock") or {}
        off = [k for k in keys if not pab.get(k)]
        if off:
            yield Hit(uid, "PublicAccessBlock off: " + ", ".join(off) if pab else "no PublicAccessBlock configured",
                      nodes=[uid], name=r.get("Name"), region=r.get("Region"))


@check("S3.NO_DEFAULT_ENCRYPTION")
def s3_encryption(ctx):
    for uid, r in ctx.of("S3Bucket"):
        if not r.get("Encryption"):
            yield Hit(uid, "no ServerSideEncryptionConfiguration", nodes=[uid], name=r.get("Name"),
                      region=r.get("Region"))


# ---- EC2 ---------------------------------------------------------------------------------

@check("EC2.IMDSV1_ALLOWED")
def imdsv1(ctx):
    for uid, r in ctx.of("Ec2Instance"):
        if r.get("ImdsHttpTokens") == "optional":
            role = r.get("IamInstanceProfile")
            yield Hit(uid, "MetadataOptions.HttpTokens = optional", nodes=[uid], name=r.get("InstanceId"),
                      region=r.get("Region"),
                      severity="high" if role else None,
                      severity_reason="the instance carries an IAM role whose credentials IMDSv1 exposes" if role else None)


@check("EC2.PUBLIC_IP")
def public_ip(ctx):
    for uid, r in ctx.of("Ec2Instance"):
        if r.get("PublicIpAddress"):
            yield Hit(uid, f"PublicIpAddress = {r['PublicIpAddress']} (state {r.get('State')})",
                      nodes=[uid], name=r.get("InstanceId"), region=r.get("Region"))


@check("EC2.EBS_UNENCRYPTED")
def ebs_unencrypted(ctx):
    for uid, r in ctx.of("EbsVolume"):
        if r.get("Encrypted") is False:
            att = ", ".join(r.get("AttachedTo") or []) or "unattached"
            yield Hit(uid, f"Encrypted = false ({r.get('Size')} GiB {r.get('VolumeType')}, {att})",
                      nodes=[uid, *(r.get("AttachedTo") or [])], name=r.get("VolumeId"), region=r.get("Region"))


@check("EC2.EBS_DEFAULT_ENCRYPTION_OFF")
def ebs_default(ctx):
    off = sorted(r["Region"] for _, r in ctx.of("EbsDefaults") if r.get("EncryptionByDefault") is False)
    total = len(ctx.of("EbsDefaults"))
    if off:
        yield Hit("account", f"EbsEncryptionByDefault = false in {len(off)} of {total} regions: {', '.join(off)}",
                  name="EBS encryption by default")


# ---- VPC ---------------------------------------------------------------------------------

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
DB_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 1521: "Oracle",
            27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch"}


def _open_rules(rules):
    for rule in rules or []:
        cidrs = [x.get("CidrIp") for x in rule.get("IpRanges", [])] + \
                [x.get("CidrIpv6") for x in rule.get("Ipv6Ranges", [])]
        open_to = sorted(c for c in cidrs if c in OPEN_CIDRS)
        if open_to:
            yield rule, open_to


def _covers(rule, port) -> bool:
    if str(rule.get("IpProtocol")) == "-1":
        return True
    if str(rule.get("IpProtocol")) not in ("tcp", "6"):
        return False
    lo, hi = rule.get("FromPort"), rule.get("ToPort")
    return lo is not None and hi is not None and lo <= port <= hi


def _sg_instances(ctx, sg) -> list[str]:
    return sorted(uid for uid, r in ctx.of("Ec2Instance") if sg in (r.get("SecurityGroups") or []))


def _sg_usage(ctx, sg) -> str:
    """Which instances use the group, with state: an open port on a stopped instance is
    not reachable today but is the moment someone starts it."""
    states = {uid: r.get("State") for uid, r in ctx.of("Ec2Instance")}
    used = _sg_instances(ctx, sg)
    if not used:
        return " (not attached to any instance)"
    return " (used by " + ", ".join(f"{u} [{states.get(u)}]" for u in used) + ")"


@check("VPC.SG_ALL_TRAFFIC_OPEN")
def sg_all_open(ctx):
    for uid, r in ctx.of("SecurityGroup"):
        for rule, cidrs in _open_rules(r.get("IngressRules")):
            if str(rule.get("IpProtocol")) == "-1":
                yield Hit(uid, f"ingress: all protocols, all ports from {', '.join(cidrs)}"
                          + _sg_usage(ctx, uid),
                          nodes=[uid, *_sg_instances(ctx, uid)], name=f"{r.get('GroupName')} ({uid})",
                          region=r.get("Region"))
                break


def _sg_port_check(ctx, ports):
    for uid, r in ctx.of("SecurityGroup"):
        rules = list(_open_rules(r.get("IngressRules")))
        if any(str(rule.get("IpProtocol")) == "-1" for rule, _ in rules):
            continue  # reported once, as SG_ALL_TRAFFIC_OPEN
        hits = sorted({f"{name} ({p})" for rule, _ in rules for p, name in ports.items() if _covers(rule, p)})
        if hits:
            yield Hit(uid, f"ingress from 0.0.0.0/0 or ::/0 to {', '.join(hits)}" + _sg_usage(ctx, uid),
                      nodes=[uid, *_sg_instances(ctx, uid)], name=f"{r.get('GroupName')} ({uid})",
                      region=r.get("Region"))


@check("VPC.SG_ADMIN_PORTS_OPEN")
def sg_admin(ctx):
    yield from _sg_port_check(ctx, ADMIN_PORTS)


@check("VPC.SG_DATABASE_PORTS_OPEN")
def sg_db(ctx):
    yield from _sg_port_check(ctx, DB_PORTS)


@check("VPC.DEFAULT_SG_NOT_RESTRICTED")
def default_sg(ctx):
    for uid, r in ctx.of("SecurityGroup"):
        if r.get("GroupName") == "default" and (r.get("IngressRules") or r.get("EgressRules")):
            yield Hit(uid, f"default group has {len(r.get('IngressRules') or [])} ingress / "
                      f"{len(r.get('EgressRules') or [])} egress rules",
                      nodes=[uid, *_sg_instances(ctx, uid)], name=f"default ({r.get('VpcId')})",
                      region=r.get("Region"))


@check("VPC.NACL_ADMIN_PORTS_OPEN")
def nacl_admin(ctx):
    for uid, r in ctx.of("NetworkAcl"):
        for e in sorted(r.get("Entries") or [], key=lambda e: e.get("RuleNumber", 0)):
            if e.get("Egress") or e.get("RuleAction") != "allow":
                continue
            if e.get("CidrBlock") not in OPEN_CIDRS and e.get("Ipv6CidrBlock") not in OPEN_CIDRS:
                continue
            proto = str(e.get("Protocol"))
            pr = e.get("PortRange") or {}
            covered = [n for p, n in ADMIN_PORTS.items()
                       if proto == "-1" or (proto == "6" and pr.get("From", 0) <= p <= pr.get("To", -1))]
            if covered:
                yield Hit(uid, f"rule {e.get('RuleNumber')} allows {', '.join(covered)} from "
                          f"{e.get('CidrBlock') or e.get('Ipv6CidrBlock')}", nodes=[uid],
                          name=uid, region=r.get("Region"))
                break


# ---- Lambda --------------------------------------------------------------------------------

SECRET_NAME = re.compile(r"(secret|passw(or)?d|pwd|token|api[_-]?key|private[_-]?key|access[_-]?key|credential)", re.I)
KEY_VALUE = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")
# Runtimes past AWS Lambda's deprecation date (as of Oct 2026). Update when AWS deprecates more.
DEPRECATED_RUNTIMES = {
    "python2.7", "python3.6", "python3.7", "python3.8", "python3.9",
    "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10", "nodejs10.x", "nodejs12.x",
    "nodejs14.x", "nodejs16.x", "nodejs18.x",
    "java8", "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1",
    "dotnet5.0", "dotnet6", "ruby2.5", "ruby2.7", "go1.x", "provided",
}


@check("LAMBDA.URL_NO_AUTH")
def lambda_url(ctx):
    for uid, r in ctx.of("LambdaFunction"):
        if str(r.get("FunctionUrlAuthType") or "").upper() == "NONE":
            yield Hit(uid, "FunctionUrlAuthType = NONE", nodes=[uid], name=r.get("FunctionName"),
                      region=r.get("Region"))


@check("LAMBDA.SECRET_IN_ENV")
def lambda_secret_env(ctx):
    for uid, r in ctx.of("LambdaFunction"):
        env = r.get("EnvVars") or {}
        # Names only in the evidence: a finding must never repeat the secret it found.
        names = sorted(k for k, v in env.items() if SECRET_NAME.search(k) or KEY_VALUE.search(str(v)))
        if names:
            yield Hit(uid, "environment variables that look like secrets: " + ", ".join(names),
                      nodes=[uid], name=r.get("FunctionName"), region=r.get("Region"))


@check("LAMBDA.DEPRECATED_RUNTIME")
def lambda_runtime(ctx):
    for uid, r in ctx.of("LambdaFunction"):
        if r.get("Runtime") in DEPRECATED_RUNTIMES:
            yield Hit(uid, f"Runtime = {r['Runtime']}", nodes=[uid], name=r.get("FunctionName"),
                      region=r.get("Region"))


# ---- RDS -----------------------------------------------------------------------------------

@check("RDS.PUBLIC")
def rds_public(ctx):
    for uid, r in ctx.of("RdsInstance"):
        if r.get("PubliclyAccessible") is True:
            yield Hit(uid, "PubliclyAccessible = true", nodes=[uid], name=r.get("DBInstanceIdentifier"),
                      region=r.get("Region"))


@check("RDS.UNENCRYPTED")
def rds_unencrypted(ctx):
    for uid, r in ctx.of("RdsInstance"):
        if r.get("StorageEncrypted") is False:
            yield Hit(uid, "StorageEncrypted = false", nodes=[uid], name=r.get("DBInstanceIdentifier"),
                      region=r.get("Region"))


@check("RDS.NO_DELETION_PROTECTION")
def rds_deletion(ctx):
    for uid, r in ctx.of("RdsInstance"):
        if r.get("DeletionProtection") is False:
            yield Hit(uid, "DeletionProtection = false", nodes=[uid], name=r.get("DBInstanceIdentifier"),
                      region=r.get("Region"))


# ---- Secrets Manager / KMS -----------------------------------------------------------------

@check("SECRETS.PUBLIC_POLICY")
def secret_public(ctx):
    for uid, r in ctx.of("SecretsManagerSecret"):
        for st, cond in _public_statements(r.get("ResourcePolicy")):
            yield Hit(uid, "resource policy: Allow to Principal '*'" + (" (with conditions)" if cond else ""),
                      nodes=[uid], name=r.get("Name"), region=r.get("Region"),
                      severity="medium" if cond else None,
                      severity_reason="conditions may restrict access; verify them" if cond else None)
            break


@check("KMS.PUBLIC_POLICY")
def kms_public(ctx):
    for uid, r in ctx.of("KmsKey"):
        for st, cond in _public_statements(r.get("Policy")):
            yield Hit(uid, "key policy: Allow to Principal '*'" + (" (with conditions)" if cond else ""),
                      nodes=[uid], name=r.get("KeyId"), region=r.get("Region"),
                      severity="medium" if cond else None,
                      severity_reason="conditions may restrict access; verify them" if cond else None)
            break


@check("KMS.NO_ROTATION")
def kms_rotation(ctx):
    for uid, r in ctx.of("KmsKey"):
        if (r.get("KeyRotationEnabled") is False and r.get("KeyManager") == "CUSTOMER"
                and r.get("KeyState") == "Enabled" and r.get("KeySpec") in (None, "SYMMETRIC_DEFAULT")):
            yield Hit(uid, "KeyRotationEnabled = false", nodes=[uid], name=r.get("KeyId"), region=r.get("Region"))


# ---- CloudTrail ----------------------------------------------------------------------------

@check("CLOUDTRAIL.NOT_ENABLED")
def cloudtrail_enabled(ctx):
    if ctx.one("CloudTrailStatus") is None:
        return  # could not read CloudTrail: unknown, not a finding
    trails = [r for _, r in ctx.of("CloudTrailTrail")]
    if not any(t.get("IsMultiRegionTrail") and t.get("IsLogging") is not False for t in trails):
        yield Hit("account", "no trails at all" if not trails else
                  f"{len(trails)} trail(s), none both multi-region and logging", name="CloudTrail")


@check("CLOUDTRAIL.NO_LOG_VALIDATION")
def cloudtrail_validation(ctx):
    for uid, r in ctx.of("CloudTrailTrail"):
        if r.get("LogFileValidationEnabled") is False:
            yield Hit(uid, "LogFileValidationEnabled = false", nodes=[uid], name=r.get("Name"),
                      region=r.get("HomeRegion"))


@check("CLOUDTRAIL.NOT_KMS_ENCRYPTED")
def cloudtrail_kms(ctx):
    for uid, r in ctx.of("CloudTrailTrail"):
        if not r.get("KmsKeyId"):
            yield Hit(uid, "no KmsKeyId on the trail", nodes=[uid], name=r.get("Name"),
                      region=r.get("HomeRegion"))
