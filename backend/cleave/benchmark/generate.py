"""Benchmark scenario generator (Phase 10) — the real contribution.

Generates a synthetic AWS account with a KNOWN ground truth: mostly-benign resources with a
handful of planted multi-hop attack paths, and a manifest saying exactly what was planted.
With the answer key in hand, recall and precision become exact measurements, not guesses —
which is the whole point of a benchmark and why a seeded synthetic account beats a real one
for evaluation (a real account's full path set is never known).

Discipline that makes precision meaningful: **the benign noise forms no real path.** Benign
identities get scoped, non-escalating permissions; benign buckets are private; benign
security groups open nothing to the internet; benign roles are service-linked or trusted by
no reachable principal. So every real path Cleave finds is either a planted one (a true
positive) or a generator bug — never ambiguous.

`generate(seed, n_benign, n_paths)` returns {records, cred_findings, manifest}. The records
are collector-shaped, so `graph_from_records` runs Cleave on the account with no deployment.
`to_terraform` emits the same account as .tf for the live multi-tool comparison (Phase 10
step 2). Free primitives only — IAM, S3, security groups, Lambda (handbook cost rule).
"""
from __future__ import annotations
import json
import random

ACCOUNT = "100000000000"
A = f"arn:aws:iam::{ACCOUNT}:"
ADMIN_MANAGED = {
    "_type": "IamPolicy", "_id": "arn:aws:iam::aws:policy/AdministratorAccess",
    "PolicyName": "AdministratorAccess", "ManagedBy": "AWS",
    "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
}

# Admin-equivalent primitives used to plant GRANTS_ADMIN paths (a subset of the catalogue).
PRIMITIVES = ["iam:CreatePolicyVersion", "iam:PutUserPolicy", "iam:AttachUserPolicy"]
# (actions, resource). Scoped so benign identities reach no sink: S3 reads are confined to a
# benign bucket prefix (never the planted public buckets), the rest are describe/read on
# services with no planted sink. This is what keeps the benign noise genuinely path-free.
BENIGN_ACTIONS = [
    (["s3:GetObject", "s3:ListBucket"], "arn:aws:s3:::app-data-*/*"),
    (["ec2:Describe*"], "*"), (["cloudwatch:GetMetricData"], "*"),
    (["logs:FilterLogEvents"], "*"), (["sqs:ReceiveMessage"], "*"),
    (["cloudformation:DescribeStacks"], "*"),
]


class _Gen:
    def __init__(self, seed: int):
        self.r = random.Random(seed)
        self.records: list[dict] = [ADMIN_MANAGED]
        self.creds: list[dict] = []
        self.manifest: list[dict] = []
        self._n = 0

    def _id(self, prefix: str) -> str:
        self._n += 1
        return f"{prefix}-{self._n:04d}"

    # ---- benign, path-free resources ----
    def benign_user(self):
        name = self._id("svc-user")
        acts, res = self.r.choice(BENIGN_ACTIONS)
        self.records.append({
            "_type": "IamUser", "_id": f"{A}user/{name}", "UserName": name,
            "AttachedPolicies": [], "Groups": [], "AccessKeys": [],
            "InlinePolicies": {"p": {"Statement": [
                {"Effect": "Allow", "Action": acts, "Resource": res}]}}})

    def benign_role(self):
        name = self._id("svc-role")
        acts, res = self.r.choice(BENIGN_ACTIONS)
        # service-linked-ish: trusted only by a service, no workload runs as it -> not a source
        self.records.append({
            "_type": "IamRole", "_id": f"{A}role/{name}", "RoleName": name,
            "AttachedPolicies": [], "InlinePolicies": {"p": {"Statement": [
                {"Effect": "Allow", "Action": acts, "Resource": res}]}},
            "TrustPolicy": {"Statement": [{"Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"}, "Action": "sts:AssumeRole"}]}})

    def benign_bucket(self):
        name = self._id("data-bucket")
        self.records.append({
            "_type": "S3Bucket", "_id": f"arn:aws:s3:::{name}", "Name": name,
            "Policy": None, "Acl": [], "PublicAccessBlock": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True}})

    def benign_sg(self):
        sid = self._id("sg")
        # open only to the VPC, never 0.0.0.0/0
        self.records.append({
            "_type": "SecurityGroup", "_id": sid, "GroupName": sid,
            "IngressRules": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                             "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]})

    def benign_policy(self):
        # an unattached, scoped policy — touches IAM-shaped data but grants nothing dangerous
        name = self._id("scoped-pol")
        self.records.append({
            "_type": "IamPolicy", "_id": f"{A}policy/{name}", "PolicyName": name,
            "ManagedBy": "Customer", "Document": {"Statement": [
                {"Effect": "Allow", "Action": ["iam:GetRole", "iam:ListRoles"], "Resource": "*"}]}})

    BENIGN = [benign_user, benign_role, benign_bucket, benign_sg, benign_policy]

    def _record_path(self, template: str, source: str, rels: list[str], sink="admin"):
        self.manifest.append({"id": f"path-{len(self.manifest)+1:02d}", "template": template,
                              "source": source, "sink": sink, "hops": rels})

    # ---- planted attack paths (each adds a real, intended route) ----
    def plant_privesc_primitive(self):
        prim = self.r.choice(PRIMITIVES)
        u = self._id("deploy")
        uid = f"{A}user/{u}"
        attached: list[str] = []
        if prim == "iam:CreatePolicyVersion":
            # CreatePolicyVersion/SetDefaultPolicyVersion escalate the holder only if they
            # have an attached customer-managed policy to rewrite into admin (an inline-only
            # holder cannot; AWS-managed is immutable). Give deploy one so the planted path
            # is a genuine escalation under the precise model -- the grant on "*" covers it.
            pol = self._id("deploy-scoped")
            parn = f"{A}policy/{pol}"
            self.records.append({
                "_type": "IamPolicy", "_id": parn, "PolicyName": pol, "ManagedBy": "Customer",
                "Document": {"Statement": [
                    {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]}})
            attached = [parn]
        self.records.append({
            "_type": "IamUser", "_id": uid, "UserName": u, "AttachedPolicies": attached,
            "Groups": [], "AccessKeys": [], "InlinePolicies": {"p": {"Statement": [
                {"Effect": "Allow", "Action": [prim, "s3:GetObject"], "Resource": "*"}]}}})
        self._record_path("privesc_primitive", uid, ["HAS_ATTACHED", "GRANTS_ADMIN"])

    def plant_passrole_launch(self):
        u, role = self._id("builder"), self._id("ci-admin-role")
        uid, rid = f"{A}user/{u}", f"{A}role/{role}"
        self.records.append({
            "_type": "IamRole", "_id": rid, "RoleName": role,
            "AttachedPolicies": [ADMIN_MANAGED["_id"]], "InlinePolicies": {},
            "TrustPolicy": {"Statement": [{"Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}})
        self.records.append({
            "_type": "IamUser", "_id": uid, "UserName": u, "AttachedPolicies": [],
            "Groups": [], "AccessKeys": [], "InlinePolicies": {"p": {"Statement": [
                {"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction"],
                 "Resource": "*"}]}}})
        self._record_path("passrole_launch", uid, ["CAN_LAUNCH_AS", "HAS_ATTACHED", "GRANTS_ADMIN"])

    def plant_public_bucket_cred(self):
        b, victim = self._id("public-dump"), self._id("ci-deployer")
        bid, vid = f"arn:aws:s3:::{b}", f"{A}user/{victim}"
        self.records.append({
            "_type": "S3Bucket", "_id": bid, "Name": b, "PublicAccessBlock": None, "Acl": [],
            "Policy": {"Statement": [{"Effect": "Allow", "Principal": "*",
                "Action": "s3:GetObject", "Resource": f"{bid}/*"}]}})
        self.records.append({
            "_type": "IamUser", "_id": vid, "UserName": victim, "AttachedPolicies": [],
            "Groups": [], "AccessKeys": [{"AccessKeyId": f"AKIA{self._n:016d}", "Status": "Active"}],
            "InlinePolicies": {"p": {"Statement": [
                {"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"}]}}})
        self.creds.append({"bucket_id": bid, "object_key": "ci/.env",
                           "key_id": f"AKIA{self._n:016d}", "key_type": "AKIA", "owner_arn": vid})
        self._record_path("public_bucket_cred", bid,
                          ["CONTAINS_CREDENTIAL", "HAS_ATTACHED", "GRANTS_ADMIN"])

    def plant_assume_chain(self):
        u, role = self._id("eng"), self._id("break-glass")
        uid, rid = f"{A}user/{u}", f"{A}role/{role}"
        self.records.append({
            "_type": "IamRole", "_id": rid, "RoleName": role,
            "AttachedPolicies": [ADMIN_MANAGED["_id"]], "InlinePolicies": {},
            "TrustPolicy": {"Statement": [{"Effect": "Allow",
                "Principal": {"AWS": f"{A}root"}, "Action": "sts:AssumeRole"}]}})
        self.records.append({
            "_type": "IamUser", "_id": uid, "UserName": u, "AttachedPolicies": [],
            "Groups": [], "AccessKeys": [], "InlinePolicies": {"p": {"Statement": [
                {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": rid}]}}})
        self._record_path("assume_chain", uid, ["CAN_ASSUME", "HAS_ATTACHED", "GRANTS_ADMIN"])

    def plant_github_oidc(self):
        role = self._id("gha-deploy")
        rid = f"{A}role/{role}"
        self.records.append({
            "_type": "IamRole", "_id": rid, "RoleName": role,
            "AttachedPolicies": [ADMIN_MANAGED["_id"]], "InlinePolicies": {},
            "TrustPolicy": {"Statement": [{"Effect": "Allow",
                "Principal": {"Federated": f"{A}oidc-provider/token.actions.githubusercontent.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {"StringLike": {
                    "token.actions.githubusercontent.com:sub": "repo:acme/infra:*"}}}]}})
        self._record_path("github_oidc", rid, ["HAS_ATTACHED", "GRANTS_ADMIN"])

    PLANTS = [plant_privesc_primitive, plant_passrole_launch, plant_public_bucket_cred,
              plant_assume_chain, plant_github_oidc]


def generate(seed: int = 1, n_benign: int = 160, n_paths: int = 5) -> dict:
    g = _Gen(seed)
    before = {r["_id"] for r in g.records}          # ADMIN_MANAGED is pre-seeded, not planted
    plants = [g.PLANTS[i % len(g.PLANTS)] for i in range(n_paths)]
    for p in plants:
        p(g)
    # every resource created during the plant phase is "planted"; a correct benchmark has no
    # path that avoids all of these (benign noise is path-free).
    planted = {r["_id"] for r in g.records} - before
    for _ in range(n_benign):
        g.r.choice(g.BENIGN)(g)
    return {"account": ACCOUNT, "seed": seed, "records": g.records,
            "cred_findings": g.creds, "manifest": g.manifest,
            "planted_resources": planted}


def _tfid(uid: str) -> str:
    base = uid.split("/")[-1].split(":")[-1]
    out = "".join(c if (c.isalnum() or c == "_") else "_" for c in base).strip("_")
    return ("r_" + out) if (not out or out[0].isdigit()) else out


def _heredoc(doc: dict, indent: str = "  ") -> str:
    # AWS requires a policy Version; the engine does not, so inject it only at emit time.
    if "Version" not in doc:
        doc = {"Version": "2012-10-17", **doc}
    body = json.dumps(doc, indent=2)
    body = "\n".join(indent + ln for ln in body.splitlines())
    return f"<<-POLICY\n{body}\n{indent}POLICY"


def to_terraform(scn: dict) -> dict[str, str]:
    """Emit the synthetic account as deployable Terraform, so the other tools can scan a live
    account (Phase 10 step 2). Free primitives only. Public buckets get the ownership/PAB
    settings a public policy needs; a planted credential becomes a real (throwaway) access key
    whose id is written into the bucket object, so Cleave's live credscan reconstructs that
    path. Tear the account down the same session (handbook Rule 2).
    """
    recs = {r["_id"]: r for r in scn["records"]}
    blocks: list[str] = []

    def policy_arn_ref(arn: str) -> str:
        # an AWS-managed policy is referenced by its ARN; a generated customer policy by its resource
        if arn.startswith("arn:aws:iam::aws:policy/"):
            return f'"{arn}"'
        r = recs.get(arn)
        return f"aws_iam_policy.{_tfid(arn)}.arn" if r else f'"{arn}"'

    for r in scn["records"]:
        t, rid = r["_type"], _tfid(r["_id"])
        if t == "IamPolicy" and r.get("ManagedBy") != "AWS" and r.get("Document"):
            blocks.append(f'resource "aws_iam_policy" "{rid}" {{\n  name   = "{r["PolicyName"]}"\n'
                          f'  policy = {_heredoc(r["Document"])}\n}}')
        elif t in ("IamUser", "IamRole", "IamGroup"):
            kind = {"IamUser": "user", "IamRole": "role", "IamGroup": "group"}[t]
            name = r.get("UserName") or r.get("RoleName") or r.get("GroupName")
            head = [f'resource "aws_iam_{kind}" "{rid}" {{', f'  name = "{name}"']
            if t == "IamRole" and r.get("TrustPolicy"):
                head.append(f'  assume_role_policy = {_heredoc(r["TrustPolicy"], "  ")}')
            head.append("}")
            blocks.append("\n".join(head))
            for pname, doc in (r.get("InlinePolicies") or {}).items():
                if doc:
                    blocks.append(
                        f'resource "aws_iam_{kind}_policy" "{rid}_{_tfid(pname)}" {{\n'
                        f'  name   = "{pname}"\n  {kind}   = aws_iam_{kind}.{rid}.name\n'
                        f'  policy = {_heredoc(doc)}\n}}')
            for parn in r.get("AttachedPolicies") or []:
                blocks.append(
                    f'resource "aws_iam_{kind}_policy_attachment" "{rid}_{_tfid(parn)}" {{\n'
                    f'  {kind}       = aws_iam_{kind}.{rid}.name\n'
                    f'  policy_arn = {policy_arn_ref(parn)}\n}}')
        elif t == "S3Bucket":
            name = r["Name"]
            blocks.append(f'resource "aws_s3_bucket" "{rid}" {{\n  bucket = "{name}"\n'
                          f'  force_destroy = true\n}}')
            public = r.get("Policy") and not r.get("PublicAccessBlock")
            pab = r.get("PublicAccessBlock") or {}
            block = "true" if (pab.get("BlockPublicPolicy") is not False and not public) else "false"
            blocks.append(
                f'resource "aws_s3_bucket_public_access_block" "{rid}_pab" {{\n'
                f'  bucket                  = aws_s3_bucket.{rid}.id\n'
                f'  block_public_acls       = {str(not public).lower()}\n'
                f'  ignore_public_acls      = {str(not public).lower()}\n'
                f'  block_public_policy     = {block}\n'
                f'  restrict_public_buckets = {str(not public).lower()}\n}}')
            if r.get("Policy"):
                blocks.append(
                    f'resource "aws_s3_bucket_policy" "{rid}_pol" {{\n'
                    f'  bucket = aws_s3_bucket.{rid}.id\n  policy = {_heredoc(r["Policy"])}\n'
                    f'  depends_on = [aws_s3_bucket_public_access_block.{rid}_pab]\n}}')

    # planted credentials: a real (throwaway) access key for the owner, its id written into
    # the bucket object, so a live credscan maps the key -> owner and reconstructs the path.
    for i, f in enumerate(scn.get("cred_findings") or []):
        owner = recs.get(f["owner_arn"])
        bucket = recs.get(f["bucket_id"])
        if not (owner and bucket):
            continue
        ok, bk = _tfid(owner["_id"]), _tfid(bucket["_id"])
        blocks.append(f'resource "aws_iam_access_key" "cred_{i}" {{\n'
                      f'  user = aws_iam_user.{ok}.name\n}}')
        blocks.append(
            f'resource "aws_s3_object" "cred_{i}" {{\n  bucket  = aws_s3_bucket.{bk}.id\n'
            f'  key     = "{f.get("object_key", "secret.env")}"\n'
            f'  content = "aws_access_key_id=${{aws_iam_access_key.cred_{i}.id}}\\n'
            f'aws_secret_access_key=${{aws_iam_access_key.cred_{i}.secret}}\\n"\n}}')

    providers = ('terraform {\n  required_providers {\n'
                 '    aws = { source = "hashicorp/aws", version = "~> 5.0" }\n  }\n}\n\n'
                 'provider "aws" {\n  region = "us-east-1"\n}\n')
    return {"providers.tf": providers,
            "main.tf": "# Generated by cleave.benchmark — synthetic benchmark account.\n"
                       "# Free primitives only; tear down the same session.\n\n"
                       + "\n\n".join(blocks) + "\n"}


def write(out_dir, seed: int = 1, n_benign: int = 160, n_paths: int = 5) -> dict:
    import pathlib
    out = pathlib.Path(out_dir)
    (out / "raw").mkdir(parents=True, exist_ok=True)
    scn = generate(seed, n_benign, n_paths)
    (out / "raw" / "all.json").write_text(json.dumps(scn["records"]), encoding="utf-8")
    (out / "raw" / "_credentials.json").write_text(json.dumps(scn["cred_findings"]), encoding="utf-8")
    (out / "manifest.json").write_text(json.dumps(
        {"account": scn["account"], "seed": seed, "resources": len(scn["records"]),
         "planted_paths": scn["manifest"]}, indent=2), encoding="utf-8")
    tf = out / "terraform"
    tf.mkdir(parents=True, exist_ok=True)
    for fname, content in to_terraform(scn).items():
        (tf / fname).write_text(content, encoding="utf-8")
    return scn
