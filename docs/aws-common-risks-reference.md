# AWS Common Risks — reference for Cleave coverage

Real-world AWS mistakes, gathered from security audits and dev/cost war-stories, mapped to
how Cleave models them. Two buckets: **security** (what Cleave detects as attack-path
edges) and **cost hygiene** (what our Rule 2 teardown keeps clean — NOT a Cleave feature).

---

## A. Security misconfigurations → Cleave coverage

| Real-world mistake | How Cleave models it | Node / Edge | Phase |
|---|---|---|---|
| **IAM privilege escalation** — policy rollback, `iam:CreatePolicyVersion`, `iam:PassRole`, `iam:CreateAccessKey`, `AttachUserPolicy`/`PutUserPolicy`, AssumeRole chains, Lambda-based | evaluate policies; dangerous perms in the **admin-equivalent catalogue** | `CAN_WRITE`, `CAN_PASS_ROLE`, `CAN_LAUNCH_AS`, `CAN_ASSUME`, `GRANTS_ADMIN` | 3/4/7 |
| **Over-permissive default service roles** (SageMaker/Glue/EMR create broad roles) | role policy evaluated → admin-equivalent | `HAS_ATTACHED` → `GRANTS_ADMIN` | 3/7 |
| **Public S3 buckets** (~31% of buckets public) | bucket policy + ACL + public-access-block collected → public bucket = entry point | `S3Bucket` as **source**, `CAN_REACH` | 3/4 |
| **Security groups open to `0.0.0.0/0`** on 22/3389/5432/3306 (~41% of prod SGs have one) | ingress rules collected → internet-reachable | `SecurityGroup` ingress → `CAN_REACH` from `Internet` | 3/4 |
| **Publicly accessible RDS** | `PubliclyAccessible` flag collected | `RdsInstance` as source/sink | 3/4 |
| **IMDSv1 enabled** (`HttpTokens=optional`) → SSRF steals role creds | `ImdsHttpTokens` collected on instances | strengthens `HAS_INSTANCE_PROFILE` → credential-theft path | 3 |
| **Hardcoded secrets** in Lambda env vars / S3 objects / `.env` files | env vars collected; S3 object credential scan | `CONTAINS_CREDENTIAL` → principal | 3 |
| **Exposed secrets unlocking bigger access** (public bucket holding a creds file → admin role) | credential-in-content links a resource to a principal | `CONTAINS_CREDENTIAL`, then normal path search | 3/4 |

**The admin-equivalent permission catalogue (Phase 4/7) must include at least:**
`iam:*` on `*`, `AdministratorAccess`, `iam:CreatePolicyVersion`,
`iam:SetDefaultPolicyVersion`, `iam:PassRole`, `iam:CreateAccessKey`,
`iam:AttachUserPolicy`, `iam:AttachRolePolicy`, `iam:PutUserPolicy`, `iam:PutRolePolicy`,
`iam:CreateLoginProfile`, `iam:UpdateLoginProfile`, `iam:UpdateAssumeRolePolicy`,
`iam:AddUserToGroup`, `sts:AssumeRole` (into admin), `lambda:CreateFunction`+`iam:PassRole`,
`ec2:RunInstances`+`iam:PassRole`, `glue`/`sagemaker`/`cloudformation` create+PassRole.

**Deliberately OUT of scope (flat findings, not attack paths):** encryption-at-rest missing
(S3/EBS/RDS), missing MFA, no CloudTrail. These are compliance checkboxes with no
*reachability* story, so they belong (if anywhere) in the conventional Findings list
(Phase 6), never as graph edges. Cleave's thesis is *reachability*, not compliance.

---

## B. Cost hygiene → Rule 2 teardown (NOT a Cleave feature)

The #1 sources of surprise AWS bills, and where our teardown sweep already checks:

| Cost leftover | Rough cost if forgotten | Our sweep checks it? |
|---|---|---|
| **Unattached EBS volumes** (cited as ~30% of overspend) | $0.08/GB-mo | ✅ describe-volumes |
| **Running EC2 left on** (test/dev) | ~$8/mo (t3.micro) → much more for bigger | ✅ describe-instances all regions |
| **RDS left running** | ~$12/mo+ | ✅ describe-db-instances |
| **Unused Elastic IPs** | ~$3.6/mo each | ✅ describe-addresses |
| **NAT Gateways** | ~$32/mo + data | ✅ describe-nat-gateways |
| **Idle load balancers** | ~$16/mo | ✅ describe-load-balancers |
| **Old snapshots / AMIs** | small but accumulates | ✅ describe-snapshots / images |
| **Oversized instances** | varies | ⚠️ judgment, not swept |
| **Cross-region / internet data transfer** | sneaky, usage-based | ⚠️ can't be swept — watch Cost Explorer |

**Scope note:** detecting cost waste is a **NON-GOAL** for Cleave (the thesis is attack
paths). This table is *our operational hygiene* — the session-end teardown sweep — not a
product feature. If a "cost leftovers" side-report is ever wanted, it's a separate small
tool, kept out of Cleave's core so depth isn't diluted.

---

## Sources
- IAM privesc paths & dangerous permissions: RedFox Security, Sysdig, cybersecpentesting.com, Rhino Security (CreatePolicyVersion/PassRole/CreateAccessKey/AssumeRole/Lambda)
- Gartner: ~75% of cloud security failures stem from IAM misconfiguration
- S3 public exposure (~31%), SG `0.0.0.0/0` (~41% of prod SGs): Qualys, industry audits
- IMDSv1/SSRF credential theft: Wiz, Tenable, Latacora, AWS Security Blog
- Cost leftovers (unattached EBS ~30% overspend, idle EC2/RDS/EIP): DEV Community cost war-stories, AWS Cost Optimization guidance
