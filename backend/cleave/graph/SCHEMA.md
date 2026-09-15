# Cleave Graph Schema (v1 — draft for iteration)

The graph is the heart of Cleave. Nodes are resources and identities; **edges are things
an attacker can traverse.** This document is the contract: every node and edge type, what
data creates it, and — for edges — *what an attacker does by using it*. If an edge can't be
justified by an attacker action, it does not exist.

> **Golden rule.** Every edge carries `evidence` pointing at a real config element. At
> review, the deep question is *"why does this edge exist?"* — `evidence` is the answer.

---

## Edge property contract (every edge has these)

| Property | Meaning | Example |
|---|---|---|
| `reason` | one-line human explanation | "user has AdministratorAccess attached" |
| `evidence` | pointer to the config element that proves it | `iam.json#IamUser/cleave-dev/AttachedPolicies[0]` |
| `confidence` | `Certain` or `Possible` (Possible = IAM evaluator couldn't decide statically) | `Certain` |
| `discovered_by` | which collector/analyzer created it | `graph.loader` / `iam.evaluator.v1` / `reachability` |

---

## The Phase 2 / Phase 3 split (scope discipline)

- **Phase 2 (this phase) — STRUCTURAL edges.** Read directly from config, no judgment
  needed: attachments, group membership, instance-profile links, trust-policy principals,
  network topology. `confidence = Certain` by construction.
- **Phase 3 — EVALUATED edges.** Require the IAM policy evaluator or network-reachability
  logic: `CAN_READ/WRITE`, `CAN_PASS_ROLE`, `CAN_LAUNCH_AS`, `CAN_REACH`,
  `CONTAINS_CREDENTIAL`, `GRANTS_ADMIN`.

Phase 2 defines *all* types in the schema but the loader only populates the structural
ones. Keeping this line clean is what lets us swap in `terraform plan` later (Phase 9).

---

## Node types

Each node has `_id` (globally unique, usually the ARN), a `label` (the type), and the
normalised properties from the Phase 1 collector that produced it.

| Label | Source (data/raw) | Key properties | Notes |
|---|---|---|---|
| `Internet` | synthetic | — | single node; origin of all external reach |
| `IamUser` | iam.json | Arn, UserName, AccessKeys[] (with LastUsed) | a human/programmatic principal |
| `IamRole` | iam.json | Arn, RoleName, TrustPolicy | assumable principal |
| `IamGroup` | iam.json | Arn, GroupName | policy container for users |
| `IamPolicy` | iam.json | Arn, Document, DefaultVersionId | managed or inline; the actual permissions |
| `IamInstanceProfile` | iam.json | Arn, Roles[] | the instance→role bridge (Phase 0 scenario 2) |
| `S3Bucket` | s3.json | Name, Policy, PublicAccessBlock, Acl, Encryption | |
| `Ec2Instance` | ec2.json | InstanceId, PublicIpAddress, ImdsHttpTokens, SubnetId | IMDSv1 (`HttpTokens=optional`) is a real weakness |
| `SecurityGroup` | vpc.json | GroupId, IngressRules, EgressRules | the firewall |
| `Subnet` | vpc.json | SubnetId, VpcId, MapPublicIpOnLaunch | |
| `Vpc` | vpc.json | VpcId, CidrBlock | |
| `RouteTable` | vpc.json | Routes[], Associations[] | routes to IGW = public path |
| `NetworkAcl` | vpc.json | Entries[] | subnet-level firewall |
| `InternetGateway` | vpc.json | AttachedVpcs[] | the door to the internet |
| `LambdaFunction` | lambda.json | Arn, Role, FunctionUrlAuthType, EnvVars | URL `AuthType=NONE` = unauth entry |
| `RdsInstance` | rds.json | Arn, PubliclyAccessible, VpcSecurityGroups | |
| `SecretsManagerSecret` | secrets.json | Arn, ResourcePolicy | |
| `SsmParameter` | secrets.json | Name, ParamType | metadata only — never the value |
| `KmsKey` | kms.json | Arn, Policy | customer-managed only |

---

## Edge types

### A. Structural edges — populated in Phase 2

| Edge | From → To | Created by | Attacker action (why it exists) |
|---|---|---|---|
| `HAS_ATTACHED` | IamUser/Group/Role → IamPolicy | identity's `AttachedPolicies` / `InlinePolicies` | principal inherits every permission the policy grants |
| `IN_GROUP` | IamUser → IamGroup | user's `Groups` | user inherits the group's attached policies |
| `HAS_INSTANCE_PROFILE` | Ec2Instance → IamRole | instance `IamInstanceProfile` → profile `Roles` | compromise the instance → read the role's creds from IMDS `169.254.169.254` |
| `EXECUTES_AS` | LambdaFunction → IamRole | function `Role` | compromise/invoke the function → act as its role |
| `CAN_ASSUME` | IamUser/IamRole/Service → IamRole | target role's `TrustPolicy` Principal | the named principal may `sts:AssumeRole` into this role *(basic form; trust `Condition`s refined in Phase 3)* |
| `IN_SUBNET` | Ec2Instance/RdsInstance → Subnet | resource `SubnetId` | locates the resource for reachability |
| `IN_VPC` | Subnet → Vpc | subnet `VpcId` | topology |
| `PROTECTED_BY` | Ec2Instance/RdsInstance → SecurityGroup | resource `SecurityGroups` | the firewall guarding the resource |
| `ROUTES_VIA` | Subnet → RouteTable | route-table `Associations` | how the subnet reaches out |
| `HAS_INTERNET_ROUTE` | RouteTable → InternetGateway | a `0.0.0.0/0` route to an IGW | subnet is internet-facing (half of "public") |

*Rationale for the topology edges:* they carry no judgment (`Certain`), but Phase 3's
`CAN_REACH` computation walks exactly this chain (public IP + SG open + subnet routes to
IGW), so the scaffolding belongs in the structural layer.

### B. Evaluated edges — DEFINED here, populated in Phase 3

| Edge | From → To | Needs | Attacker action |
|---|---|---|---|
| `CAN_ASSUME` (refined) | Principal → IamRole | trust-policy `Condition` evaluation | assume the role, conditions permitting |
| `CAN_PASS_ROLE` | Principal → IamRole | IAM eval: `iam:PassRole` on the role | hand this role to a service they launch |
| `CAN_LAUNCH_AS` | Principal → IamRole | `CAN_PASS_ROLE` + `ec2:RunInstances`/`lambda:CreateFunction` | boot a resource carrying the role, then read its creds (**Phase 0 scenario 2**) |
| `CAN_READ` / `CAN_WRITE` | Principal → resource | IAM eval of action on resource | read/modify the resource (incl. `iam:SetDefaultPolicyVersion` — **Phase 0 scenario 1**) |
| `CAN_REACH` | Internet/resource → resource | network reachability chain | a network packet can arrive (public IP + SG + route) |
| `CONTAINS_CREDENTIAL` | S3Bucket/LambdaFunction env → Principal | credential scanning | found a key/secret that unlocks a principal |
| `GRANTS_ADMIN` | IamPolicy → (admin marker) | admin-equivalent permission catalogue | this policy is admin-equivalent (`*:*`, or a permission that reaches `*:*`) |

---

## How the two Phase 0 attacks appear in the graph (ground truth)

**Scenario 1 — policy rollback:**
```
raynor ─HAS_ATTACHED→ cg-raynor-policy ─(GRANTS_ADMIN via a reachable version)→ admin
```
The evaluator (Phase 3) must resolve the *default* version and honour explicit-deny
precedence — the v2-Deny / v3-Allow trap. `iam:SetDefaultPolicyVersion` is an
admin-equivalent permission in the catalogue.

**Scenario 2 — instance-profile attachment:**
```
kerrigan ─CAN_PASS_ROLE→ cg-ec2-mighty-role
kerrigan ─CAN_LAUNCH_AS→ cg-ec2-mighty-role   (PassRole + RunInstances)
new EC2 ─HAS_INSTANCE_PROFILE→ cg-ec2-mighty-role ─(is admin)→ compromise
```
`HAS_INSTANCE_PROFILE` is structural (Phase 2); `CAN_PASS_ROLE`/`CAN_LAUNCH_AS` are
evaluated (Phase 3).

---

## Open questions for iteration (decide before coding the loader)

1. **Inline vs managed policies** — model both as `IamPolicy` nodes, or fold inline policy
   documents onto the identity as a property? (Leaning: node for both, so `GRANTS_ADMIN`
   and evidence work uniformly.)
2. **Collapse the instance profile?** Keep `IamInstanceProfile` as its own node, or draw
   `HAS_INSTANCE_PROFILE` straight from instance to role? (Leaning: keep the node — the
   Phase 0 swap attack *is* an edit to the profile, so it's a real attacker touch-point.)
3. **`GRANTS_ADMIN` target** — an edge to a synthetic `Admin` sink node, or a boolean
   property on the policy? (Leaning: synthetic sink, so path search has a concrete target.)
4. **Group policies** — resolve `IN_GROUP` + group's `HAS_ATTACHED` at load time, or let
   path search walk both hops? (Leaning: let path search walk it — keeps the graph honest.)
5. **Multi-region nodes** — namespace `_id` by region for regional resources? (ARNs already
   encode region, so probably fine as-is.)

---

*Status: v1 draft. Iterate here until solid, THEN write the loader (`graph/loader.py`),
which is a pure function: `data/raw/*.json` → Neo4j `MERGE`. No AWS calls in the loader.*
