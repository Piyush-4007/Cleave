import { Cpu, Crown, Database, Globe, KeyRound, User, type LucideIcon } from "lucide-react";

// One illustrative attack path, in the same shape Cleave's API returns
// (nodes along the path, an edge per hop with its reason and evidence, one edge in the cut).
// The resource names are made up; the moves are the documented ones Cleave detects.

export type Hop = { id: string; label: string; kind: string; icon: LucideIcon; sink?: boolean };
export type Edge = { reason: string; plain: string; evidence: string; cut?: boolean };

export const HOPS: Hop[] = [
  { id: "internet", label: "Internet", kind: "entry point", icon: Globe },
  { id: "bucket", label: "s3://acme-backups", kind: "S3 bucket", icon: Database },
  { id: "key", label: "AKIA…7Q2F", kind: "access key, in deploy.env", icon: KeyRound },
  { id: "user", label: "iam/ci-deploy", kind: "IAM user", icon: User },
  { id: "lambda", label: "λ nightly-report", kind: "Lambda it can create", icon: Cpu },
  { id: "admin", label: "role/AdminRole", kind: "AdministratorAccess", icon: Crown, sink: true },
];

export const EDGES: Edge[] = [
  {
    reason: "PUBLIC_READ",
    plain: "Anyone on the internet can read objects in the backups bucket.",
    evidence: `Bucket policy statement
  "Effect": "Allow",
  "Principal": "*",
  "Action": "s3:GetObject"`,
  },
  {
    reason: "CONTAINS_CREDENTIAL",
    plain: "One of those objects is a deploy file with a live access key in it.",
    evidence: `s3://acme-backups/ci/deploy.env
  AWS_ACCESS_KEY_ID=AKIA…7Q2F   (key is Active)`,
  },
  {
    reason: "AUTHENTICATES_AS",
    plain: "That key signs requests as the ci-deploy user.",
    evidence: `iam:ListAccessKeys ci-deploy
  AccessKeyId AKIA…7Q2F  Status Active`,
  },
  {
    reason: "CAN_LAUNCH_AS",
    plain: "ci-deploy can create a Lambda function and hand it AdminRole (iam:PassRole).",
    evidence: `ci-deploy inline policy
  lambda:CreateFunction  on *
  iam:PassRole           on *   <- no resource scoping
AdminRole trust: lambda.amazonaws.com`,
    cut: true,
  },
  {
    reason: "RUNS_AS",
    plain: "The new function runs with AdminRole's permissions, so the attacker is now admin.",
    evidence: `AdminRole
  AttachedPolicy  AdministratorAccess`,
  },
];

export const FIX = {
  title: "Scope ci-deploy's iam:PassRole to the one role it actually deploys",
  diff: `- "Resource": "*"
+ "Resource": "arn:aws:iam::…:role/report-runner"`,
  disruption: "Low. ci-deploy only ever passes report-runner.",
};
