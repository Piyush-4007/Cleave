import type { Analysis, AttackPath, PathNode } from "./api";

/* A believable scanned account. Six paths; three funnel through deploy-bot's admin grant,
   so the single best fix breaks three at once and the minimum cut is more than one edge.
   Admin is an explicit terminal node (matches the backend's synthetic Admin sink). */

const ADMIN: PathNode = { id: "admin", type: "admin", name: "administrator" };

const ADMIN_POLICY = JSON.stringify(
  { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "iam:CreateAccessKey", Resource: "*" }] },
  null, 2,
);
const READ_POLICY = JSON.stringify(
  { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "s3:GetObject", Resource: "arn:aws:s3:::prod-config/*" }] },
  null, 2,
);

const paths: AttackPath[] = [
  {
    id: "PATH-001", rank: 1, score: 9.2, confidence: "Certain",
    title: "The internet reaches an admin role through a config file.",
    source: { name: "internet", kind: "EXTERNAL" },
    sink: { name: "administrator", kind: "ADMIN" },
    technique: "Read-then-steal (bucket read yields a live key)",
    nodes: [
      { id: "internet", type: "internet", name: "anyone" },
      { id: "web-01", type: "ec2", name: "web-01",
        detail: { arn: "arn:aws:ec2:us-east-1:4155:instance/i-0a1b", facts: [["public ip", "54.x.x.12"], ["imds", "v1 (optional)"], ["security group", "sg-web · 0.0.0.0/0:22"]] } },
      { id: "web-app-role", type: "role", name: "web-app-role",
        detail: { arn: "arn:aws:iam::4155:role/web-app-role", policy: READ_POLICY, facts: [["attached via", "instance profile"], ["last used", "2 hours ago"], ["trust", "ec2.amazonaws.com"]] } },
      { id: "prod-config", type: "s3", name: "prod-config/.env",
        detail: { arn: "arn:aws:s3:::prod-config", facts: [["object", "deploy/.env (106 B)"], ["public", "no"], ["encryption", "SSE-S3"]] } },
      { id: "deploy-bot", type: "user", name: "deploy-bot",
        detail: { arn: "arn:aws:iam::4155:user/deploy-bot", policy: ADMIN_POLICY, facts: [["access key", "AKIA…F3FQ · active"], ["key last used", "91 days ago"], ["admin-equivalent", "iam:CreateAccessKey"]] } },
      ADMIN,
    ],
    hops: [
      { frm: "internet", to: "web-01", rel: "CAN_REACH", reason: "internet-reachable on port 22", confidence: "Certain" },
      { frm: "web-01", to: "web-app-role", rel: "HAS_INSTANCE_PROFILE", reason: "the instance runs with this role's credentials", confidence: "Certain" },
      { frm: "web-app-role", to: "prod-config", rel: "CAN_READ", reason: "can call s3:GetObject on this bucket", confidence: "Certain" },
      { frm: "prod-config", to: "deploy-bot", rel: "CONTAINS_CREDENTIAL", reason: "an AKIA key for deploy-bot is in the object", confidence: "Certain" },
      { frm: "deploy-bot", to: "admin", rel: "GRANTS_ADMIN", reason: "admin-equivalent permission iam:CreateAccessKey", confidence: "Certain" },
    ],
  },
  {
    id: "PATH-002", rank: 2, score: 8.8, confidence: "Certain",
    title: "A CI user rolls a policy back to an admin version.",
    source: { name: "ci-runner", kind: "ASSUMED_COMPROMISE" },
    sink: { name: "administrator", kind: "ADMIN" },
    technique: "SetDefaultPolicyVersion rollback",
    nodes: [
      { id: "ci-runner", type: "user", name: "ci-runner",
        detail: { arn: "arn:aws:iam::4155:user/ci-runner", facts: [["can", "iam:SetDefaultPolicyVersion"], ["key last used", "today"]] } },
      { id: "ci-policy", type: "policy", name: "ci-deploy-policy",
        detail: { arn: "arn:aws:iam::4155:policy/ci-deploy-policy", facts: [["default version", "v1 (read-only)"], ["hidden versions", "v2 Deny, v3 Allow *:*"]] } },
      ADMIN,
    ],
    hops: [
      { frm: "ci-runner", to: "ci-policy", rel: "HAS_ATTACHED", reason: "user holds this managed policy", confidence: "Certain" },
      { frm: "ci-policy", to: "admin", rel: "GRANTS_ADMIN", reason: "iam:SetDefaultPolicyVersion reaches Allow *:*", confidence: "Certain" },
    ],
  },
  {
    id: "PATH-003", rank: 3, score: 8.1, confidence: "Certain",
    title: "A public backup leaks a key that reads the customer database.",
    source: { name: "db-backups", kind: "EXTERNAL" },
    sink: { name: "prod-customers", kind: "SENSITIVE_DATA" },
    technique: "Credential exposed in storage, reused",
    nodes: [
      { id: "backups", type: "s3", name: "db-backups", detail: { arn: "arn:aws:s3:::db-backups", facts: [["public", "bucket ACL: AllUsers"], ["object", "dump.sql"]] } },
      { id: "analytics-bot", type: "user", name: "analytics-bot", detail: { arn: "arn:aws:iam::4155:user/analytics-bot", facts: [["can", "secretsmanager:GetSecretValue"]] } },
      { id: "prod-customers", type: "rds", name: "prod-customers", detail: { arn: "arn:aws:rds:us-east-1:4155:db/prod-customers", facts: [["tag", "Environment=production"], ["engine", "postgres"]] } },
    ],
    hops: [
      { frm: "backups", to: "analytics-bot", rel: "CONTAINS_CREDENTIAL", reason: "a key for analytics-bot is in dump.sql", confidence: "Certain" },
      { frm: "analytics-bot", to: "prod-customers", rel: "CAN_READ", reason: "can read the production database secret", confidence: "Possible" },
    ],
  },
  {
    id: "PATH-004", rank: 4, score: 7.4, confidence: "Certain",
    title: "An intern overwrites a Lambda that runs as an admin role.",
    source: { name: "intern", kind: "ASSUMED_COMPROMISE" },
    sink: { name: "administrator", kind: "ADMIN" },
    technique: "Lambda code overwrite (act as the execution role)",
    nodes: [
      { id: "intern", type: "user", name: "intern", detail: { arn: "arn:aws:iam::4155:user/intern", facts: [["can", "lambda:UpdateFunctionCode"]] } },
      { id: "report-fn", type: "lambda", name: "nightly-report", detail: { arn: "arn:aws:lambda:us-east-1:4155:function:nightly-report", facts: [["url auth", "none"], ["runtime", "python3.12"]] } },
      { id: "report-role", type: "role", name: "report-role", detail: { arn: "arn:aws:iam::4155:role/report-role", policy: ADMIN_POLICY, facts: [["attached", "AdministratorAccess"]] } },
      ADMIN,
    ],
    hops: [
      { frm: "intern", to: "report-fn", rel: "CAN_WRITE", reason: "can overwrite the function code", confidence: "Certain" },
      { frm: "report-fn", to: "report-role", rel: "EXECUTES_AS", reason: "the function runs as this role", confidence: "Certain" },
      { frm: "report-role", to: "admin", rel: "GRANTS_ADMIN", reason: "AdministratorAccess is attached", confidence: "Certain" },
    ],
  },
  {
    id: "PATH-005", rank: 5, score: 6.9, confidence: "Certain",
    title: "A build cache leaks the same deploy-bot key.",
    source: { name: "ci-cache", kind: "EXTERNAL" },
    sink: { name: "administrator", kind: "ADMIN" },
    technique: "Credential exposed in storage, reused",
    nodes: [
      { id: "ci-cache", type: "s3", name: "ci-cache", detail: { arn: "arn:aws:s3:::ci-cache", facts: [["public", "bucket policy: Principal *"]] } },
      { id: "deploy-bot", type: "user", name: "deploy-bot", detail: { arn: "arn:aws:iam::4155:user/deploy-bot", policy: ADMIN_POLICY, facts: [["admin-equivalent", "iam:CreateAccessKey"]] } },
      ADMIN,
    ],
    hops: [
      { frm: "ci-cache", to: "deploy-bot", rel: "CONTAINS_CREDENTIAL", reason: "the same AKIA key is cached here too", confidence: "Certain" },
      { frm: "deploy-bot", to: "admin", rel: "GRANTS_ADMIN", reason: "admin-equivalent permission iam:CreateAccessKey", confidence: "Certain" },
    ],
  },
  {
    id: "PATH-006", rank: 6, score: 6.2, confidence: "Possible",
    title: "A staging role can assume its way to deploy-bot.",
    source: { name: "staging-deployer", kind: "ASSUMED_COMPROMISE" },
    sink: { name: "administrator", kind: "ADMIN" },
    technique: null,
    nodes: [
      { id: "staging-deployer", type: "role", name: "staging-deployer", detail: { arn: "arn:aws:iam::4155:role/staging-deployer", facts: [["can", "sts:AssumeRole (conditional)"]] } },
      { id: "deploy-bot", type: "user", name: "deploy-bot", detail: { arn: "arn:aws:iam::4155:user/deploy-bot", policy: ADMIN_POLICY, facts: [["admin-equivalent", "iam:CreateAccessKey"]] } },
      ADMIN,
    ],
    hops: [
      { frm: "staging-deployer", to: "deploy-bot", rel: "CAN_ASSUME", reason: "trust policy allows this principal, conditions permitting", confidence: "Possible" },
      { frm: "deploy-bot", to: "admin", rel: "GRANTS_ADMIN", reason: "admin-equivalent permission iam:CreateAccessKey", confidence: "Possible" },
    ],
  },
];

const cut = [
  { frm: "deploy-bot", to: "admin", rel: "GRANTS_ADMIN", cost: 6, paths_cut: 3, paths_total: 6, fix: "Scope iam:CreateAccessKey to specific users and rotate deploy-bot's key" },
  { frm: "ci-policy", to: "admin", rel: "GRANTS_ADMIN", cost: 6, paths_cut: 1, paths_total: 6, fix: "Remove iam:SetDefaultPolicyVersion from ci-deploy-policy" },
  { frm: "report-role", to: "admin", rel: "GRANTS_ADMIN", cost: 6, paths_cut: 1, paths_total: 6, fix: "Give nightly-report a least-privilege execution role" },
  { frm: "analytics-bot", to: "prod-customers", rel: "CAN_READ", cost: 3, paths_cut: 1, paths_total: 6, fix: "Remove the analytics-bot secret grant on the production database" },
];

export const MOCK: Analysis = {
  source: "mock",
  account: "415500000000",
  generated_at: new Date().toISOString(),
  summary: {
    resources: 1284,
    sources: 21,
    sources_external: 4,
    paths_found: 6,
    sinks_admin: 1,
    sinks_sensitive_data: 3,
    top_score: 9.2,
    best_single_fix: { fix: "Scope deploy-bot's iam:CreateAccessKey and rotate its key", breaks: 3, of: 6, cost: 6 },
  },
  paths,
  minimum_cut: { total_cost: 21, paths_total: 6, edges: cut },
  best_single_fix: cut,
};
