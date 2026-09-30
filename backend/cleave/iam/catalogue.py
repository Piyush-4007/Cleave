"""Admin-equivalent IAM permissions — permissions that are not *:* themselves but
*reach* admin. Sourced from docs/aws-common-risks-reference.md. Used by grants_admin()
and by Phase 4 sink detection. Patterns are matched case-insensitively with * wildcards.

The catalogue is split in two, and the split is load-bearing.

`ADMIN_EQUIVALENT_ACTIONS` are **sufficient on their own**: holding one, on an ordinary
account, is a complete privilege escalation with no second permission required. These are
what `grants_admin()` fires on, and therefore what puts a `GRANTS_ADMIN` edge in the graph.

`ENABLING_PRIMITIVES` are **only dangerous in combination**. iam:PassRole permits handing
a role to a service; on its own it obtains nothing, because you still need a compute action
to land the role somewhere. Treating these as admin-equivalent produced a path marked
*Certain* from a principal who could not actually take it — the exact "plausible-but-fake
path" the handbook names as Phase 3's trap. The combination is already modelled properly,
as the `CAN_LAUNCH_AS` edge (PassRole + RunInstances/CreateFunction), so nothing is lost by
keeping them out of `grants_admin`: they are evidence, not a conclusion.
"""

# Sufficient alone. Keep these CONCRETE (no "*"/"iam:*" here) — the "does the grant cover a
# dangerous action" test lives in grants_admin(), and putting wildcards here would make
# every action match.
ADMIN_EQUIVALENT_ACTIONS = {
    # policy mutation — write yourself a new permission set
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",       # Phase 0 scenario 1
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    # credential / identity takeover — become someone who already has more
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AddUserToGroup",
    # trust manipulation — make a privileged role trust you
    "iam:UpdateAssumeRolePolicy",
    # NOTE (30 Sep): lambda:UpdateFunctionCode moved to ENABLING_PRIMITIVES -- it yields
    # the function's own role, which the CAN_WRITE -> EXECUTES_AS edges model exactly.
    # TODO Phase 7: iam:CreateAccessKey / CreateLoginProfile / UpdateLoginProfile /
    # AddUserToGroup / UpdateAssumeRolePolicy have the same shape (you become a specific
    # user/group/role, admin only if it is). They stay here until precise takeover edges
    # exist, because dropping them now would lose real paths, not just noisy ones.
}

# The compute services that can carry an IAM role, and the action(s) that land the role on
# a new resource of that service. Each is "PassRole + these actions" AND the target role
# must TRUST the service principal (a Glue-only role cannot ride an EC2 instance). This is
# the general form of the Phase 0 privesc; CAN_LAUNCH_AS in graph/evaluated.py materialises
# it. Adding a service here is how Cleave learns a new launch route.
#   key   = the service principal the target role must trust
#   value = every IAM action required, ALL of which the attacker must hold
LAUNCH_SERVICES = {
    "lambda.amazonaws.com":         ["lambda:CreateFunction"],
    "ec2.amazonaws.com":            ["ec2:RunInstances"],   # + an instance profile (special-cased)
    "ecs-tasks.amazonaws.com":      ["ecs:RegisterTaskDefinition", "ecs:RunTask"],
    "glue.amazonaws.com":           ["glue:CreateDevEndpoint"],
    "sagemaker.amazonaws.com":      ["sagemaker:CreateTrainingJob"],
    "codebuild.amazonaws.com":      ["codebuild:CreateProject", "codebuild:StartBuild"],
    "cloudformation.amazonaws.com": ["cloudformation:CreateStack"],
}

# Dangerous only in combination. Excluded from grants_admin() on purpose.
ENABLING_PRIMITIVES = {
    "iam:PassRole",                       # Phase 0 scenario 2 — needs a compute action
    "iam:CreateUser",                     # a user with no permissions is not escalation
    "iam:AddRoleToInstanceProfile",       # walkthrough 2 step 3 — needs RunInstances
    "iam:RemoveRoleFromInstanceProfile",
    "ec2:AssociateIamInstanceProfile",
    "ec2:ReplaceIamInstanceProfileAssociation",
    "sts:AssumeRole",                     # the role's trust policy decides; see CAN_ASSUME
    "lambda:UpdateFunctionCode",          # = that function's role; see CAN_WRITE -> EXECUTES_AS
    # every launch action (needs PassRole + a service-trusting role; see CAN_LAUNCH_AS)
    *(a for actions in LAUNCH_SERVICES.values() for a in actions),
}

assert not (ADMIN_EQUIVALENT_ACTIONS & ENABLING_PRIMITIVES), "an action is one or the other"
