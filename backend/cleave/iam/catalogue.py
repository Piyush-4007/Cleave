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
    # NOTE (30 Sep): lambda:UpdateFunctionCode moved to ENABLING_PRIMITIVES -- it yields
    # the function's own role, which the CAN_WRITE -> EXECUTES_AS edges model exactly.
    # NOTE (Phase 7): the identity-takeover actions moved to TAKEOVER_ACTIONS below.
}

# Identity takeover (Phase 7). Each makes the attacker a SPECIFIC principal -- admin only
# if that principal is. v1 listed them as admin-equivalent, which drew a GRANTS_ADMIN edge
# (a finished path to admin) for anyone holding e.g. iam:CreateAccessKey, even in an
# account with nobody worth becoming. They are now precise edges to the target, built in
# graph/evaluated.py, and the path continues through whatever that target holds.
#   action -> (edge type, target kind)
# Technique numbers: Rhino Security Labs, "AWS IAM Privilege Escalation Methods".
TAKEOVER_ACTIONS = {
    "iam:CreateAccessKey":        ("CAN_TAKE_OVER", "user"),     # Rhino #4
    "iam:CreateLoginProfile":     ("CAN_TAKE_OVER", "user"),     # Rhino #5
    "iam:UpdateLoginProfile":     ("CAN_TAKE_OVER", "user"),     # Rhino #6
    "iam:AddUserToGroup":         ("CAN_JOIN_GROUP", "group"),   # Rhino #13
    "iam:UpdateAssumeRolePolicy": ("CAN_REWRITE_TRUST", "role"), # Rhino #14
}

# The compute services that can carry an IAM role, and the action(s) that land the role on
# a new resource of that service. Each is "PassRole + these actions" AND the target role
# must TRUST the service principal (a Glue-only role cannot ride an EC2 instance). This is
# the general form of the Phase 0 privesc; CAN_LAUNCH_AS in graph/evaluated.py materialises
# it. Adding a service here is how Cleave learns a new launch route.
#   key   = the service principal the target role must trust
#   value = every IAM action required, ALL of which the attacker must hold
# Value is a list of ROUTES; each route is an AND-list of actions. The service is
# launchable if the attacker holds every action of ANY one route. Multiple routes because
# a service usually offers several ways to run code as a role — e.g. Glue via a dev
# endpoint, or via CreateJob+StartJobRun (the CloudGoat glue_privesc path). Learned by
# reading real scenarios: a single action per service missed live escalations.
LAUNCH_SERVICES = {
    "lambda.amazonaws.com":         [["lambda:CreateFunction"]],
    "ec2.amazonaws.com":            [["ec2:RunInstances"]],   # + an instance profile (special-cased)
    "ecs-tasks.amazonaws.com":      [["ecs:RegisterTaskDefinition", "ecs:RunTask"]],
    "glue.amazonaws.com":           [["glue:CreateDevEndpoint"],
                                     ["glue:CreateJob", "glue:StartJobRun"],
                                     ["glue:UpdateJob", "glue:StartJobRun"]],
    "sagemaker.amazonaws.com":      [["sagemaker:CreateTrainingJob"],
                                     ["sagemaker:CreateNotebookInstance"]],
    "codebuild.amazonaws.com":      [["codebuild:CreateProject", "codebuild:StartBuild"],
                                     ["codebuild:UpdateProject", "codebuild:StartBuild"]],
    "cloudformation.amazonaws.com": [["cloudformation:CreateStack"]],
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
    *(a for routes in LAUNCH_SERVICES.values() for route in routes for a in route),
}

assert not (ADMIN_EQUIVALENT_ACTIONS & ENABLING_PRIMITIVES), "an action is one or the other"
assert not (set(TAKEOVER_ACTIONS) & (ADMIN_EQUIVALENT_ACTIONS | ENABLING_PRIMITIVES))
