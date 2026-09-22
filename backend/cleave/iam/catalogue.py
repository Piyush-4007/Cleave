"""Admin-equivalent IAM permissions — permissions that are not *:* themselves but
*reach* admin. Sourced from docs/aws-common-risks-reference.md. Used by grants_admin()
and (Phase 4) by sink detection. Patterns are matched case-insensitively with * wildcards.
"""

# Concrete admin-equivalent actions. A granted action pattern (e.g. "*", "iam:*",
# "iam:Create*") is admin-equivalent if it *covers* one of these. Keep these CONCRETE
# (no "*"/"iam:*" here) — the "does the grant cover a dangerous action" test lives in
# grants_admin(), and putting wildcards here would make every action match.
ADMIN_EQUIVALENT_ACTIONS = {
    # policy mutation
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",       # Phase 0 scenario 1
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    # credential / identity creation
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:CreateUser",
    "iam:AddUserToGroup",
    # trust / assume manipulation
    "iam:UpdateAssumeRolePolicy",
    "iam:PassRole",                       # enabling primitive (Phase 0 scenario 2)
    "sts:AssumeRole",
    # compute-based (PassRole + these = launch-as)
    "ec2:RunInstances",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "glue:CreateDevEndpoint",
    "cloudformation:CreateStack",
}
