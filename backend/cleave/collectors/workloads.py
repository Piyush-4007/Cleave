"""Compute workloads that carry an IAM role: Glue jobs, SageMaker notebooks, CodeBuild
projects, ECS services. Regional. Reads and normalises only.

Why these live together: each is a running (or runnable) workload that executes AS a role.
Compromising the workload yields that role's credentials, so the findings/endpoints layer
treats such a role as a possible starting point (a source) — the same reasoning already
applied to Lambda functions and EC2 instances. The role reference is the one field that
matters here; everything else is context.
"""
from __future__ import annotations
from .base import collector, paginate


@collector("glue")
def collect_glue(ctx) -> list[dict]:
    def in_region(region: str) -> list[dict]:
        out: list[dict] = []
        glue = ctx.client("glue", region)
        for j in paginate(glue, "get_jobs", "Jobs"):
            out.append({
                "_type": "GlueJob", "_id": f"arn:aws:glue:{region}:job/{j['Name']}",
                "Region": region, "Name": j.get("Name"), "Role": j.get("Role"),
                "Command": (j.get("Command") or {}).get("Name"),
            })
        return out
    return ctx.per_region(in_region)


@collector("sagemaker")
def collect_sagemaker(ctx) -> list[dict]:
    def in_region(region: str) -> list[dict]:
        out: list[dict] = []
        sm = ctx.client("sagemaker", region)
        for n in paginate(sm, "list_notebook_instances", "NotebookInstances"):
            name = n["NotebookInstanceName"]
            role, direct = None, None
            try:
                d = sm.describe_notebook_instance(NotebookInstanceName=name)
                role, direct = d.get("RoleArn"), d.get("DirectInternetAccess")
            except Exception:  # noqa: BLE001 - keep the instance even if describe is denied
                pass
            out.append({
                "_type": "SageMakerNotebook", "_id": n.get("NotebookInstanceArn") or name,
                "Region": region, "Name": name, "Role": role,
                "Status": n.get("NotebookInstanceStatus"), "DirectInternetAccess": direct,
            })
        return out
    return ctx.per_region(in_region)


@collector("codebuild")
def collect_codebuild(ctx) -> list[dict]:
    def in_region(region: str) -> list[dict]:
        out: list[dict] = []
        cb = ctx.client("codebuild", region)
        names = list(paginate(cb, "list_projects", "projects"))
        for i in range(0, len(names), 100):  # batch_get_projects takes <=100 names
            for p in cb.batch_get_projects(names=names[i:i + 100]).get("projects", []):
                out.append({
                    "_type": "CodeBuildProject", "_id": p.get("arn") or p["name"],
                    "Region": region, "Name": p.get("name"), "Role": p.get("serviceRole"),
                    "SourceType": (p.get("source") or {}).get("type"),
                })
        return out
    return ctx.per_region(in_region)


@collector("ecs")
def collect_ecs(ctx) -> list[dict]:
    def in_region(region: str) -> list[dict]:
        out: list[dict] = []
        ecs = ctx.client("ecs", region)
        td_role: dict[str, tuple] = {}  # task-def arn -> (task role, execution role)

        def roles_for(td_arn: str):
            if td_arn not in td_role:
                try:
                    td = ecs.describe_task_definition(taskDefinition=td_arn)["taskDefinition"]
                    td_role[td_arn] = (td.get("taskRoleArn"), td.get("executionRoleArn"))
                except Exception:  # noqa: BLE001
                    td_role[td_arn] = (None, None)
            return td_role[td_arn]

        for cluster in paginate(ecs, "list_clusters", "clusterArns"):
            svc_arns = list(paginate(ecs, "list_services", "serviceArns", cluster=cluster))
            for i in range(0, len(svc_arns), 10):  # describe_services takes <=10
                for s in ecs.describe_services(cluster=cluster,
                                               services=svc_arns[i:i + 10]).get("services", []):
                    task_role, exec_role = roles_for(s.get("taskDefinition"))
                    out.append({
                        "_type": "EcsService", "_id": s.get("serviceArn") or s.get("serviceName"),
                        "Region": region, "Name": s.get("serviceName"), "Cluster": cluster,
                        "TaskDefinition": s.get("taskDefinition"),
                        "DesiredCount": s.get("desiredCount"), "LaunchType": s.get("launchType"),
                        "Role": task_role, "ExecutionRole": exec_role,
                    })
        return out
    return ctx.per_region(in_region)
