"""Resource-policy holders that can be exposed to the whole internet: SNS topics, SQS
queues, ECR repositories. Regional. Reads names, ARNs and resource policies only.

These do not carry roles, so they are not launch routes; the risk is a resource policy
that names Principal '*' (public send/receive/pull). The findings layer decides that;
collectors only read.
"""
from __future__ import annotations
from .base import collector, paginate
from ._util import as_doc


@collector("sns")
def collect_sns(ctx) -> list[dict]:
    def in_region(region: str) -> list[dict]:
        out: list[dict] = []
        sns = ctx.client("sns", region)
        for t in paginate(sns, "list_topics", "Topics"):
            arn = t["TopicArn"]
            policy = None
            try:
                attrs = sns.get_topic_attributes(TopicArn=arn).get("Attributes", {})
                policy = as_doc(attrs.get("Policy"))
            except Exception:  # noqa: BLE001
                pass
            out.append({
                "_type": "SnsTopic", "_id": arn, "Region": region,
                "Name": arn.rsplit(":", 1)[-1], "Policy": policy,
            })
        return out
    return ctx.per_region(in_region)


@collector("sqs")
def collect_sqs(ctx) -> list[dict]:
    def in_region(region: str) -> list[dict]:
        out: list[dict] = []
        sqs = ctx.client("sqs", region)
        urls = sqs.list_queues().get("QueueUrls", []) or []
        for url in urls:
            policy, arn = None, url
            try:
                attrs = sqs.get_queue_attributes(
                    QueueUrl=url, AttributeNames=["Policy", "QueueArn"]).get("Attributes", {})
                policy = as_doc(attrs.get("Policy"))
                arn = attrs.get("QueueArn") or url
            except Exception:  # noqa: BLE001
                pass
            out.append({
                "_type": "SqsQueue", "_id": arn, "Region": region,
                "Name": url.rsplit("/", 1)[-1], "Url": url, "Policy": policy,
            })
        return out
    return ctx.per_region(in_region)


@collector("ecr")
def collect_ecr(ctx) -> list[dict]:
    def in_region(region: str) -> list[dict]:
        out: list[dict] = []
        ecr = ctx.client("ecr", region)
        for repo in paginate(ecr, "describe_repositories", "repositories"):
            name = repo["repositoryName"]
            policy = None
            try:
                policy = as_doc(ecr.get_repository_policy(repositoryName=name).get("policyText"))
            except Exception:  # noqa: BLE001 - RepositoryPolicyNotFoundException etc.
                pass
            out.append({
                "_type": "EcrRepository", "_id": repo.get("repositoryArn") or name,
                "Region": region, "Name": name,
                "Uri": repo.get("repositoryUri"), "Policy": policy,
            })
        return out
    return ctx.per_region(in_region)
