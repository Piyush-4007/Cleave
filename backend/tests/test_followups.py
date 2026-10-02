"""The small open follow-ups (2 Oct): DynamoDB as a sink, API Gateway -> Lambda tracing,
and EKS IRSA roles as sources. Each with a positive case and a negative control."""
from cleave.paths.graphview import graph_from_records, rels_between
from cleave.paths.search import find_paths
from cleave.paths.endpoints import find_sinks, find_sources

A = "arn:aws:iam::111122223333:"
ADMIN = {"_type": "IamPolicy", "_id": "arn:aws:iam::aws:policy/AdministratorAccess",
         "PolicyName": "AdministratorAccess", "ManagedBy": "AWS",
         "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}


def user(name, *actions, resource="*"):
    return {"_type": "IamUser", "_id": f"{A}user/{name}", "UserName": name,
            "AttachedPolicies": [], "Groups": [],
            "InlinePolicies": {"p": {"Statement": [
                {"Effect": "Allow", "Action": list(actions), "Resource": resource}]}}}


# ---- DynamoDB as a sensitive-data sink -------------------------------------------------

def ddb(name="customers", tags=None):
    return {"_type": "DynamoDbTable", "_id": f"arn:aws:dynamodb:us-east-1:111122223333:table/{name}",
            "Region": "us-east-1", "Name": name, "Policy": None, "Tags": tags or {}}


def test_tagged_dynamodb_table_read_is_a_path():
    table = ddb(tags={"DataClassification": "pii"})
    g = graph_from_records([user("analyst", "dynamodb:GetItem", resource=table["_id"]), table])
    sinks = {s.uid: s.kind for s in find_sinks(g)}
    assert sinks.get(table["_id"]) == "SENSITIVE_DATA"
    paths = find_paths(g)
    assert any(p.sink.uid == table["_id"] for p in paths)


def test_untagged_dynamodb_table_is_not_a_sink():
    g = graph_from_records([user("analyst", "dynamodb:GetItem"), ddb()])
    assert all(s.kind != "SENSITIVE_DATA" for s in find_sinks(g))
    assert find_paths(g) == []


# ---- API Gateway route -> Lambda -> its role -------------------------------------------

def api(targets, routes=None):
    return {"_type": "ApiGatewayApi", "_id": "arn:aws:apigateway:us-east-1::/restapis/abc",
            "Region": "us-east-1", "Name": "api", "ApiId": "abc", "Protocol": "REST",
            "PublicRoutes": routes or [f"{t['route']}" for t in targets],
            "PublicRouteTargets": targets}


def lambda_fn(role=None, name="handler"):
    return {"_type": "LambdaFunction", "_id": f"arn:aws:lambda:us-east-1:111122223333:function:{name}",
            "FunctionName": name, "Region": "us-east-1", "Role": role, "FunctionUrlAuthType": None}


def test_public_api_route_traces_to_lambda_and_its_admin_role():
    fn = lambda_fn(role=f"{A}role/fn-role")
    role = {"_type": "IamRole", "_id": f"{A}role/fn-role", "RoleName": "fn-role",
            "AttachedPolicies": [ADMIN["_id"]], "InlinePolicies": {},
            "TrustPolicy": {"Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                                           "Action": "sts:AssumeRole"}]}}
    a = api([{"route": "GET /run", "lambda": fn["_id"]}])
    g = graph_from_records([a, fn, role, ADMIN])
    assert "ROUTES_TO" in rels_between(g, a["_id"], fn["_id"])
    paths = find_paths(g)
    chain = [[n for n in p.nodes] for p in paths if p.source.uid == a["_id"]]
    assert any(fn["_id"] in nodes and "admin" in nodes for nodes in chain), "api->lambda->role->admin expected"


def test_api_with_no_lambda_target_has_no_routes_to_edge():
    a = api([], routes=["GET /static"])  # public but no Lambda integration
    g = graph_from_records([a])
    assert not any(e[2] for e in [(a["_id"], n, rels_between(g, a["_id"], n)) for n in g.successors(a["_id"])])


# ---- EKS IRSA: a role a pod can assume via the cluster OIDC provider --------------------

OIDC = "oidc.eks.us-east-1.amazonaws.com/id/ABCDEF0123"


def eks_cluster():
    return {"_type": "EksCluster", "_id": "arn:aws:eks:us-east-1:111122223333:cluster/prod",
            "Name": "prod", "Region": "us-east-1", "Version": "1.29",
            "OidcIssuer": f"https://{OIDC}"}


def irsa_role(name="pod-role", admin=True):
    return {"_type": "IamRole", "_id": f"{A}role/{name}", "RoleName": name,
            "AttachedPolicies": [ADMIN["_id"]] if admin else [], "InlinePolicies": {},
            "TrustPolicy": {"Statement": [{"Effect": "Allow",
                "Principal": {"Federated": f"arn:aws:iam::111122223333:oidc-provider/{OIDC}"},
                "Action": "sts:AssumeRoleWithWebIdentity"}]}}


def test_irsa_role_is_a_source_and_mentions_the_cluster():
    role = irsa_role()
    g = graph_from_records([eks_cluster(), role, ADMIN])
    src = {s.uid: s for s in find_sources(g)}
    assert role["_id"] in src
    assert "IRSA" in src[role["_id"]].reason or "pod" in src[role["_id"]].reason
    # and it reaches admin: pod-role -> AdministratorAccess -> admin
    assert any(p.source.uid == role["_id"] for p in find_paths(g))


def test_oidc_role_without_a_matching_cluster_is_not_an_irsa_source():
    """A Federated OIDC trust whose provider matches no collected cluster is not asserted as
    pod-assumable (could be an external IdP); it falls through to the generic 'others' rule."""
    role = irsa_role()
    g = graph_from_records([role, ADMIN])  # no EKS cluster collected
    src = {s.uid: s for s in find_sources(g)}
    assert "IRSA" not in (src.get(role["_id"]).reason if role["_id"] in src else "")
