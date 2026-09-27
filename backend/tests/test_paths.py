"""Phase 4 path search.

The fixture files in `path_fixtures/` are the ground truth: each is a hand-built account
(collector-shaped records) with the paths we walked by hand in Phase 0 written down as the
expected answer. They run the WHOLE pipeline -- structural edges, IAM evaluation, evaluated
edges, source/sink classification, search -- so a regression anywhere shows up here.

Handbook's "done when": it finds the CloudGoat paths you exploited by hand.
"""
import json
import pathlib
import pytest

from cleave.graph.loader import EDGE_TYPES
from cleave.paths.endpoints import bucket_public_reason, find_sinks, find_sources, holds_full_admin
from cleave.paths.graphview import graph_from_records, rels_between
from cleave.paths.model import ASSUMED_COMPROMISE, EXTERNAL
from cleave.paths.access import effective_policy_docs, expansion_targets
from cleave.paths.search import (CONTEXT_ONLY, TRAVERSABLE, find_paths, search_graph,
                                 traversable_subgraph)

FIX_DIR = pathlib.Path(__file__).parent / "path_fixtures"
FIXTURES = sorted(FIX_DIR.glob("*.json"))


def _load(path):
    fx = json.loads(path.read_text())
    g = graph_from_records(fx["records"], fx.get("cred_findings", []))
    return fx, g, find_paths(g)


def _signature(p):
    return (p.source.uid, p.sink.uid, tuple(p.nodes), tuple(h.rel for h in p.hops))


# What the collector now produces for an attached AWS-managed policy: the real document.
ADMIN_POLICY = {
    "_type": "IamPolicy", "_id": "arn:aws:iam::aws:policy/AdministratorAccess",
    "PolicyName": "AdministratorAccess", "ManagedBy": "AWS",
    "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
}


# ---- the allowlist contract ----------------------------------------------------------

def test_every_edge_type_is_classified():
    """A new edge type must be declared traversable or context-only. Without this, adding
    an edge in a later phase silently defaults to 'not walkable' and the path vanishes."""
    classified = set(TRAVERSABLE) | set(CONTEXT_ONLY)
    assert classified == EDGE_TYPES, {
        "unclassified": EDGE_TYPES - classified,
        "unknown to the loader": classified - EDGE_TYPES,
    }
    assert not (set(TRAVERSABLE) & set(CONTEXT_ONLY))


def test_structural_connective_edges_are_traversable():
    """A principal reaches its powers THROUGH the structural edges -- dropping them
    disconnects every IAM path in the graph."""
    for rel in ("HAS_ATTACHED", "IN_GROUP", "HAS_INSTANCE_PROFILE", "CONTAINS_ROLE",
                "EXECUTES_AS", "CAN_ASSUME"):
        assert rel in TRAVERSABLE


def test_topology_edges_are_not_traversable():
    """These exist so CAN_REACH can be computed; walking them invents fake paths."""
    for rel in ("IN_SUBNET", "IN_VPC", "PROTECTED_BY", "ROUTES_VIA", "HAS_INTERNET_ROUTE",
                "CAN_PASS_ROLE"):
        assert rel in CONTEXT_ONLY and rel not in TRAVERSABLE


def test_traversable_subgraph_drops_context_edges():
    records = [
        {"_type": "Ec2Instance", "_id": "i-1", "SubnetId": "subnet-1", "VpcId": "vpc-1",
         "SecurityGroups": ["sg-1"], "IamInstanceProfile": None},
        {"_type": "Subnet", "_id": "subnet-1", "VpcId": "vpc-1"},
        {"_type": "Vpc", "_id": "vpc-1"},
        {"_type": "SecurityGroup", "_id": "sg-1", "IngressRules": []},
    ]
    g = graph_from_records(records)
    sub = traversable_subgraph(g)
    assert g.has_edge("i-1", "subnet-1")        # present for context (Phase 6 draws it)
    assert not sub.has_edge("i-1", "subnet-1")  # but never walked
    assert not sub.has_edge("subnet-1", "vpc-1")


# ---- the ground-truth fixtures -------------------------------------------------------
# Path fixtures come in two shapes: those with `expect.paths` (a written-out expected path
# list, checked here) and Phase-5 fixtures that only declare aggregate expectations like a
# shared choke point (checked in test_ranking.py). The path-list tests skip the latter.
PATHLIST_FIXTURES = [p for p in FIXTURES
                     if "paths" in json.loads(p.read_text()).get("expect", {})]


@pytest.mark.parametrize("path", PATHLIST_FIXTURES, ids=[p.stem for p in PATHLIST_FIXTURES])
def test_fixture_finds_expected_paths(path):
    fx, _g, found = _load(path)
    found_sigs = {_signature(p) for p in found}

    for exp in fx["expect"]["paths"]:
        want = (exp["source"], exp["sink"], tuple(exp["nodes"]), tuple(exp["edges"]))
        assert want in found_sigs, (
            f"{fx['name']}: expected path not found.\n"
            f"  wanted: {want}\n  found:  "
            + "\n          ".join(map(str, sorted(found_sigs))))
        match = next(p for p in found if _signature(p) == want)
        assert match.source.kind == exp["source_kind"]
        if "sink_kind" in exp:
            assert match.sink.kind == exp["sink_kind"]
        if "confidence" in exp:
            assert match.confidence == exp["confidence"]


@pytest.mark.parametrize("path", PATHLIST_FIXTURES, ids=[p.stem for p in PATHLIST_FIXTURES])
def test_fixture_finds_nothing_extra(path):
    """Over-reporting is the failure mode that rebuilds alert fatigue. A fixture pins the
    exact number of paths so a new edge type cannot quietly double it."""
    fx, _g, found = _load(path)
    assert len(found) == fx["expect"]["total_paths"], \
        "\n".join(f"{p.source.uid} -> {[h.rel for h in p.hops]}" for p in found)
    for uid in fx["expect"].get("no_paths_from", []):
        assert not [p for p in found if p.source.uid == uid], \
            f"{uid} should not reach admin"


@pytest.mark.parametrize("path", PATHLIST_FIXTURES, ids=[p.stem for p in PATHLIST_FIXTURES])
def test_fixture_hops_carry_evidence(path):
    """Every edge needs evidence tied to a real attacker action (standing constraint 4)."""
    _fx, _g, found = _load(path)
    for p in found:
        for h in p.hops:
            assert h.reason and h.evidence, f"{h.rel} hop has no evidence"
            assert h.confidence in ("Certain", "Possible")
            assert h.discovered_by


# ---- source classification -----------------------------------------------------------

def test_admin_holder_is_not_a_source():
    """cleave-dev holds AdministratorAccess: that is the account baseline, not a finding."""
    records = [
        {"_type": "IamUser", "_id": "arn:aws:iam::1:user/cleave-dev", "UserName": "cleave-dev",
         "AttachedPolicies": ["arn:aws:iam::aws:policy/AdministratorAccess"],
         "Groups": [], "InlinePolicies": {}},
        ADMIN_POLICY,
    ]
    g = graph_from_records(records)
    assert holds_full_admin(g, "arn:aws:iam::1:user/cleave-dev")
    assert [s.uid for s in find_sources(g)] == []


def test_escalation_primitive_holder_is_a_source():
    """The distinction that makes Phase 4 work: a policy granting
    iam:SetDefaultPolicyVersion is admin-EQUIVALENT (it gets a GRANTS_ADMIN edge) but its
    holder is not yet admin -- he has to escalate, and that escalation is the finding."""
    records = [
        {"_type": "IamUser", "_id": "arn:aws:iam::1:user/raynor", "UserName": "raynor",
         "AttachedPolicies": [], "Groups": [],
         "InlinePolicies": {"p": {"Statement": [
             {"Effect": "Allow", "Action": "iam:SetDefaultPolicyVersion", "Resource": "*"}]}}},
    ]
    g = graph_from_records(records)
    assert not holds_full_admin(g, "arn:aws:iam::1:user/raynor")
    assert [(s.uid, s.kind) for s in find_sources(g)] == \
           [("arn:aws:iam::1:user/raynor", ASSUMED_COMPROMISE)]
    assert len(find_paths(g)) == 1


def test_group_inherited_admin_is_excluded():
    records = [
        {"_type": "IamUser", "_id": "arn:aws:iam::1:user/u", "UserName": "u",
         "AttachedPolicies": [], "Groups": ["admins"], "InlinePolicies": {}},
        {"_type": "IamGroup", "_id": "arn:aws:iam::1:group/admins", "GroupName": "admins",
         "AttachedPolicies": ["arn:aws:iam::aws:policy/AdministratorAccess"],
         "InlinePolicies": {}},
        ADMIN_POLICY,
    ]
    g = graph_from_records(records)
    assert holds_full_admin(g, "arn:aws:iam::1:user/u")


def test_public_access_block_beats_a_public_acl():
    allusers = [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]
    assert bucket_public_reason({"Acl": allusers})
    assert not bucket_public_reason({
        "Acl": allusers,
        "PublicAccessBlock": {"BlockPublicAcls": True, "IgnorePublicAcls": True,
                              "BlockPublicPolicy": True, "RestrictPublicBuckets": True}})


def test_unauthenticated_lambda_url_is_external():
    records = [{"_type": "LambdaFunction", "_id": "arn:aws:lambda:us-east-1:1:function:f",
                "FunctionName": "f", "FunctionUrlAuthType": "NONE", "Role": None}]
    g = graph_from_records(records)
    assert [s.kind for s in find_sources(g)] == [EXTERNAL]


# ---- search behaviour ----------------------------------------------------------------

def test_hop_limit_is_respected():
    _fx, g, _ = _load(FIX_DIR / "02-iam_privesc_by_attachment.json")
    assert find_paths(g, max_hops=1) == []
    assert all(p.length <= 2 for p in find_paths(g, max_hops=2))


def test_passrole_is_evidence_but_not_a_step():
    """kerrigan has both CAN_PASS_ROLE and CAN_LAUNCH_AS to the mighty role. The edge stays
    in the graph as evidence of the primitive, but only the completed form is walkable."""
    _fx, g, found = _load(FIX_DIR / "02-iam_privesc_by_attachment.json")
    kerrigan = "arn:aws:iam::111122223333:user/kerrigan"
    mighty = "arn:aws:iam::111122223333:role/cg-ec2-mighty-role"
    assert rels_between(g, kerrigan, mighty) == {"CAN_PASS_ROLE", "CAN_LAUNCH_AS"}
    assert rels_between(traversable_subgraph(g), kerrigan, mighty) == {"CAN_LAUNCH_AS"}
    hop = next(h for p in found for h in p.hops if h.to == mighty)
    assert hop.rel == "CAN_LAUNCH_AS"


def test_passrole_without_a_compute_action_reaches_nothing():
    """The false positive this guards: passing a role obtains nothing on its own. It must
    not reappear via GRANTS_ADMIN either -- iam:PassRole is an enabling primitive, so it is
    not admin-equivalent by itself."""
    records = [
        {"_type": "IamUser", "_id": "arn:aws:iam::1:user/passrole-only",
         "UserName": "passrole-only", "AttachedPolicies": [], "Groups": [],
         "InlinePolicies": {"p": {"Statement": [
             {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}}},
        {"_type": "IamRole", "_id": "arn:aws:iam::1:role/mighty", "RoleName": "mighty",
         "AttachedPolicies": ["arn:aws:iam::aws:policy/AdministratorAccess"],
         "InlinePolicies": {}, "TrustPolicy": {}},
        ADMIN_POLICY,
    ]
    g = graph_from_records(records)
    assert rels_between(g, "arn:aws:iam::1:user/passrole-only", "arn:aws:iam::1:role/mighty")         == {"CAN_PASS_ROLE"}
    assert find_paths(g) == []


def test_sink_is_admin_only_in_v1():
    _fx, g, _ = _load(FIX_DIR / "01-iam_privesc_by_rollback.json")
    assert [(s.uid, s.kind) for s in find_sinks(g)] == [("admin", "ADMIN")]


def test_dedup_key_distinguishes_routes():
    """Phase 5 groups on this; prove it is stable and separates distinct routes."""
    _fx, _g, found = _load(FIX_DIR / "02-iam_privesc_by_attachment.json")
    assert len({p.dedup_key for p in found}) == len(found)


def test_narration_is_deterministic_and_mentions_every_hop():
    _fx, _g, found = _load(FIX_DIR / "01-iam_privesc_by_rollback.json")
    text = found[0].narrate()
    assert text == found[0].narrate()
    for h in found[0].hops:
        assert h.rel in text


# ---- CAN_READ / CAN_WRITE expansion (increment 2) ------------------------------------

def test_expansion_skips_dead_end_resources():
    """Demand-driven: a bucket nobody can pivot through is not worth evaluating access to,
    however readable it is. This is what keeps the cost off a principal x resource
    cross product."""
    records = [
        {"_type": "S3Bucket", "_id": "arn:aws:s3:::dead-end", "Name": "dead-end",
         "Policy": None, "Acl": [], "PublicAccessBlock": None},
    ]
    g = graph_from_records(records)
    assert expansion_targets(g, set(TRAVERSABLE)) == []


def test_expansion_targets_a_bucket_holding_a_credential():
    records = [
        {"_type": "S3Bucket", "_id": "arn:aws:s3:::leaky", "Name": "leaky",
         "Policy": None, "Acl": [], "PublicAccessBlock": None},
        {"_type": "IamUser", "_id": "arn:aws:iam::1:user/victim", "UserName": "victim",
         "AttachedPolicies": [], "Groups": [], "InlinePolicies": {},
         "AccessKeys": [{"AccessKeyId": "AKIAEXAMPLE000000001"}]},
    ]
    creds = [{"bucket_id": "arn:aws:s3:::leaky", "object_key": "x/.env",
              "key_id": "AKIAEXAMPLE000000001", "key_type": "AKIA",
              "owner_arn": "arn:aws:iam::1:user/victim"}]
    g = graph_from_records(records, creds)
    assert expansion_targets(g, set(TRAVERSABLE)) == ["arn:aws:s3:::leaky"]


def test_can_read_granted_by_a_bucket_policy_alone():
    """The read hop must consider the resource-based side: outsider holds no S3 permission
    at all, but the bucket policy names him."""
    outsider = "arn:aws:iam::1:user/outsider"
    records = [
        {"_type": "IamUser", "_id": outsider, "UserName": "outsider",
         "AttachedPolicies": ["arn:aws:iam::1:policy/nothing-useful"],
         "Groups": [], "InlinePolicies": {}, "AccessKeys": []},
        {"_type": "IamPolicy", "_id": "arn:aws:iam::1:policy/nothing-useful",
         "PolicyName": "nothing-useful",
         "Document": {"Statement": [{"Effect": "Allow", "Action": "ec2:Describe*",
                                     "Resource": "*"}]}},
        {"_type": "S3Bucket", "_id": "arn:aws:s3:::shared", "Name": "shared",
         "PublicAccessBlock": None, "Acl": [],
         "Policy": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": outsider},
                                   "Action": "s3:GetObject"}]}},
        {"_type": "IamUser", "_id": "arn:aws:iam::1:user/privileged", "UserName": "privileged",
         "AttachedPolicies": ["arn:aws:iam::1:policy/priv"], "Groups": [], "InlinePolicies": {},
         "AccessKeys": [{"AccessKeyId": "AKIAEXAMPLE000000002"}]},
        {"_type": "IamPolicy", "_id": "arn:aws:iam::1:policy/priv", "PolicyName": "priv",
         "Document": {"Statement": [{"Effect": "Allow", "Action": "iam:CreateAccessKey",
                                     "Resource": "*"}]}},
    ]
    creds = [{"bucket_id": "arn:aws:s3:::shared", "object_key": "creds.json",
              "key_id": "AKIAEXAMPLE000000002", "key_type": "AKIA",
              "owner_arn": "arn:aws:iam::1:user/privileged"}]
    g = graph_from_records(records, creds)
    paths = find_paths(g)
    sub = search_graph(g, find_sources(g), find_sinks(g))
    assert rels_between(sub, outsider, "arn:aws:s3:::shared") == {"CAN_READ"}
    theft = [p for p in paths if p.source.uid == outsider]
    assert len(theft) == 1
    assert [h.rel for h in theft[0].hops] == \
        ["CAN_READ", "CONTAINS_CREDENTIAL", "HAS_ATTACHED", "GRANTS_ADMIN"]


def test_can_write_to_a_lambda_reaches_its_role():
    """Overwrite the code and it runs as the execution role. EXECUTES_AS is the hop that
    makes the write worth anything."""
    attacker = "arn:aws:iam::1:user/attacker"
    fn = "arn:aws:lambda:us-east-1:1:function:reporter"
    role = "arn:aws:iam::1:role/reporter-role"
    records = [
        {"_type": "IamUser", "_id": attacker, "UserName": "attacker",
         "AttachedPolicies": [], "Groups": [],
         "InlinePolicies": {"p": {"Statement": [
             {"Effect": "Allow", "Action": "lambda:UpdateFunctionCode", "Resource": "*"}]}}},
        {"_type": "LambdaFunction", "_id": fn, "FunctionName": "reporter", "Role": role,
         "FunctionUrlAuthType": None, "EnvVars": {}},
        {"_type": "IamRole", "_id": role, "RoleName": "reporter-role",
         "AttachedPolicies": ["arn:aws:iam::aws:policy/AdministratorAccess"],
         "InlinePolicies": {}, "TrustPolicy": {}},
        ADMIN_POLICY,
    ]
    g = graph_from_records(records)
    routes = [[h.rel for h in p.hops] for p in find_paths(g)
              if p.source.uid == attacker]
    assert ["CAN_WRITE", "EXECUTES_AS", "HAS_ATTACHED", "GRANTS_ADMIN"] in routes, routes


def test_inline_policy_documents_are_readable_from_the_graph():
    """Inline policies are nodes without their own IAM object; the graph must still carry
    the document or access expansion cannot see what they grant."""
    uid = "arn:aws:iam::1:user/u"
    doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    g = graph_from_records([
        {"_type": "IamUser", "_id": uid, "UserName": "u", "AttachedPolicies": [],
         "Groups": [], "InlinePolicies": {"only": doc}},
    ])
    assert effective_policy_docs(g, uid) == [doc]


def test_expansion_can_be_switched_off():
    """Isolating which edges produced a result matters when a path looks wrong."""
    _fx, g, _ = _load(FIX_DIR / "05-credential-theft-via-bucket-read.json")
    without = find_paths(g, expand=False)
    assert all("CAN_READ" not in [h.rel for h in p.hops] for p in without)
    assert len(without) < len(find_paths(g))


def test_search_does_not_mutate_the_stored_graph():
    """Access expansion happens on a copy. The same graph searched twice must give the
    same answer, and the graph Phase 6 holds must not silently grow edges underneath it."""
    _fx, g, _ = _load(FIX_DIR / "05-credential-theft-via-bucket-read.json")
    before = (g.number_of_nodes(), g.number_of_edges())
    first = [_signature(p) for p in find_paths(g)]
    second = [_signature(p) for p in find_paths(g)]
    assert (g.number_of_nodes(), g.number_of_edges()) == before
    assert first == second
    assert not any("CAN_READ" in rels_between(g, a, b) for a, b in g.edges())
