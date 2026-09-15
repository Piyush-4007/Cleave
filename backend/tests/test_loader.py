"""Unit tests for the graph loader's pure logic (no Neo4j needed)."""
from cleave.graph.loader import _trust_principals, _node_props


def test_trust_principals_aws_and_service():
    trust = {"Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111:user/bob"},
         "Action": "sts:AssumeRole"},
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
         "Action": "sts:AssumeRole"},
        {"Effect": "Deny", "Principal": {"AWS": "arn:aws:iam::111:user/eve"},
         "Action": "sts:AssumeRole"},
    ]}
    got = _trust_principals(trust)
    assert "arn:aws:iam::111:user/bob" in got
    assert "service:ec2.amazonaws.com" in got
    assert "arn:aws:iam::111:user/eve" not in got  # Deny is skipped


def test_node_props_keeps_scalars_and_raw():
    rec = {"_type": "IamUser", "_id": "arn:...:user/x", "UserName": "x",
           "AttachedPolicies": ["a", "b"], "InlinePolicies": {"p": {"big": "doc"}}}
    props = _node_props(rec)
    assert props["UserName"] == "x"
    assert props["AttachedPolicies"] == ["a", "b"]      # list of scalars kept
    assert "InlinePolicies" not in props                # dict dropped from props
    assert "_raw" in props                              # ...but preserved as evidence
