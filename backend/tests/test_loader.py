"""Unit tests for the graph loader's pure logic (no Neo4j needed).

Trust-policy parsing moved to graph/evaluated.py (assume_role_edges) in Phase 7, where
CAN_ASSUME is evaluated with identity policies and trust Conditions; see
tests/test_evaluator_v2.py for its coverage.
"""
from cleave.graph.loader import _node_props


def test_node_props_keeps_scalars_and_raw():
    rec = {"_type": "IamUser", "_id": "arn:...:user/x", "UserName": "x",
           "AttachedPolicies": ["a", "b"], "InlinePolicies": {"p": {"big": "doc"}}}
    props = _node_props(rec)
    assert props["UserName"] == "x"
    assert props["AttachedPolicies"] == ["a", "b"]      # list of scalars kept
    assert "InlinePolicies" not in props                # dict dropped from props
    assert "_raw" in props                              # ...but preserved as evidence
