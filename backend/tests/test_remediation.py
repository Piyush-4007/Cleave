"""Phase 8 — remediation generator + verification loop.

Each test runs a path fixture through analyze -> generate(fix) -> verify, and asserts the
fix both looks right (the corrected Terraform/policy removes the dangerous grant) and
WORKS (re-running the search with it applied removes the path). The verify half is the
handbook's "rescan -> path confirmed gone", done offline.
"""
import json
import pathlib

import pytest

from cleave.paths.analysis import analyze
from cleave.paths.graphview import graph_from_records
from cleave.remediation.generate import generate, generate_for_result
from cleave.remediation.verify import verify_fixes

FIX_DIR = pathlib.Path(__file__).parent / "path_fixtures"


def _load(name):
    fx = json.loads((FIX_DIR / name).read_text())
    g = graph_from_records(fx["records"], fx.get("cred_findings", []))
    return fx, g, analyze(g)


def _edge(result, rel):
    for e in result["minimum_cut"]["edges"]:
        if e["rel"] == rel:
            return e
    raise AssertionError(f"no {rel} in the minimum cut: "
                         f"{[e['rel'] for e in result['minimum_cut']['edges']]}")


# ---- GRANTS_ADMIN on a primitive (customer/inline policy) ------------------------------

def test_grants_admin_primitive_is_scoped_and_verified():
    fx, g, result = _load("01-iam_privesc_by_rollback.json")
    fix = generate(_edge(result, "GRANTS_ADMIN"), g)
    assert fix.confidence == "templated"
    assert "SetDefaultPolicyVersion" not in json.dumps(fix.policy_json)
    assert fix.terraform and "jsonencode" in fix.terraform
    v = verify_fixes(fx["records"], [fix.to_dict()])
    assert v["fully_cut"] and v["paths_after"] == 0


# ---- GRANTS_ADMIN on real AdministratorAccess (AWS-managed) -> guidance ----------------

def test_grants_admin_aws_managed_is_guidance():
    fx, g, result = _load("09-access-key-takeover-of-an-admin.json")
    # the admin policy itself is AWS-managed: a direct GRANTS_ADMIN fix is guidance-only
    admin_edge = {"rel": "GRANTS_ADMIN",
                  "frm": "arn:aws:iam::aws:policy/AdministratorAccess", "to": "admin",
                  "fix": "x"}
    fix = generate(admin_edge, g)
    assert fix.confidence == "guidance" and fix.terraform is None
    assert "detach" in fix.note.lower()


# ---- CAN_TAKE_OVER -> scope to self, verified ------------------------------------------

def test_can_take_over_is_scoped_to_self_and_verified():
    fx, g, result = _load("09-access-key-takeover-of-an-admin.json")
    fix = generate(_edge(result, "CAN_TAKE_OVER"), g)
    assert fix.confidence == "templated"
    assert "${aws:username}" in json.dumps(fix.policy_json)
    v = verify_fixes(fx["records"], [fix.to_dict()])
    assert v["fully_cut"] and v["paths_after"] == 0


# ---- the whole minimum cut, as the UI would request it ---------------------------------

def test_generate_for_result_cuts_every_path():
    fx, g, result = _load("06-overlapping-paths-shared-cut.json")
    fixes = generate_for_result(result, g)
    assert fixes and all(f["confidence"] in ("templated", "guidance") for f in fixes)
    templated = [f for f in fixes if f["confidence"] == "templated"]
    assert templated, "the shared-cut fixture should yield at least one templated fix"
    v = verify_fixes(fx["records"], templated)
    assert v["remaining"] < v["paths_before"]  # the cut reduces the paths


# ---- a guidance fallback never claims to be a patch ------------------------------------

def test_unknown_edge_is_guidance_only():
    fix = generate({"rel": "CAN_REACH", "frm": "internet", "to": "x", "fix": "narrow SG"},
                   graph_from_records([]))
    assert fix.confidence == "guidance" and fix.terraform is None and not fix.apply
