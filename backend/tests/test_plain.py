"""Plain-language path summaries: deterministic, one sentence per hop type, no jargon."""
import json
import pathlib

from cleave.paths.analysis import analyze
from cleave.paths.graphview import graph_from_records
from cleave.paths.plain import plain_summary

FIX_DIR = pathlib.Path(__file__).parent / "path_fixtures"


def _analysis(name):
    fx = json.loads((FIX_DIR / name).read_text())
    return analyze(graph_from_records(fx["records"], fx.get("cred_findings", [])))


def test_every_path_gets_a_summary_and_it_is_stable():
    a = _analysis("06-overlapping-paths-shared-cut.json")
    b = _analysis("06-overlapping-paths-shared-cut.json")
    assert a["paths"] and all(p["plain"] for p in a["paths"])
    assert [p["plain"] for p in a["paths"]] == [p["plain"] for p in b["paths"]]


def test_summary_avoids_edge_type_jargon():
    for p in _analysis("06-overlapping-paths-shared-cut.json")["paths"]:
        assert not any(rel in p["plain"] for rel in
                       ("GRANTS_ADMIN", "HAS_ATTACHED", "CAN_ASSUME", "CONTAINS_CREDENTIAL"))


def test_public_bucket_credential_path_reads_as_a_story():
    path = {
        "source": {"kind": "EXTERNAL"}, "sink": {"kind": "ADMIN"}, "confidence": "Certain",
        "view": [{"label": "S3Bucket", "name": "public-dump"},
                 {"label": "IamUser", "name": "ci-deployer"},
                 {"label": "IamPolicy", "name": "p"},
                 {"label": "Admin", "name": "administrator"}],
        "hops": [{"rel": "CONTAINS_CREDENTIAL", "reason": "AKIA access key for the owner found in an object"},
                 {"rel": "HAS_ATTACHED", "reason": "IamUser has inline policy p"},
                 {"rel": "GRANTS_ADMIN", "reason": "admin-equivalent permission 'iam:AttachUserPolicy'"}],
    }
    assert plain_summary(path) == (
        "Anyone on the internet can read the storage bucket public-dump, with no login. "
        "The storage bucket public-dump holds a saved login key that belongs to the user "
        "ci-deployer, so whoever reads it can act as the user ci-deployer. "
        "The user ci-deployer holds a permission (iam:AttachUserPolicy) that lets it give "
        "itself full control of the account.")


def test_possible_paths_say_so():
    path = {"source": {"kind": "ASSUMED_COMPROMISE"}, "sink": {"kind": "ADMIN"},
            "confidence": "Possible",
            "view": [{"label": "IamUser", "name": "eng"}, {"label": "IamRole", "name": "ops"}],
            "hops": [{"rel": "CAN_ASSUME", "reason": "trust"}]}
    s = plain_summary(path)
    assert s.startswith("Suppose the login for the user eng")
    assert "possible rather than certain" in s
