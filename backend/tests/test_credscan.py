"""Credential detection tests — finds key IDs, maps to owners, never leaks the secret."""
from cleave.credscan import scan_text, access_key_owners, credential_edges

ENV = "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\nAWS_SECRET_ACCESS_KEY=superSecretValue123+/xyz\n"

def test_scan_text_finds_key_only():
    hits = scan_text(ENV)
    assert len(hits) == 1
    assert hits[0]["key_id"] == "AKIAABCDEFGHIJKLMNOP"
    assert hits[0]["key_type"] == "AKIA"
    # the secret value must NEVER appear in the finding
    assert "superSecretValue123" not in str(hits)

def test_scan_text_ignores_random():
    assert scan_text("just some normal text with AKIA but not a key") == []

def test_scan_text_temp_and_role_keys():
    hits = {h["key_type"] for h in scan_text("ASIAABCDEFGHIJKLMNOP and AROAZYXWVUTSRQPONMLK")}
    assert hits == {"ASIA", "AROA"}

def test_access_key_owners_and_edges():
    iam = [{"_type": "IamUser", "_id": "arn:aws:iam::111:user/bob",
            "AccessKeys": [{"AccessKeyId": "AKIAABCDEFGHIJKLMNOP"}]}]
    owners = access_key_owners(iam)
    assert owners["AKIAABCDEFGHIJKLMNOP"] == "arn:aws:iam::111:user/bob"

    findings = [{"bucket_id": "arn:aws:s3:::leaky", "object_key": ".env",
                 "key_id": "AKIAABCDEFGHIJKLMNOP", "key_type": "AKIA",
                 "owner_arn": owners["AKIAABCDEFGHIJKLMNOP"]}]
    edges = credential_edges(findings)
    assert len(edges) == 1
    e = edges[0]
    assert e["frm"] == "arn:aws:s3:::leaky" and e["to"] == "arn:aws:iam::111:user/bob"
    assert e["rel"] == "CONTAINS_CREDENTIAL"

def test_unknown_key_makes_no_edge():
    findings = [{"bucket_id": "b", "object_key": "x.env", "key_id": "AKIAUNKNOWNUNKNOWN00",
                 "key_type": "AKIA", "owner_arn": None}]
    assert credential_edges(findings) == []


# ---- opt-in gating (Decision A) ------------------------------------------------------

def test_credscan_is_off_by_default():
    """Reading S3 object bodies needs s3:GetObject, which the default read-only role does
    not grant — so the scan must be opt-in, not run unconditionally."""
    from cleave.config import Settings
    assert Settings().cleave_credscan is False


def test_collect_skips_credscan_when_disabled(monkeypatch, tmp_path):
    """With the toggle off, the scan writes an empty _credentials.json and never calls
    scan_buckets (which would spray AccessDenied on the default role)."""
    import cleave.collect as collect
    from cleave import credscan

    monkeypatch.setattr(collect.settings, "cleave_credscan", False)
    monkeypatch.setattr(collect.settings, "cleave_output_dir", str(tmp_path))
    monkeypatch.setattr(collect.base, "COLLECTORS", {})  # no AWS collectors

    class FakeSession:
        def client(self, *_a, **_k):
            class C:
                def get_caller_identity(self):
                    return {"Arn": "arn:aws:iam::1:role/CleaveAudit"}
            return C()
    monkeypatch.setattr(collect, "build_session", lambda: FakeSession())

    called = {"scan": False}
    def _boom(*_a, **_k):
        called["scan"] = True
        raise AssertionError("scan_buckets must not run when credscan is disabled")
    monkeypatch.setattr(credscan, "scan_buckets", _boom)

    summary = collect.run()
    assert called["scan"] is False
    assert summary["credscan_findings"] == 0
    import json, pathlib
    assert json.loads((pathlib.Path(tmp_path) / "_credentials.json").read_text()) == []
