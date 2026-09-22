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
