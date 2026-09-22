"""Graph loader — pure transform: data/raw/*.json  ->  Neo4j nodes + structural edges.

No AWS calls here. Reads the JSON the collectors wrote and MERGEs a graph. Only the
STRUCTURAL edges are populated (Phase 2); evaluated edges (CAN_READ, CAN_PASS_ROLE,
CAN_REACH, GRANTS_ADMIN, …) are added in Phase 3.

Every edge carries the 4-field contract: reason, evidence, confidence, discovered_by.
"""
from __future__ import annotations
import json
import logging
import pathlib
from typing import Iterable
from neo4j import GraphDatabase

log = logging.getLogger("cleave.graph")

SCALAR = (str, int, float, bool, type(None))

# Allowlist — labels/relationship types are interpolated into Cypher, so they must be
# from a controlled set (never user/config input).
NODE_LABELS = {
    "Internet", "IamUser", "IamRole", "IamGroup", "IamPolicy", "IamInstanceProfile",
    "S3Bucket", "Ec2Instance", "SecurityGroup", "Subnet", "Vpc", "RouteTable",
    "NetworkAcl", "InternetGateway", "LambdaFunction", "RdsInstance",
    "SecretsManagerSecret", "SsmParameter", "KmsKey", "Principal", "Admin",
}
EDGE_TYPES = {
    # structural (Phase 2)
    "HAS_ATTACHED", "IN_GROUP", "HAS_INSTANCE_PROFILE", "CONTAINS_ROLE",
    "EXECUTES_AS", "CAN_ASSUME", "IN_SUBNET", "IN_VPC", "PROTECTED_BY",
    "ROUTES_VIA", "HAS_INTERNET_ROUTE",
    # evaluated (Phase 3)
    "GRANTS_ADMIN", "CAN_PASS_ROLE", "CAN_LAUNCH_AS", "CAN_REACH", "CONTAINS_CREDENTIAL",
    # evaluated on demand during path search (Phase 4 increment 2) — see paths/access.py
    "CAN_READ", "CAN_WRITE",
}


def _node_props(rec: dict) -> dict:
    """Scalar fields become node properties; the full record is kept as _raw (evidence)."""
    props = {"label": rec["_type"]}
    for k, v in rec.items():
        if k.startswith("_"):
            continue
        if isinstance(v, SCALAR):
            props[k] = v
        elif isinstance(v, list) and all(isinstance(x, SCALAR) for x in v):
            props[k] = v
        # dicts / lists-of-dicts (policy docs, SG rules) live only in _raw
    props["_raw"] = json.dumps(rec, default=str)
    return props


def _edge(frm: str, to: str, rel: str, reason: str, evidence: str,
          confidence: str = "Certain", discovered_by: str = "graph.loader") -> dict:
    return {"frm": frm, "to": to, "rel": rel, "props": {
        "reason": reason, "evidence": evidence,
        "confidence": confidence, "discovered_by": discovered_by,
    }}


class GraphLoader:
    def __init__(self, uri: str, user: str, password: str):
        self._driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self._driver.close()

    # ---- low-level ----
    def _merge_node(self, tx, label: str, uid: str, props: dict):
        assert label in NODE_LABELS, f"unknown label {label}"
        tx.run(f"MERGE (n:{label} {{uid:$uid}}) SET n += $props", uid=uid, props=props)

    def _merge_edge(self, tx, e: dict):
        assert e["rel"] in EDGE_TYPES, f"unknown edge {e['rel']}"
        tx.run(
            f"MATCH (a {{uid:$frm}}), (b {{uid:$to}}) "
            f"MERGE (a)-[r:{e['rel']}]->(b) SET r += $props",
            frm=e["frm"], to=e["to"], props=e["props"],
        )

    def wipe(self):
        with self._driver.session() as s:
            s.run("MATCH (n) DETACH DELETE n")

    # ---- high-level ----
    def load(self, raw_dir: str | pathlib.Path) -> dict[str, int]:
        raw = pathlib.Path(raw_dir)
        records: list[dict] = []
        for f in sorted(raw.glob("*.json")):
            if f.name.startswith("_"):
                continue
            data = json.loads(f.read_text())
            if isinstance(data, list):
                records.extend(data)
        by_id = {r["_id"]: r for r in records}

        with self._driver.session() as s:
            # uniqueness constraint on uid per label -> fast MERGE, no cartesian warnings
            for label in NODE_LABELS:
                s.run(f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{label}) REQUIRE n.uid IS UNIQUE")

            # synthetic sink/source nodes
            s.execute_write(self._merge_node, "Internet", "internet",
                            {"label": "Internet", "_raw": "{}"})
            s.execute_write(self._merge_node, "Admin", "admin",
                            {"label": "Admin", "_raw": "{}"})

            # 1) nodes
            for r in records:
                if r["_type"] in NODE_LABELS:
                    s.execute_write(self._merge_node, r["_type"], r["_id"], _node_props(r))

            # 2) edges — structural (Phase 2) + evaluated (Phase 3)
            from .evaluated import compute_evaluated_edges
            cred_path = raw / "_credentials.json"
            cred_findings = json.loads(cred_path.read_text()) if cred_path.exists() else []
            edges = list(derive_structural_edges(records))
            edges += compute_evaluated_edges(records, cred_findings)
            # ensure stub target nodes (AWS-managed policies, external/inline principals) exist
            for stub in stub_nodes(edges, by_id):
                s.execute_write(self._merge_node, stub["label"], stub["uid"], stub["props"])
            for e in edges:
                s.execute_write(self._merge_edge, e)

        counts = {"nodes": len(by_id) + 1, "edges": len(edges)}
        log.info("loaded %d nodes, %d edges", counts["nodes"], counts["edges"])
        return counts


# ---- structural edge derivation -------------------------------------------------
# Module-level and pure so anything that needs the structural graph can call it without
# a Neo4j driver (Phase 4 path search builds its NetworkX view straight from records).
def derive_structural_edges(records: list[dict]) -> Iterable[dict]:
    """Phase 2 structural edges: read straight from config, no judgment, all Certain."""
    groups_by_name = {r["GroupName"]: r["_id"] for r in records if r["_type"] == "IamGroup"}
    for r in records:
        t = r["_type"]

        if t in ("IamUser", "IamRole", "IamGroup"):
            for arn in r.get("AttachedPolicies", []):
                yield _edge(r["_id"], arn, "HAS_ATTACHED",
                            f"{t} has managed policy attached", f"{r['_id']}#AttachedPolicies")
            for pname in (r.get("InlinePolicies") or {}):
                inline_id = f"{r['_id']}#inline/{pname}"
                yield _edge(r["_id"], inline_id, "HAS_ATTACHED",
                            f"{t} has inline policy {pname}", f"{r['_id']}#InlinePolicies/{pname}")

        if t == "IamUser":
            for gname in r.get("Groups", []):
                gid = groups_by_name.get(gname)
                if gid:
                    yield _edge(r["_id"], gid, "IN_GROUP",
                                f"user is member of group {gname}", f"{r['_id']}#Groups")

        if t == "IamInstanceProfile":
            for role_arn in r.get("Roles", []):
                yield _edge(r["_id"], role_arn, "CONTAINS_ROLE",
                            "instance profile carries role", f"{r['_id']}#Roles")

        if t == "Ec2Instance":
            prof = r.get("IamInstanceProfile")
            if prof:
                yield _edge(r["_id"], prof, "HAS_INSTANCE_PROFILE",
                            "instance uses this instance profile", f"{r['_id']}#IamInstanceProfile")
            if r.get("SubnetId"):
                yield _edge(r["_id"], r["SubnetId"], "IN_SUBNET",
                            "instance lives in subnet", f"{r['_id']}#SubnetId")
            for sg in r.get("SecurityGroups", []):
                yield _edge(r["_id"], sg, "PROTECTED_BY",
                            "instance guarded by security group", f"{r['_id']}#SecurityGroups")

        if t == "LambdaFunction" and r.get("Role"):
            yield _edge(r["_id"], r["Role"], "EXECUTES_AS",
                        "function runs as this role", f"{r['_id']}#Role")

        if t == "IamRole" and isinstance(r.get("TrustPolicy"), dict):
            for principal in _trust_principals(r["TrustPolicy"]):
                yield _edge(principal, r["_id"], "CAN_ASSUME",
                            "principal is trusted to assume this role",
                            f"{r['_id']}#TrustPolicy", confidence="Certain")

        if t == "Subnet":
            if r.get("VpcId"):
                yield _edge(r["_id"], r["VpcId"], "IN_VPC",
                            "subnet belongs to vpc", f"{r['_id']}#VpcId")

        if t == "RouteTable":
            for assoc in r.get("Associations", []):
                sn = assoc.get("SubnetId")
                if sn:
                    yield _edge(sn, r["_id"], "ROUTES_VIA",
                                "subnet uses this route table", f"{r['_id']}#Associations")
            for route in r.get("Routes", []):
                gw = route.get("GatewayId", "")
                if str(gw).startswith("igw-") and route.get("DestinationCidrBlock") == "0.0.0.0/0":
                    yield _edge(r["_id"], gw, "HAS_INTERNET_ROUTE",
                                "route table has 0.0.0.0/0 -> internet gateway",
                                f"{r['_id']}#Routes")

def _stub(label: str, uid: str, record: dict):
    """A node we didn't collect as a record. `record` is the dict form (what in-memory
    consumers read); `props` is the Neo4j form, with non-scalars folded into _raw."""
    props = {k: v for k, v in record.items()
             if not k.startswith("_") and isinstance(v, SCALAR)}
    props["label"] = label
    props["_raw"] = json.dumps(record, default=str)
    return {"label": label, "uid": uid, "props": props, "record": record}


def stub_nodes(edges, by_id):
    """Create nodes for edge targets we didn't collect as records (inline policies,
    AWS-managed policies we couldn't read, external/service principals) so edges have
    something to land on.

    Inline-policy nodes carry their actual Document: the policy is real, it just lives on
    the identity rather than as its own IAM object. Without it the graph holds an edge to
    an empty node, and anything reasoning from the graph (Phase 4 access expansion, the
    Phase 6 node inspector) cannot see what the policy grants.
    """
    seen = set()
    known = set(by_id) | {"internet", "admin"}
    for e in (edges or []):
        for uid in (e["frm"], e["to"]):
            if uid in known or uid in seen:
                continue
            seen.add(uid)
            if "#inline/" in uid:
                identity, name = uid.split("#inline/", 1)
                doc = ((by_id.get(identity) or {}).get("InlinePolicies") or {}).get(name)
                yield _stub("IamPolicy", uid, {
                    "_type": "IamPolicy", "_id": uid, "PolicyName": name,
                    "Inline": True, "AttachedTo": identity, "Document": doc})
            elif uid.startswith("arn:aws:iam::aws:policy/"):
                yield _stub("IamPolicy", uid, {
                    "_type": "IamPolicy", "_id": uid, "PolicyName": uid.split("/")[-1],
                    "ManagedBy": "AWS", "Document": None})
            elif uid.startswith("arn:aws:iam::") or uid.startswith("service:") or uid == "*":
                yield _stub("Principal", uid, {
                    "_type": "Principal", "_id": uid, "Name": uid})
            # anything else (e.g. igw-, subnet-) is a real collected node or absent; skip

def _trust_principals(trust: dict) -> list[str]:
    """Pull AWS/Service principals out of a role trust policy (Allow + sts:AssumeRole)."""
    out: list[str] = []
    stmts = trust.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for st in stmts:
        if st.get("Effect") != "Allow":
            continue
        pr = st.get("Principal", {})
        if pr == "*":
            out.append("*")
            continue
        if isinstance(pr, dict):
            aws = pr.get("AWS")
            if isinstance(aws, str):
                out.append(aws)
            elif isinstance(aws, list):
                out.extend(aws)
            svc = pr.get("Service")
            for s in ([svc] if isinstance(svc, str) else (svc or [])):
                out.append(f"service:{s}")
    return out
