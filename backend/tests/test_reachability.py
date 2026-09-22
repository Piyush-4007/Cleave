"""Reachability predicate-chain tests: all three conditions must hold for CAN_REACH."""
from cleave.reachability.engine import compute_reach

def _records(public_ip=True, sg_open=True, public_subnet=True):
    sg = {"_type": "SecurityGroup", "_id": "sg-1", "IngressRules":
          ([{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}] if sg_open else
           [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}])}
    rt = {"_type": "RouteTable", "_id": "rtb-1", "VpcId": "vpc-1",
          "Associations": [{"SubnetId": "subnet-1"}],
          "Routes": ([{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}]
                     if public_subnet else
                     [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}])}
    inst = {"_type": "Ec2Instance", "_id": "i-1", "SubnetId": "subnet-1", "VpcId": "vpc-1",
            "SecurityGroups": ["sg-1"],
            "PublicIpAddress": "54.1.2.3" if public_ip else None}
    return [sg, rt, inst]


def test_public_instance_is_reachable():
    edges = compute_reach(_records())
    assert len(edges) == 1
    e = edges[0]
    assert e["frm"] == "internet" and e["to"] == "i-1" and e["rel"] == "CAN_REACH"
    assert "SSH" in e["props"]["reason"]  # port 22 labelled

def test_no_public_ip_blocks():
    assert compute_reach(_records(public_ip=False)) == []

def test_closed_sg_blocks():
    assert compute_reach(_records(sg_open=False)) == []

def test_private_subnet_blocks():
    assert compute_reach(_records(public_subnet=False)) == []
