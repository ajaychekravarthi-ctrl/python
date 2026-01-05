#!/usr/bin/env python3
"""
Unified AWS Security Group + EKS + ALB Automation Tool
Supports:
  - EC2 SG operations
  - EKS cluster discovery
  - Nodegroup SG fetch
  - Cluster SG fetch
  - ALB SG fetch
  - Add/Delete SG rules across EKS + ALB + EC2
"""

import boto3
import sys
from botocore.exceptions import ClientError

# Make sure AWS region/credentials are configured via:
#   aws configure
# or environment variables.

ec2 = boto3.client("ec2")
eks = boto3.client("eks")
elbv2 = boto3.client("elbv2")   # For ALBs


# ======================================================
# Helper Functions
# ======================================================
def error(msg):
    print(f"[ERROR] {msg}")
    sys.exit(1)


def success(msg):
    print(f"[SUCCESS] {msg}")


def show_usage():
    print("""
=====================================================
 AWS Security Group + EKS + ALB Unified Tool - Usage
=====================================================

EC2 OPERATIONS
-------------------------------------------
List EC2 Instances:
  python3 sgtool.py list-instances

List ALL Security Groups:
  python3 sgtool.py list-sg

Find SGs for an EC2 Instance:
  python3 sgtool.py find-sg <instance-id>


SG RULE OPERATIONS
-------------------------------------------
Add Ingress:
  python3 sgtool.py add-ingress <sg-id> <protocol> <port> <cidr>

Delete Ingress:
  python3 sgtool.py del-ingress <sg-id> <protocol> <port> <cidr>


EKS OPERATIONS
-------------------------------------------
List EKS Clusters:
  python3 sgtool.py eks-list

List Nodegroups:
  python3 sgtool.py eks-nodegroups <cluster>

List ALL SGs used by cluster (NodeGroup + Cluster SG):
  python3 sgtool.py eks-all-sg <cluster>

Add ingress to ALL EKS SGs:
  python3 sgtool.py eks-add-ingress <cluster> <protocol> <port> <cidr>


ALB OPERATIONS
-------------------------------------------
List ALBs:
  python3 sgtool.py alb-list

List ALB SGs:
  python3 sgtool.py alb-sg

Add ingress rule to ALL ALB SGs:
  python3 sgtool.py alb-add-ingress <protocol> <port> <cidr>


FULL CLUSTER-WIDE OPERATION (EKS + ALB)
-------------------------------------------
Add ingress to ALL SGs (EKS + ALB):
  python3 sgtool.py eks-add-ingress-all <cluster> <protocol> <port> <cidr>

=====================================================
""")


# ======================================================
# Security Group Core Logic
# ======================================================
def get_sg(group_id):
    resp = ec2.describe_security_groups(GroupIds=[group_id])
    return resp["SecurityGroups"][0]


def rule_exists(sg, protocol, port, cidr):
    for perm in sg.get("IpPermissions", []):
        if perm.get("IpProtocol") == protocol and perm.get("FromPort") == port:
            for ip in perm.get("IpRanges", []):
                if ip.get("CidrIp") == cidr:
                    return True
    return False


def add_ingress(group_id, protocol, port, cidr):
    sg = get_sg(group_id)
    if rule_exists(sg, protocol, port, cidr):
        print(f"[SKIP] Rule already exists on {group_id}: {cidr}:{port}")
        return
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{
            "IpProtocol": protocol,
            "FromPort": port,
            "ToPort": port,
            "IpRanges": [{"CidrIp": cidr}]
        }]
    )
    success(f"Ingress added → {group_id} {cidr}:{port}")


def del_ingress(group_id, protocol, port, cidr):
    ec2.revoke_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{
            "IpProtocol": protocol,
            "FromPort": port,
            "ToPort": port,
            "IpRanges": [{"CidrIp": cidr}]
        }]
    )
    success(f"Ingress deleted → {group_id} {cidr}:{port}")


# ======================================================
# EC2 OPERATIONS
# ======================================================
def list_instances():
    resp = ec2.describe_instances()
    print("\nEC2 INSTANCES:\n")
    for res in resp["Reservations"]:
        for inst in res["Instances"]:
            name = next(
                (t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"),
                "No-Name"
            )
            print(f"{inst['InstanceId']:<20}  {name}")
    print()


def list_sg():
    resp = ec2.describe_security_groups()
    print("\nSECURITY GROUPS:\n")
    for sg in resp["SecurityGroups"]:
        print(f"{sg['GroupId']:<20}  {sg['GroupName']}")
    print()


def find_sg(instance_id):
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    inst = resp["Reservations"][0]["Instances"][0]
    print("\nInstance SGs:\n")
    for sg in inst["SecurityGroups"]:
        print(f"{sg['GroupId']}  {sg['GroupName']}")
    print()


# ======================================================
# EKS NODEGROUP + CLUSTER SG
# ======================================================
def eks_list_clusters():
    clusters = eks.list_clusters()["clusters"]
    print("\nEKS CLUSTERS:\n")
    for c in clusters:
        print(c)
    print()


def eks_nodegroups(cluster):
    ng = eks.list_nodegroups(clusterName=cluster)["nodegroups"]
    print(f"\nNodegroups for cluster {cluster}:\n")
    for n in ng:
        print(n)
    print()


def eks_get_all_sgs(cluster):
    """Fetch NodeGroup SGs + Cluster SG"""
    sgs = set()

    # Nodegroup SGs
    ngs = eks.list_nodegroups(clusterName=cluster)["nodegroups"]
    for ng in ngs:
        desc = eks.describe_nodegroup(clusterName=cluster, nodegroupName=ng)
        if "remoteAccess" in desc["nodegroup"]:
            for sg in desc["nodegroup"]["remoteAccess"]["securityGroups"]:
                sgs.add(sg)

    # Cluster SG
    c = eks.describe_cluster(name=cluster)
    cluster_sg = c["cluster"]["resourcesVpcConfig"]["clusterSecurityGroupId"]
    sgs.add(cluster_sg)

    print(f"\nSGs for EKS cluster {cluster}:")
    for sg in sgs:
        print(" →", sg)
    print()

    return list(sgs)


def eks_add_ingress(cluster, protocol, port, cidr):
    sgs = eks_get_all_sgs(cluster)
    print(f"\nUpdating EKS SGs for {cluster}")
    for sg in sgs:
        add_ingress(sg, protocol, port, cidr)
    success("EKS SG update complete.")


# ======================================================
# ALB OPERATIONS
# ======================================================
def alb_list():
    lbs = elbv2.describe_load_balancers()["LoadBalancers"]
    print("\nALBs:\n")
    for lb in lbs:
        if lb["Type"] == "application":
            print(f"{lb['LoadBalancerName']}  {lb['LoadBalancerArn']}")
    print()


def alb_sg():
    lbs = elbv2.describe_load_balancers()["LoadBalancers"]
    print("\nALB Security Groups:\n")
    for lb in lbs:
        if lb["Type"] == "application":
            for sg in lb["SecurityGroups"]:
                print(f"{lb['LoadBalancerName']} → {sg}")
    print()


def alb_add_ingress(protocol, port, cidr):
    lbs = elbv2.describe_load_balancers()["LoadBalancers"]
    print("\nUpdating ALB SGs:\n")
    for lb in lbs:
        if lb["Type"] == "application":
            for sg in lb["SecurityGroups"]:
                print(" → Updating", sg)
                add_ingress(sg, protocol, port, cidr)
    success("ALB SG update complete.")


# ======================================================
# FULL CLUSTER-WIDE UPDATE: EKS + ALB
# ======================================================
def eks_add_ingress_all(cluster, protocol, port, cidr):
    print(f"\nApplying ingress {protocol}:{port} from {cidr} to EKS + ALB")

    # EKS SGs (nodegroups + cluster SG)
    eks_add_ingress(cluster, protocol, port, cidr)

    # ALBs (all application load balancers in the account/region)
    alb_add_ingress(protocol, port, cidr)

    success("EKS + ALB update complete.")


# ======================================================
# MAIN
# ======================================================
def main():
    if len(sys.argv) < 2:
        show_usage()
        return

    cmd = sys.argv[1]

    if cmd == "help":
        show_usage()

    elif cmd == "list-instances":
        list_instances()

    elif cmd == "list-sg":
        list_sg()

    elif cmd == "find-sg":
        if len(sys.argv) < 3:
            error("Missing instance-id")
        find_sg(sys.argv[2])

    elif cmd == "add-ingress":
        if len(sys.argv) < 6:
            error("Usage: add-ingress <sg-id> <protocol> <port> <cidr>")
        add_ingress(sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5])

    elif cmd == "del-ingress":
        if len(sys.argv) < 6:
            error("Usage: del-ingress <sg-id> <protocol> <port> <cidr>")
        del_ingress(sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5])

    # EKS
    elif cmd == "eks-list":
        eks_list_clusters()

    elif cmd == "eks-nodegroups":
        if len(sys.argv) < 3:
            error("Usage: eks-nodegroups <cluster>")
        eks_nodegroups(sys.argv[2])

    elif cmd == "eks-all-sg":
        if len(sys.argv) < 3:
            error("Usage: eks-all-sg <cluster>")
        eks_get_all_sgs(sys.argv[2])

    elif cmd == "eks-add-ingress":
        if len(sys.argv) < 6:
            error("Usage: eks-add-ingress <cluster> <protocol> <port> <cidr>")
        eks_add_ingress(sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5])

    # ALB
    elif cmd == "alb-list":
        alb_list()

    elif cmd == "alb-sg":
        alb_sg()

    elif cmd == "alb-add-ingress":
        if len(sys.argv) < 5:
            error("Usage: alb-add-ingress <protocol> <port> <cidr>")
        alb_add_ingress(sys.argv[2], int(sys.argv[3]), sys.argv[4])

    # FULL (EKS + ALB)
    elif cmd == "eks-add-ingress-all":
        if len(sys.argv) < 6:
            error("Usage: eks-add-ingress-all <cluster> <protocol> <port> <cidr>")
        eks_add_ingress_all(sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5])

    else:
        error("Invalid command. Use: python3 sgtool.py help")


if __name__ == "__main__":
    main()
