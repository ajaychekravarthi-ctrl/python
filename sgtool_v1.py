#!/usr/bin/env python3

import boto3
import sys
import os
import json
from datetime import datetime
from botocore.exceptions import ClientError

# ======================================================
# AWS Clients
# ======================================================
ec2 = boto3.client("ec2")
eks = boto3.client("eks")
elbv2 = boto3.client("elbv2")

BACKUP_DIR = "sg_backups"

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
  python sgtool.py list-instances

Find SGs attached to EC2:
  python sgtool.py find-sg <instance-id>

List EC2 ingress rules (aggregated):
  python sgtool.py ec2-ingress <instance-id>


SECURITY GROUP OPERATIONS
-------------------------------------------
List ALL Security Groups:
  python sgtool.py list-sg

List ingress rules on SG:
  python sgtool.py list-ingress <sg-id>

Add ingress rule:
  python sgtool.py add-ingress <sg-id> <protocol> <port> <cidr>

Delete ingress rule:
  python sgtool.py del-ingress <sg-id> <protocol> <port> <cidr>


EKS OPERATIONS
-------------------------------------------
List EKS Clusters:
  python sgtool.py eks-list

List Nodegroups:
  python sgtool.py eks-nodegroups <cluster>

List ALL SGs used by EKS:
  python sgtool.py eks-all-sg <cluster>

Add ingress to ALL EKS SGs:
  python sgtool.py eks-add-ingress <cluster> <protocol> <port> <cidr>


ALB OPERATIONS
-------------------------------------------
List ALBs:
  python sgtool.py alb-list

List ALB SGs:
  python sgtool.py alb-sg

Add ingress to ALL ALB SGs:
  python sgtool.py alb-add-ingress <protocol> <port> <cidr>


FULL OPERATION
-------------------------------------------
Add ingress to ALL SGs (EKS + ALB):
  python sgtool.py eks-add-ingress-all <cluster> <protocol> <port> <cidr>
=====================================================
""")

# ======================================================
# Backup Logic
# ======================================================
def backup_sg_rules(group_id, action):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    sg = get_sg(group_id)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"{BACKUP_DIR}/{group_id}_{action}_{timestamp}.json"

    backup = {
        "security_group_id": group_id,
        "security_group_name": sg.get("GroupName"),
        "action": action,
        "timestamp_utc": timestamp,
        "ingress_rules": sg.get("IpPermissions", [])
    }

    with open(filename, "w") as f:
        json.dump(backup, f, indent=2)

    print(f"[BACKUP] Existing rules saved → {filename}")

# ======================================================
# Security Group Core
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

def list_ingress_rules(group_id):
    sg = get_sg(group_id)
    print(f"\nIngress rules for SG {group_id}:\n")

    if not sg.get("IpPermissions"):
        print("  (No ingress rules)")
        return

    for perm in sg["IpPermissions"]:
        proto = perm.get("IpProtocol")
        fp = perm.get("FromPort", "ALL")
        tp = perm.get("ToPort", "ALL")
        for ip in perm.get("IpRanges", []):
            cidr = ip.get("CidrIp")
            desc = ip.get("Description", "")
            print(f"  {proto:<5} {fp}-{tp:<7} {cidr:<18} {desc}")

def add_ingress(group_id, protocol, port, cidr):
    sg = get_sg(group_id)

    if rule_exists(sg, protocol, port, cidr):
        print(f"[NOTICE] Rule already exists on {group_id}")
        list_ingress_rules(group_id)
        return

    backup_sg_rules(group_id, "before_add")

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
    backup_sg_rules(group_id, "before_delete")

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
            print(f"{inst['InstanceId']:<20} {name}")
    print()

def find_sg(instance_id):
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    inst = resp["Reservations"][0]["Instances"][0]
    print("\nAttached Security Groups:\n")
    for sg in inst["SecurityGroups"]:
        print(f"{sg['GroupId']}  {sg['GroupName']}")

def list_ec2_ingress(instance_id):
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    inst = resp["Reservations"][0]["Instances"][0]

    print(f"\nAggregated ingress rules for EC2 {instance_id}:\n")

    for sg in inst["SecurityGroups"]:
        sg_id = sg["GroupId"]
        sg_name = sg["GroupName"]
        print(f"Security Group: {sg_name} ({sg_id})")

        sg_details = get_sg(sg_id)
        if not sg_details.get("IpPermissions"):
            print("  (No ingress rules)")
            continue

        for perm in sg_details["IpPermissions"]:
            proto = perm.get("IpProtocol")
            fp = perm.get("FromPort", "ALL")
            tp = perm.get("ToPort", "ALL")
            for ip in perm.get("IpRanges", []):
                cidr = ip.get("CidrIp")
                desc = ip.get("Description", "")
                print(f"  {proto:<5} {fp}-{tp:<7} {cidr:<18} {desc}")
        print()

# ======================================================
# EKS OPERATIONS
# ======================================================
def eks_list_clusters():
    print("\nEKS CLUSTERS:\n")
    for c in eks.list_clusters()["clusters"]:
        print(c)
    print()

def eks_nodegroups(cluster):
    print(f"\nNodegroups for {cluster}:\n")
    for ng in eks.list_nodegroups(clusterName=cluster)["nodegroups"]:
        print(ng)
    print()

def eks_get_all_sgs(cluster):
    sgs = set()

    for ng in eks.list_nodegroups(clusterName=cluster)["nodegroups"]:
        desc = eks.describe_nodegroup(clusterName=cluster, nodegroupName=ng)
        if "remoteAccess" in desc["nodegroup"]:
            sgs.update(desc["nodegroup"]["remoteAccess"]["securityGroups"])

    c = eks.describe_cluster(name=cluster)
    sgs.add(c["cluster"]["resourcesVpcConfig"]["clusterSecurityGroupId"])

    print(f"\nSGs for EKS cluster {cluster}:")
    for sg in sgs:
        print(" →", sg)

    return list(sgs)

def eks_add_ingress(cluster, protocol, port, cidr):
    for sg in eks_get_all_sgs(cluster):
        add_ingress(sg, protocol, port, cidr)
    success("EKS SG update complete.")

# ======================================================
# ALB OPERATIONS
# ======================================================
def alb_list():
    print("\nALBs:\n")
    for lb in elbv2.describe_load_balancers()["LoadBalancers"]:
        if lb["Type"] == "application":
            print(lb["LoadBalancerName"], lb["LoadBalancerArn"])
    print()

def alb_sg():
    print("\nALB Security Groups:\n")
    for lb in elbv2.describe_load_balancers()["LoadBalancers"]:
        if lb["Type"] == "application":
            for sg in lb["SecurityGroups"]:
                print(lb["LoadBalancerName"], "→", sg)
    print()

def alb_add_ingress(protocol, port, cidr):
    for lb in elbv2.describe_load_balancers()["LoadBalancers"]:
        if lb["Type"] == "application":
            for sg in lb["SecurityGroups"]:
                add_ingress(sg, protocol, port, cidr)
    success("ALB SG update complete.")

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
    elif cmd == "find-sg":
        find_sg(sys.argv[2])
    elif cmd == "ec2-ingress":
        list_ec2_ingress(sys.argv[2])
    elif cmd == "list-sg":
        list_sg()
    elif cmd == "list-ingress":
        list_ingress_rules(sys.argv[2])
    elif cmd == "add-ingress":
        add_ingress(sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5])
    elif cmd == "del-ingress":
        del_ingress(sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5])
    elif cmd == "eks-list":
        eks_list_clusters()
    elif cmd == "eks-nodegroups":
        eks_nodegroups(sys.argv[2])
    elif cmd == "eks-all-sg":
        eks_get_all_sgs(sys.argv[2])
    elif cmd == "eks-add-ingress":
        eks_add_ingress(sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5])
    elif cmd == "alb-list":
        alb_list()
    elif cmd == "alb-sg":
        alb_sg()
    elif cmd == "alb-add-ingress":
        alb_add_ingress(sys.argv[2], int(sys.argv[3]), sys.argv[4])
    elif cmd == "eks-add-ingress-all":
        eks_add_ingress(sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5])
    else:
        error("Invalid command")

if __name__ == "__main__":
    main()
