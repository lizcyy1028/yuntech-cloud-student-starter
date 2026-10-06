#!/usr/bin/env python3
"""W5: two private subnets, a DB subnet group, SG-db and one private PostgreSQL instance.

Safe to re-run: every created ID is written to .local/resources.json at once, and a step
whose ID is already recorded is skipped, so a second run never builds a second database.
"""
import argparse
import ipaddress
import json
import secrets
import time

import labctl
from labctl import LabError, aws

DB_NAME = "inspection"
DB_USER = "inspection"
DB_ENV = labctl.LOCAL / "db.env"
CREATE_INPUT = labctl.LOCAL / "rds-create.json"


def free_blocks(vpc_cidr, used, count):
    """Highest /24 blocks of the VPC range that overlap no existing subnet."""
    taken = [ipaddress.ip_network(cidr) for cidr in used]
    blocks = []
    for block in reversed(list(ipaddress.ip_network(vpc_cidr).subnets(new_prefix=24))):
        if not any(block.overlaps(other) for other in taken):
            blocks.append(str(block))
            if len(blocks) == count:
                return blocks
    raise LabError("No free /24 blocks left in the VPC range.")


def pick_zones(cfg, host_zone):
    """Two different AZs, preferring the host's, limited to AZs that offer db.t3.micro."""
    zones = sorted(zone["ZoneName"] for zone in aws(
        cfg, "ec2", "describe-availability-zones", "--filters", "Name=state,Values=available")["AvailabilityZones"])
    try:
        offered = set(aws(cfg, "rds", "describe-orderable-db-instance-options", "--engine", "postgres",
                          "--db-instance-class", "db.t3.micro", "--max-items", "5", "--query",
                          "OrderableDBInstanceOptions[].AvailabilityZones[].Name"))
    except LabError:
        offered = set()
    usable = [zone for zone in zones if zone in offered] or zones
    usable.sort(key=lambda zone: zone != host_zone)
    if len(usable) < 2:
        raise LabError("Fewer than two usable AZs for the DB subnet group.")
    return usable[:2]


def db_status(cfg, identifier):
    return aws(cfg, "rds", "describe-db-instances", "--db-instance-identifier", identifier)["DBInstances"][0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", help="Approval token printed by a previous run")
    args = parser.parse_args()
    cfg = labctl.settings()
    labctl.verify(cfg)
    resources = labctl.load_resources()
    db = resources.setdefault("db", {})
    instance = labctl.describe_instance(cfg, resources["instance"]["id"])
    vpc_id, host_zone = instance["VpcId"], instance["Placement"]["AvailabilityZone"]
    host_group = instance["SecurityGroups"][0]["GroupId"]
    name = f"w05-{labctl.prefix(cfg)}"

    if "subnets" not in db:
        vpc_cidr = aws(cfg, "ec2", "describe-vpcs", "--vpc-ids", vpc_id)["Vpcs"][0]["CidrBlock"]
        existing = aws(cfg, "ec2", "describe-subnets", "--filters", f"Name=vpc-id,Values={vpc_id}")["Subnets"]
        blocks = free_blocks(vpc_cidr, [subnet["CidrBlock"] for subnet in existing], 2)
        db["plan"] = [{"cidr": cidr, "az": zone} for cidr, zone in zip(blocks, pick_zones(cfg, host_zone))]
    plan = db["plan"]

    labctl.confirm(
        "Will CREATE in VPC " + vpc_id + " (steps already recorded in resources.json are skipped):\n"
        + "".join(f"  private subnet   {item['cidr']} in {item['az']}\n" for item in plan)
        + "  route table      local route only, explicitly associated with both subnets\n"
        f"  security group   {name}-db: TCP 5432 from the host SG {host_group} only\n"
        f"  DB subnet group  {name}\n"
        f"  RDS instance     {name}: PostgreSQL, db.t3.micro, 20 GiB gp3, encrypted, single-AZ,\n"
        f"                   NOT publicly accessible, initial database {DB_NAME}\n"
        "  cost             RDS instance hours and 20 GiB storage are billed (storage even while stopped)\n"
        "  duration         about 8 minutes until available\n"
        "Remove later with: bash deploy/db-down.sh",
        f"db-up-{name}", args.confirm)
    labctl.save_resources(resources)

    if "subnets" not in db:
        db["subnets"] = []
    for item in plan[len(db["subnets"]):]:
        subnet_id = aws(cfg, "ec2", "create-subnet", "--vpc-id", vpc_id, "--cidr-block", item["cidr"],
                        "--availability-zone", item["az"],
                        "--tag-specifications", labctl.tag_spec(cfg, "w05", "subnet"))["Subnet"]["SubnetId"]
        db["subnets"].append(subnet_id)
        labctl.save_resources(resources)
        print(f"{labctl.utc_now()} subnet {subnet_id} {item['cidr']} {item['az']}")

    if "route_table" not in db:
        # A new route table has only the local route. Without the explicit associations the
        # subnets would fall back to the main table, which routes 0.0.0.0/0 to the IGW.
        db["route_table"] = aws(cfg, "ec2", "create-route-table", "--vpc-id", vpc_id, "--tag-specifications",
                                labctl.tag_spec(cfg, "w05", "route-table"))["RouteTable"]["RouteTableId"]
        labctl.save_resources(resources)
        print(f"{labctl.utc_now()} route table {db['route_table']}")
    associations = db.setdefault("associations", [])
    for subnet_id in db["subnets"][len(associations):]:
        associations.append(aws(cfg, "ec2", "associate-route-table", "--route-table-id", db["route_table"],
                                "--subnet-id", subnet_id)["AssociationId"])
        labctl.save_resources(resources)

    if "security_group" not in db:
        db["security_group"] = aws(
            cfg, "ec2", "create-security-group", "--group-name", f"{name}-db",
            "--description", "W5 inspection database: PostgreSQL from the host SG only", "--vpc-id", vpc_id,
            "--tag-specifications", labctl.tag_spec(cfg, "w05", "security-group"))["GroupId"]
        labctl.save_resources(resources)
        print(f"{labctl.utc_now()} SG-db {db['security_group']}")
    if not db.get("ingress"):
        aws(cfg, "ec2", "authorize-security-group-ingress", "--group-id", db["security_group"],
            "--ip-permissions", json.dumps([{
                "IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
                "UserIdGroupPairs": [{"GroupId": host_group, "Description": "inspection host SG"}]}]))
        db["ingress"] = f"tcp/5432 from {host_group}"
        labctl.save_resources(resources)

    if "subnet_group" not in db:
        aws(cfg, "rds", "create-db-subnet-group", "--db-subnet-group-name", name,
            "--db-subnet-group-description", "W5 inspection private subnets",
            "--subnet-ids", *db["subnets"], "--tags", json.dumps(labctl.tags(cfg, "w05")))
        db["subnet_group"] = name
        labctl.save_resources(resources)
        print(f"{labctl.utc_now()} DB subnet group {name}")

    if "instance" not in db:
        # The password is generated here, kept in .local/db.env (600) and handed to the CLI
        # through a short-lived input file: it is never printed and never a command argument.
        if DB_ENV.exists():
            password = labctl.read_env(DB_ENV)["DB_PASSWORD"]
        else:
            password = secrets.token_urlsafe(24)
            labctl.write_private(DB_ENV, f"DB_NAME={DB_NAME}\nDB_USER={DB_USER}\nDB_PASSWORD={password}\n")
        labctl.write_private(CREATE_INPUT, json.dumps({
            "DBInstanceIdentifier": name, "DBName": DB_NAME, "Engine": "postgres",
            "DBInstanceClass": "db.t3.micro", "AllocatedStorage": 20, "StorageType": "gp3",
            "StorageEncrypted": True, "MultiAZ": False, "PubliclyAccessible": False,
            "MasterUsername": DB_USER, "MasterUserPassword": password,
            "DBSubnetGroupName": db["subnet_group"], "VpcSecurityGroupIds": [db["security_group"]],
            "DeletionProtection": False, "Tags": labctl.tags(cfg, "w05")}))
        try:
            aws(cfg, "rds", "create-db-instance", "--cli-input-json", "file://.local/rds-create.json")
        finally:
            CREATE_INPUT.unlink(missing_ok=True)
        db["instance"] = name
        db["create_started"] = labctl.utc_now()
        labctl.save_resources(resources)
        print(f"{labctl.utc_now()} RDS {name} creating; this takes several minutes. Do not re-run meanwhile.")

    started = time.monotonic()
    def available():
        current = db_status(cfg, db["instance"])
        return current if current["DBInstanceStatus"] == "available" else None

    state, _ = labctl.wait_for(available, "RDS available", 1500, 30)
    endpoint = state["Endpoint"]["Address"]
    if "DB_HOST" not in labctl.read_env(DB_ENV):
        labctl.write_private(DB_ENV, DB_ENV.read_text(encoding="utf-8").rstrip("\n")
                             + f"\nDB_HOST={endpoint}\nDB_PORT={state['Endpoint']['Port']}\n")
    db["endpoint"] = endpoint
    labctl.save_resources(resources)
    print(f"{labctl.utc_now()} read back after waiting {int(time.monotonic() - started)}s in this run "
          f"(creation started {db['create_started']}):")
    print(json.dumps({
        "DBInstanceIdentifier": state["DBInstanceIdentifier"], "DBInstanceStatus": state["DBInstanceStatus"],
        "PubliclyAccessible": state["PubliclyAccessible"], "StorageEncrypted": state["StorageEncrypted"],
        "MultiAZ": state["MultiAZ"], "DBInstanceClass": state["DBInstanceClass"],
        "AllocatedStorage": state["AllocatedStorage"], "StorageType": state["StorageType"],
        "Engine": f"{state['Engine']} {state['EngineVersion']}",
        "AvailabilityZone": state["AvailabilityZone"]}, indent=2))
    if state["PubliclyAccessible"]:
        raise LabError("PubliclyAccessible is true: stop and fix before going further.")
    print("Secrets are in .local/db.env (not shown). Next: bash deploy/deploy.sh")


if __name__ == "__main__":
    raise SystemExit(labctl.run(main))
