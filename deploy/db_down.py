#!/usr/bin/env python3
"""W5: stop, start, or delete exactly the database resources recorded in .local/resources.json."""
import argparse

import labctl
from labctl import LabError, aws


def status(cfg, identifier):
    return aws(cfg, "rds", "describe-db-instances", "--db-instance-identifier",
               identifier)["DBInstances"][0]["DBInstanceStatus"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--stop", action="store_true", help="Only stop the RDS instance; delete nothing")
    mode.add_argument("--start", action="store_true", help="Start the stopped RDS instance")
    parser.add_argument("--confirm", help="Approval token printed by a previous run")
    args = parser.parse_args()
    cfg = labctl.settings()
    labctl.verify(cfg)
    resources = labctl.load_resources()
    db = resources.get("db") or {}
    if not db:
        raise LabError("No database resources in .local/resources.json; nothing to do.")
    identifier = db.get("instance")

    if args.stop or args.start:
        if not identifier:
            raise LabError("No RDS instance recorded.")
        verb, target = ("stop", "stopped") if args.stop else ("start", "available")
        note = ("storage stays billed, and AWS starts it again by itself after 7 days" if args.stop
                else "instance hours are billed again")
        labctl.confirm(f"Will {verb.upper()} RDS instance {identifier} ({note}).",
                       f"db-{verb}-{identifier}", args.confirm)
        aws(cfg, "rds", f"{verb}-db-instance", "--db-instance-identifier", identifier)
        labctl.wait_for(lambda: status(cfg, identifier) == target, f"RDS {target}", 1500, 30)
        print(f"{labctl.utc_now()} read back: {identifier} {target}")
        return

    if identifier:
        arn = aws(cfg, "rds", "describe-db-instances", "--db-instance-identifier",
                  identifier)["DBInstances"][0]["DBInstanceArn"]
        if not labctl.owned(cfg, aws(cfg, "rds", "list-tags-for-resource", "--resource-name", arn)["TagList"]):
            raise LabError("The RDS instance does not carry this owner's course tags; refusing to delete.")
    labctl.confirm(
        "Will DELETE, by recorded ID only (the database content is lost; no final snapshot):\n"
        f"  RDS instance     {identifier or '-'}\n"
        f"  DB subnet group  {db.get('subnet_group', '-')}\n"
        f"  security group   {db.get('security_group', '-')}\n"
        f"  route table      {db.get('route_table', '-')}\n"
        f"  subnets          {', '.join(db.get('subnets', [])) or '-'}",
        f"db-down-{identifier or 'network'}", args.confirm)

    def absent(*call):
        return labctl.gone(cfg, *call)

    if identifier:
        describe = ("rds", "describe-db-instances", "--db-instance-identifier", identifier)
        if not absent(*describe):
            aws(cfg, "rds", "delete-db-instance", "--db-instance-identifier", identifier,
                "--skip-final-snapshot", "--delete-automated-backups")
            labctl.wait_for(lambda: absent(*describe), "RDS instance deletion", 1500, 30)
        print(f"{labctl.utc_now()} read back: RDS {identifier} not found")
        del db["instance"]
        labctl.save_resources(resources)
    if db.get("subnet_group"):
        if not absent("rds", "describe-db-subnet-groups", "--db-subnet-group-name", db["subnet_group"]):
            aws(cfg, "rds", "delete-db-subnet-group", "--db-subnet-group-name", db["subnet_group"])
        del db["subnet_group"]
        labctl.save_resources(resources)
    if db.get("security_group"):
        if not absent("ec2", "describe-security-groups", "--group-ids", db["security_group"]):
            aws(cfg, "ec2", "delete-security-group", "--group-id", db["security_group"])
        del db["security_group"]
        db.pop("ingress", None)
        labctl.save_resources(resources)
    while db.get("associations"):
        try:
            aws(cfg, "ec2", "disassociate-route-table", "--association-id", db["associations"][-1])
        except LabError as exc:
            if "NotFound" not in labctl.aws_code(exc):
                raise
        db["associations"].pop()
        labctl.save_resources(resources)
    if db.get("route_table"):
        if not absent("ec2", "describe-route-tables", "--route-table-ids", db["route_table"]):
            aws(cfg, "ec2", "delete-route-table", "--route-table-id", db["route_table"])
        del db["route_table"]
        labctl.save_resources(resources)
    while db.get("subnets"):
        subnet_id = db["subnets"][-1]
        if not absent("ec2", "describe-subnets", "--subnet-ids", subnet_id):
            aws(cfg, "ec2", "delete-subnet", "--subnet-id", subnet_id)
        db["subnets"].pop()
        labctl.save_resources(resources)
    del resources["db"]
    labctl.save_resources(resources)
    print(f"{labctl.utc_now()} read back: all recorded database resources are gone. "
          "Delete .local/db.env yourself once it is no longer needed.")


if __name__ == "__main__":
    raise SystemExit(labctl.run(main))
