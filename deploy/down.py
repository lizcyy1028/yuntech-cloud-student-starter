#!/usr/bin/env python3
"""W3: stop, or terminate and clean up, exactly the host recorded in .local/resources.json."""
import argparse

import labctl
from labctl import LabError, aws


def instance_state(cfg, instance_id):
    return labctl.describe_instance(cfg, instance_id)["State"]["Name"]


def stop(cfg, instance_id):
    aws(cfg, "ec2", "stop-instances", "--instance-ids", instance_id)
    labctl.wait_for(lambda: instance_state(cfg, instance_id) == "stopped", "instance stopped", 300, 5)
    print(f"{labctl.utc_now()} read back: {instance_id} stopped (EBS still exists and may be billed)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stop", action="store_true", help="Only stop the instance; delete nothing")
    parser.add_argument("--confirm", help="Approval token printed by a previous run")
    args = parser.parse_args()
    cfg = labctl.settings()
    labctl.verify(cfg)
    resources = labctl.load_resources()
    instance_id = resources.get("instance", {}).get("id")
    if not instance_id:
        raise LabError("No instance in .local/resources.json; nothing to do.")
    instance = labctl.describe_instance(cfg, instance_id)
    if not labctl.owned(cfg, instance.get("Tags")):
        raise LabError(f"{instance_id} does not carry this owner's course tags; refusing to touch it.")

    if args.stop:
        labctl.confirm(f"Will STOP (not delete) instance {instance_id}; its public address is released.",
                       f"stop-{instance_id[-4:]}", args.confirm)
        stop(cfg, instance_id)
        return

    if resources.get("db"):
        raise LabError("W5 database resources still reference this host's SG; run deploy/db-down.sh first.")
    group_id = resources["security_group"]["id"]
    key_id = resources["key_pair"]["id"]
    volume_id = resources["volume"]["id"]
    interface_id = resources["network_interface"]["id"]
    group = aws(cfg, "ec2", "describe-security-groups", "--group-ids", group_id)["SecurityGroups"][0]
    key = aws(cfg, "ec2", "describe-key-pairs", "--key-pair-ids", key_id)["KeyPairs"][0]
    for label, tag_list in (("security group", group.get("Tags")), ("key pair", key.get("Tags"))):
        if not labctl.owned(cfg, tag_list):
            raise LabError(f"The {label} does not carry this owner's course tags; refusing to delete.")
    labctl.confirm(
        "Will DELETE, by ID only:\n"
        f"  instance           {instance_id} (terminate)\n"
        f"  root volume        {volume_id} (deleted with the instance)\n"
        f"  network interface  {interface_id} (deleted with the instance)\n"
        f"  security group     {group_id}\n"
        f"  key pair           {key_id} ({key['KeyName']})",
        f"down-{instance_id[-4:]}", args.confirm)

    aws(cfg, "ec2", "terminate-instances", "--instance-ids", instance_id)
    labctl.wait_for(lambda: instance_state(cfg, instance_id) == "terminated", "instance terminated", 420, 5)

    def group_deleted():
        try:
            aws(cfg, "ec2", "delete-security-group", "--group-id", group_id)
        except LabError as exc:
            code = labctl.aws_code(exc)
            if "NotFound" in code:
                return True
            if code == "DependencyViolation":  # the ENI is still detaching
                return False
            raise
        return True

    labctl.wait_for(group_deleted, "security group deletion", 180, 5)
    aws(cfg, "ec2", "delete-key-pair", "--key-pair-id", key_id)

    checks = {
        "root volume": ("ec2", "describe-volumes", "--volume-ids", volume_id),
        "network interface": ("ec2", "describe-network-interfaces", "--network-interface-ids", interface_id),
        "security group": ("ec2", "describe-security-groups", "--group-ids", group_id),
        "key pair": ("ec2", "describe-key-pairs", "--key-pair-ids", key_id),
    }
    print(f"{labctl.utc_now()} read back: instance {instance_id} terminated")
    remaining = []
    for label, call in checks.items():
        absent = labctl.gone(cfg, *call)
        print(f"{labctl.utc_now()} read back: {label} {'not found' if absent else 'STILL EXISTS'}")
        if not absent:
            remaining.append(label)
    if remaining:
        raise LabError("Still present: " + ", ".join(remaining) + ". The ledger was kept; inspect and retry.")
    for key_name in ("instance", "volume", "network_interface", "security_group", "key_pair"):
        resources.pop(key_name, None)
    labctl.save_resources(resources)


if __name__ == "__main__":
    raise SystemExit(labctl.run(main))
