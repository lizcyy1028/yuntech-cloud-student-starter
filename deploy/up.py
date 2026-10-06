#!/usr/bin/env python3
"""W3: create one SG, one imported key pair and one instance running the committed service."""
import argparse
from pathlib import Path
import shutil
import time

import labctl
from labctl import LabError, aws
import make_user_data

AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


def routes_to_igw(cfg, vpc_id, subnet_id):
    """Check the route table the subnet actually uses (explicit association, else main)."""
    tables = aws(cfg, "ec2", "describe-route-tables", "--filters",
                 f"Name=association.subnet-id,Values={subnet_id}")["RouteTables"]
    if not tables:
        tables = aws(cfg, "ec2", "describe-route-tables", "--filters", f"Name=vpc-id,Values={vpc_id}",
                     "Name=association.main,Values=true")["RouteTables"]
    return any(route.get("DestinationCidrBlock") == "0.0.0.0/0" and route.get("GatewayId", "").startswith("igw-")
               for table in tables for route in table["Routes"])


def plan(cfg):
    vpcs = aws(cfg, "ec2", "describe-vpcs", "--filters", "Name=is-default,Values=true")["Vpcs"]
    if not vpcs:
        raise LabError("No default VPC; stop and ask for help instead of creating one.")
    vpc_id = vpcs[0]["VpcId"]
    subnets = aws(cfg, "ec2", "describe-subnets", "--filters", f"Name=vpc-id,Values={vpc_id}",
                  "Name=default-for-az,Values=true")["Subnets"]
    subnets.sort(key=lambda subnet: subnet["AvailabilityZone"])
    wanted = cfg.get("az")
    subnet = next((s for s in subnets if not wanted or s["AvailabilityZone"] == wanted), None)
    if subnet is None:
        raise LabError("No default subnet in the requested AZ.")
    if not routes_to_igw(cfg, vpc_id, subnet["SubnetId"]):
        raise LabError("The subnet's route table has no 0.0.0.0/0 -> igw route; stop and ask for help.")
    ami = aws(cfg, "ssm", "get-parameter", "--name", AMI_PARAMETER)["Parameter"]["Value"]
    image = aws(cfg, "ec2", "describe-images", "--image-ids", ami)["Images"][0]
    return {"vpc": vpc_id, "subnet": subnet["SubnetId"], "az": subnet["AvailabilityZone"], "ami": ami,
            "ami_name": image["Name"], "ami_arch": image["Architecture"], "ami_created": image["CreationDate"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("commit", nargs="?", default="HEAD", help="Commit to deploy (default HEAD)")
    parser.add_argument("--confirm", help="Approval token printed by a previous run")
    args = parser.parse_args()
    cfg = labctl.settings()
    labctl.verify(cfg)
    resources = labctl.load_resources()
    if resources.get("instance", {}).get("id"):
        raise LabError("resources.json already lists an instance; one host at a time. Run deploy/down.sh first.")

    sha, user_data = make_user_data.build(args.commit)
    target = plan(cfg)
    name = f"w03-{labctl.prefix(cfg)}-{time.strftime('%Y%m%d%H%M%S', time.gmtime())}"
    public_key = Path(cfg.get("ssh_key", "~/.ssh/id_ed25519")).expanduser().with_suffix(".pub")
    if not public_key.is_file():
        raise LabError("SSH public key not found next to ssh_key; generate an ed25519 key first.")
    labctl.confirm(
        "Will CREATE (us-east-1 on-demand EC2, EBS and public IPv4 are billed while they exist):\n"
        f"  security group  {name} in {target['vpc']}: TCP 22 and 80 from {', '.join(cfg['source_cidrs'])}\n"
        f"  key pair        {name} (imports the public key only)\n"
        f"  instance        t3.micro, {target['ami_name']} ({target['ami_arch']}, {target['ami_created']})\n"
        f"                  subnet {target['subnet']} ({target['az']}), 8 GiB gp3 encrypted root, IMDSv2 required\n"
        f"  commit          {sha}\n"
        "Remove later with: bash deploy/down.sh",
        f"up-{sha[:7]}", args.confirm)

    group_id = aws(cfg, "ec2", "create-security-group", "--group-name", name,
                   "--description", "W3 inspection host: SSH and HTTP from the listed sources only",
                   "--vpc-id", target["vpc"],
                   "--tag-specifications", labctl.tag_spec(cfg, "w03", "security-group"))["GroupId"]
    resources["security_group"] = {"id": group_id, "name": name, "created": labctl.utc_now()}
    labctl.save_resources(resources)
    ranges = ",".join(f"{{CidrIp={cidr}}}" for cidr in cfg["source_cidrs"])
    aws(cfg, "ec2", "authorize-security-group-ingress", "--group-id", group_id, "--ip-permissions",
        f"IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{ranges}]",
        f"IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges=[{ranges}]")

    # The public key is not a secret; a relative copy keeps the fileb:// argument simple.
    key_copy = labctl.LOCAL / "ssh-public-key.pub"
    shutil.copyfile(public_key, key_copy)
    key_id = aws(cfg, "ec2", "import-key-pair", "--key-name", name,
                 "--public-key-material", "fileb://.local/ssh-public-key.pub",
                 "--tag-specifications", labctl.tag_spec(cfg, "w03", "key-pair"))["KeyPairId"]
    resources["key_pair"] = {"id": key_id, "name": name, "created": labctl.utc_now()}
    labctl.save_resources(resources)

    user_data_file = labctl.LOCAL / "user-data.sh"
    user_data_file.write_bytes(user_data)
    # file:// hands the raw script to the CLI, which base64-encodes it once for RunInstances.
    instance_id = aws(
        cfg, "ec2", "run-instances", "--count", "1", "--image-id", target["ami"],
        "--instance-type", "t3.micro", "--key-name", name, "--security-group-ids", group_id,
        "--subnet-id", target["subnet"], "--user-data", "file://.local/user-data.sh",
        "--metadata-options", "HttpTokens=required,HttpEndpoint=enabled",
        "--block-device-mappings",
        "DeviceName=/dev/xvda,Ebs={VolumeSize=8,VolumeType=gp3,Encrypted=true,DeleteOnTermination=true}",
        "--tag-specifications", labctl.tag_spec(cfg, "w03", "instance", "volume", "network-interface"),
    )["Instances"][0]["InstanceId"]
    resources["instance"] = {"id": instance_id, "commit": sha, "created": labctl.utc_now()}
    labctl.save_resources(resources)
    print(f"{labctl.utc_now()} created {instance_id}; waiting for running")

    def is_running():
        instance = labctl.describe_instance(cfg, instance_id)
        return instance if instance["State"]["Name"] == "running" and instance.get("PublicIpAddress") else None

    instance, _ = labctl.wait_for(is_running, "instance running", 300, 5)
    resources["volume"] = {"id": instance["BlockDeviceMappings"][0]["Ebs"]["VolumeId"]}
    resources["network_interface"] = {"id": instance["NetworkInterfaces"][0]["NetworkInterfaceId"]}
    labctl.save_resources(resources)
    host = instance["PublicIpAddress"]
    print(f"{labctl.utc_now()} running at {host}; waiting for /health (cloud-init installs the service)")

    with labctl.http_base(cfg, host) as base:
        def is_healthy():
            status, body = labctl.health(base)
            return body if status == 200 and body.get("version") == sha else None

        body, seconds = labctl.wait_for(is_healthy, "/health 200 with the deployed version", 480, 5)
    print(f"{labctl.utc_now()} /health 200 after {seconds}s: {body}")


if __name__ == "__main__":
    raise SystemExit(labctl.run(main))
