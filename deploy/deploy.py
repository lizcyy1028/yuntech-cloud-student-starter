#!/usr/bin/env python3
"""W4-W6: install one committed version on the existing host, then place the secret files."""
import argparse
import subprocess

import labctl
from labctl import LabError
import make_user_data

INSTALL = 'tmp=$(mktemp) && cat > "$tmp" && sudo bash "$tmp"; rc=$?; rm -f "$tmp"; exit $rc'
# Secrets arrive on stdin only; they are never arguments and never echoed.
PLACE_SECRET = ("sudo sh -c 'umask 077 && cat > /etc/inspection/app.env.new"
                " && chown root:root /etc/inspection/app.env.new && chmod 600 /etc/inspection/app.env.new"
                " && mv -f /etc/inspection/app.env.new /etc/inspection/app.env'")
# /etc/inspection itself stays 755 so the service can still reach rds-ca.pem and iot/.
MAKE_IOT_DIR = "sudo install -d -o inspection -g inspection -m 700 /etc/inspection/iot"
# The consumer runs as 'inspection': a file left owned by root would make it restart forever.
PLACE_IOT_FILE = ("sudo sh -c 'umask 077 && cat > /etc/inspection/iot/{name}"
                  " && chown inspection:inspection /etc/inspection/iot/{name}"
                  " && chmod 600 /etc/inspection/iot/{name}'")
IOT_FILES = ("AmazonRootCA1.pem", "consumer.cert.pem", "consumer.private.key")
IOT_DIR = labctl.LOCAL / "iot"


def iot_settings(code):
    """The IOT_ lines for the consumer; paths point at the files placed under /etc/inspection/iot."""
    endpoint = (IOT_DIR / "endpoint").read_text(encoding="utf-8").strip()
    devices = ",".join(f"{code}-d{number:02d}" for number in range(1, 11))
    return (f"IOT_ENDPOINT={endpoint}\nIOT_TOPIC=cxe/{code}/gw/events\nIOT_CLIENT_ID=consumer-{code}\n"
            f"IOT_DEVICE_IDS={devices}\nIOT_CA=/etc/inspection/iot/AmazonRootCA1.pem\n"
            "IOT_CERT=/etc/inspection/iot/consumer.cert.pem\nIOT_KEY=/etc/inspection/iot/consumer.private.key\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("commit", nargs="?", default="HEAD", help="Commit to deploy (default HEAD)")
    parser.add_argument("--confirm", help="Approval token printed by a previous run")
    args = parser.parse_args()
    cfg = labctl.settings()
    labctl.verify(cfg)
    instance = labctl.running_host(cfg, labctl.load_resources())
    instance_id, host = instance["InstanceId"], instance["PublicIpAddress"]

    sha, user_data = make_user_data.build(args.commit)
    secret_files = [labctl.LOCAL / "app.env"]
    if (labctl.LOCAL / "db.env").exists():
        secret_files.append(labctl.LOCAL / "db.env")
    names = []
    for path in secret_files:
        labctl.require_private(path)
        names.extend(labctl.read_env(path))
    for required in ("REPORTER_TOKEN", "OPERATOR_TOKEN"):
        if required not in names:
            raise LabError(f".local/app.env has no {required}; generate the tokens first (see labs/04).")
    has_db = "DB_HOST" in names
    secret = "".join(path.read_text(encoding="utf-8").replace("\r\n", "\n").rstrip("\n") + "\n"
                     for path in secret_files)

    # W6: the consumer is deployed once its code is in the commit and iot-up.sh has run.
    in_commit = subprocess.run(["git", "cat-file", "-e", sha + ":app/consumer.py"], cwd=labctl.ROOT,
                               stderr=subprocess.DEVNULL, check=False).returncode == 0
    has_iot = in_commit and (IOT_DIR / "endpoint").is_file()
    if has_iot:
        for name in IOT_FILES:
            labctl.require_private(IOT_DIR / name)
        iot_lines = iot_settings(labctl.prefix(cfg))
        names.extend(labctl.read_env_text(iot_lines))
        secret += iot_lines
    services = "inspection inspection-consumer" if has_iot else "inspection"
    uncommitted = subprocess.run(
        ["git", "status", "--porcelain", "--", "app/service.py", "app/consumer.py", "deploy/nginx.conf"],
        cwd=labctl.ROOT, capture_output=True, text=True, check=True).stdout.strip()

    labctl.confirm(
        "Will DEPLOY to the existing host (no new AWS resources):\n"
        f"  instance   {instance_id} at {host}\n"
        f"  commit     {sha}\n"
        f"  secrets    {', '.join(path.name for path in secret_files)}"
        f"{' + IOT settings' if has_iot else ''} -> /etc/inspection/app.env (keys: {', '.join(names)})\n"
        + (f"  iot files  {', '.join(IOT_FILES)} -> /etc/inspection/iot (700, owner inspection, files 600)\n"
           if has_iot else "")
        + ("  NOTE       uncommitted changes to the packaged files are NOT deployed\n" if uncommitted else "")
        + f"  effect     reinstalls the service files and restarts {services}",
        f"deploy-{sha[:7]}-{instance_id[-4:]}", args.confirm)

    labctl.ssh_run(cfg, host, INSTALL, stdin=user_data, label="service install")
    if has_iot:
        labctl.ssh_run(cfg, host, MAKE_IOT_DIR, label="iot directory")
        for name in IOT_FILES:
            labctl.ssh_run(cfg, host, PLACE_IOT_FILE.format(name=name), stdin=(IOT_DIR / name).read_bytes(),
                           label=f"iot file {name}")
    labctl.ssh_run(cfg, host, PLACE_SECRET, stdin=secret.encode("utf-8"), label="secret file placement")
    # Restart last so the services read the new secrets; the pause lets a crash loop show up.
    active = labctl.ssh_run(cfg, host, f"sudo systemctl restart {services} && sleep 4; systemctl is-active {services}",
                            label="service restart", allow_failure=True)
    print(f"systemctl is-active {services}: {' '.join(active.split())}")

    with labctl.http_base(cfg, host) as base:
        def deployed():
            status, body = labctl.health(base)
            ready = (status == 200 and body.get("version") == sha and body.get("auth_configured") is True
                     and (not has_db or body.get("db_configured") is True))
            return body if ready else None

        expected = "version, auth_configured" + (", db_configured" if has_db else "")
        body, _ = labctl.wait_for(deployed, f"/health 200 with matching {expected}", 60, 3)
    print(f"{labctl.utc_now()} /health 200: {body}")
    if active.split() != ["active"] * len(services.split()):
        raise LabError("A service is not active; check it with: sudo journalctl -u inspection-consumer -n 30")


if __name__ == "__main__":
    raise SystemExit(labctl.run(main))
