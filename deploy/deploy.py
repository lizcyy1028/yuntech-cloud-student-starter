#!/usr/bin/env python3
"""W4/W5: install one committed version on the existing host, then place the secret file."""
import argparse
import subprocess

import labctl
from labctl import LabError
import make_user_data

INSTALL = 'tmp=$(mktemp) && cat > "$tmp" && sudo bash "$tmp"; rc=$?; rm -f "$tmp"; exit $rc'
# The secret arrives on stdin only; it is never an argument and never echoed.
PLACE_SECRET = ("sudo sh -c 'umask 077 && cat > /etc/inspection/app.env.new"
                " && chown root:root /etc/inspection/app.env.new && chmod 600 /etc/inspection/app.env.new"
                " && mv -f /etc/inspection/app.env.new /etc/inspection/app.env"
                " && systemctl restart inspection'")


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
                     for path in secret_files).encode("utf-8")
    uncommitted = subprocess.run(["git", "status", "--porcelain", "--", "app/service.py", "deploy/nginx.conf"],
                                 cwd=labctl.ROOT, capture_output=True, text=True, check=True).stdout.strip()

    labctl.confirm(
        "Will DEPLOY to the existing host (no new AWS resources):\n"
        f"  instance   {instance_id} at {host}\n"
        f"  commit     {sha}\n"
        f"  secrets    {', '.join(path.name for path in secret_files)} -> /etc/inspection/app.env"
        f" (keys: {', '.join(names)})\n"
        + ("  NOTE       uncommitted changes to the packaged files are NOT deployed\n" if uncommitted else "")
        + "  effect     reinstalls the service files and restarts inspection",
        f"deploy-{sha[:7]}-{instance_id[-4:]}", args.confirm)

    labctl.ssh_run(cfg, host, INSTALL, stdin=user_data, label="service install")
    labctl.ssh_run(cfg, host, PLACE_SECRET, stdin=secret, label="secret file placement")

    with labctl.http_base(cfg, host) as base:
        def deployed():
            status, body = labctl.health(base)
            ready = (status == 200 and body.get("version") == sha and body.get("auth_configured") is True
                     and (not has_db or body.get("db_configured") is True))
            return body if ready else None

        expected = "version, auth_configured" + (", db_configured" if has_db else "")
        body, _ = labctl.wait_for(deployed, f"/health 200 with matching {expected}", 60, 3)
    print(f"{labctl.utc_now()} /health 200: {body}")


if __name__ == "__main__":
    raise SystemExit(labctl.run(main))
