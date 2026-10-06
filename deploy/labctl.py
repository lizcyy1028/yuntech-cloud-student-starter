#!/usr/bin/env python3
"""Shared helpers for the deploy scripts: settings, AWS calls, resource ledger, SSH, HTTP."""
import contextlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import lab  # noqa: E402  (course helper: clean_env / run_aws)

LOCAL = ROOT / ".local"
SETTINGS = LOCAL / "settings.json"
RESOURCES = LOCAL / "resources.json"
LabError = lab.LabError


def settings():
    """Read .local/settings.json (not in Git) and select the AWS profile for run_aws."""
    if not SETTINGS.exists():
        raise LabError("Missing .local/settings.json; copy deploy/settings.example.json and fill it in.")
    cfg = json.loads(SETTINGS.read_text(encoding="utf-8"))
    for key in ("region", "group", "owner", "source_cidrs"):
        if not cfg.get(key):
            raise LabError(f".local/settings.json is missing '{key}'.")
    for cidr in cfg["source_cidrs"]:
        if cidr in ("0.0.0.0/0", "::/0"):
            raise LabError("source_cidrs must not contain 0.0.0.0/0 or ::/0.")
    lab.PROFILE = cfg.get("profile", "learnerlab")
    os.chdir(ROOT)  # so file:// arguments can stay relative
    return cfg


def aws(cfg, *args, raw=False):
    return lab.run_aws(list(args), cfg["region"], raw=raw)


def aws_code(exc):
    """Error code from a LabError raised by run_aws, e.g. InvalidGroup.NotFound."""
    match = re.search(r": ([A-Za-z0-9._-]+)\. Stop;", str(exc))
    return match.group(1) if match else ""


def gone(cfg, *args):
    """True when a describe call reports that the resource no longer exists."""
    try:
        aws(cfg, *args)
    except LabError as exc:
        if "NotFound" in aws_code(exc):
            return True
        raise
    return False


def verify(cfg):
    identity = aws(cfg, "sts", "get-caller-identity")
    if ":assumed-role/" not in identity.get("Arn", ""):
        raise LabError("Expected temporary assumed-role credentials from Learner Lab.")
    last4 = identity["Account"][-4:]
    if cfg.get("account_last4") and cfg["account_last4"] != last4:
        raise LabError("Account mismatch: refusing operations. Compare with the Learner Lab console.")
    print(f"Identity OK: account ending {last4}, region {cfg['region']}, profile {lab.PROFILE}")


def prefix(cfg):
    return f"g{cfg['group']}-m{cfg['owner']}"


def tags(cfg, week):
    values = {"course": lab.COURSE, "week": week, "group": cfg["group"], "owner": cfg["owner"]}
    return [{"Key": key, "Value": value} for key, value in values.items()]


def tag_spec(cfg, week, *resource_types):
    return json.dumps([{"ResourceType": kind, "Tags": tags(cfg, week)} for kind in resource_types])


def owned(cfg, tag_list):
    found = {tag["Key"]: tag["Value"] for tag in tag_list or []}
    return (found.get("course") == lab.COURSE and found.get("group") == cfg["group"]
            and found.get("owner") == cfg["owner"])


def load_resources():
    return json.loads(RESOURCES.read_text(encoding="utf-8")) if RESOURCES.exists() else {}


def save_resources(resources):
    LOCAL.mkdir(exist_ok=True)
    temp = RESOURCES.with_suffix(".json.tmp")
    temp.write_text(json.dumps(resources, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    os.replace(temp, RESOURCES)


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def confirm(description, token, supplied=None):
    """Print the exact change list, then require a token that is specific to this run."""
    print(description)
    if supplied is not None:
        if supplied != token:
            raise LabError("--confirm does not match this run; review the list above. No changes made.")
        print(f"Confirmed with --confirm {token}")
        return
    if not sys.stdin.isatty():
        raise LabError(f"No interactive approval. Review the list above, then re-run with --confirm {token}")
    if input(f"Type exactly {token} to proceed: ").strip() != token:
        raise LabError("Cancelled; no changes made.")


def wait_for(check, what, timeout, interval=10):
    """Poll check() until it returns a truthy value; returns (value, seconds waited)."""
    started = time.monotonic()
    while True:
        value = check()
        if value:
            return value, int(time.monotonic() - started)
        if time.monotonic() - started > timeout:
            raise LabError(f"Timed out after {timeout}s waiting for {what}. Inspect before retrying.")
        time.sleep(interval)


def describe_instance(cfg, instance_id):
    data = aws(cfg, "ec2", "describe-instances", "--instance-ids", instance_id)
    return data["Reservations"][0]["Instances"][0]


def running_host(cfg, resources):
    """Instance from the ledger; it must be running and have a public address right now."""
    instance_id = resources.get("instance", {}).get("id")
    if not instance_id:
        raise LabError("No instance in .local/resources.json; run deploy/up.sh first.")
    instance = describe_instance(cfg, instance_id)
    state = instance["State"]["Name"]
    if state != "running" or not instance.get("PublicIpAddress"):
        raise LabError(f"Instance {instance_id} is {state}; start it and retry.")
    return instance


def read_env(path):
    """KEY=VALUE pairs from a secret file. Callers must never print the values."""
    values = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        key, separator, value = line.strip().partition("=")
        if separator and key and not key.startswith("#"):
            values[key] = value
    return values


def require_private(path):
    """Refuse a secret file that other users can read (the 600 rule)."""
    path = Path(path)
    if not path.is_file():
        raise LabError(f"Missing {path.relative_to(ROOT)}.")
    if os.name == "nt":
        return  # Windows has no POSIX mode bits; the file relies on the user-profile ACL.
    if path.stat().st_mode & 0o077:
        raise LabError(f"{path.relative_to(ROOT)} must be mode 600; run chmod 600 and retry.")


def write_private(path, text):
    path = Path(path)
    path.parent.mkdir(exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
    if os.name != "nt":
        os.chmod(path, 0o600)


def ssh_command(cfg, host, *options):
    key = str(Path(cfg.get("ssh_key", "~/.ssh/id_ed25519")).expanduser())
    return [cfg.get("ssh", "ssh"), "-i", key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15", *options,
            f"{cfg.get('ssh_user', 'ec2-user')}@{host}"]


def ssh_run(cfg, host, command, stdin=b"", label="remote step", timeout=900):
    """Run one remote command. stdin carries scripts and secrets so they never reach argv."""
    try:
        result = subprocess.run(ssh_command(cfg, host) + [command], input=stdin, capture_output=True,
                                timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise LabError(f"SSH timed out during {label}.") from exc
    if result.returncode:
        # Remote stderr is not echoed: it could repeat input that was sent on stdin.
        raise LabError(f"SSH failed during {label} (exit {result.returncode}). Check SG source, key and host state.")
    return result.stdout.decode("utf-8", "replace")


@contextlib.contextmanager
def http_base(cfg, host):
    """Base URL for the service: direct, or an SSH port forward when http_via_ssh is set."""
    if not cfg.get("http_via_ssh"):
        yield f"http://{host}"
        return
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    forward = ssh_command(cfg, host, "-N", "-o", "ExitOnForwardFailure=yes",
                          "-L", f"127.0.0.1:{port}:127.0.0.1:80")
    tunnel = subprocess.Popen(forward, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 20
        while True:
            if tunnel.poll() is not None:
                raise LabError("SSH port forward exited; check SG source, key and host state.")
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise LabError("SSH port forward did not come up within 20s.") from None
                time.sleep(0.3)
        yield f"http://127.0.0.1:{port}"
    finally:
        tunnel.terminate()
        try:
            tunnel.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tunnel.kill()


def http(method, url, token=None, body=None, content_type="application/json", timeout=8):
    """Returns (HTTP status, body text). Status 0 means no HTTP response was received."""
    request = urllib.request.Request(url, data=body, method=method)
    if token:
        request.add_header("Authorization", "Bearer " + token)
    if body is not None:
        request.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError):
        return 0, ""


def health(base):
    status, text = http("GET", base + "/health")
    try:
        return status, json.loads(text) if text else {}
    except json.JSONDecodeError:
        return status, {}


def run(main):
    """Entry point wrapper matching scripts/lab.py: short STOP message, no traceback."""
    try:
        return main() or 0
    except (LabError, OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print("STOP: " + (str(exc) if isinstance(exc, LabError) else f"{type(exc).__name__}: {exc}"),
              file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("STOP: interrupted", file=sys.stderr)
        return 1
