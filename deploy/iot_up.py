#!/usr/bin/env python3
"""W6: IoT Core endpoint, two certificates (gateway, consumer) and two exact-resource policies.

Run once. Every ID is written to .local/resources.json at once and a recorded item is
skipped on a re-run, so no second certificate is created and no private key is overwritten.
"""
import argparse
import json
import os
import urllib.request

import labctl
from labctl import LabError, aws

IOT_DIR = labctl.LOCAL / "iot"
ROOT_CA_URL = "https://www.amazontrust.com/repository/AmazonRootCA1.pem"
ROLES = ("gw", "consumer")


def names(code):
    return {"topic": f"cxe/{code}/gw/events",
            "gw": {"client": f"gw-{code}", "policy": f"cxe-{code}-gw"},
            "consumer": {"client": f"consumer-{code}", "policy": f"cxe-{code}-consumer"}}


def policy_document(role, code, account, region):
    """Exact resource strings only. Subscribe is matched against topicfilter/, the rest topic/."""
    arn = f"arn:aws:iot:{region}:{account}:"
    topic = names(code)["topic"]
    statements = [("iot:Connect", f"client/{names(code)[role]['client']}")]
    if role == "gw":
        statements.append(("iot:Publish", f"topic/{topic}"))
    else:
        statements += [("iot:Subscribe", f"topicfilter/{topic}"), ("iot:Receive", f"topic/{topic}")]
    return {"Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": action, "Resource": arn + resource}
                          for action, resource in statements]}


def private(path):
    if os.name != "nt":
        os.chmod(path, 0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", help="Approval token printed by a previous run")
    args = parser.parse_args()
    cfg = labctl.settings()
    labctl.verify(cfg)
    resources = labctl.load_resources()
    code = labctl.prefix(cfg)
    plan = names(code)
    labctl.confirm(
        "Will CREATE in AWS IoT Core (items already recorded in resources.json are skipped):\n"
        f"  certificate  gateway   -> .local/iot/gw.cert.pem, gw.private.key\n"
        f"  certificate  consumer  -> .local/iot/consumer.cert.pem, consumer.private.key\n"
        f"  policy       {plan['gw']['policy']}: connect as {plan['gw']['client']}, publish {plan['topic']}\n"
        f"  policy       {plan['consumer']['policy']}: connect as {plan['consumer']['client']}, "
        f"subscribe and receive {plan['topic']}\n"
        "  cost         idle certificates and policies are not billed; messages are billed per use\n"
        "Private keys are written straight to files and never shown.",
        f"iot-up-{code}", args.confirm)

    IOT_DIR.mkdir(mode=0o700, exist_ok=True)
    if os.name != "nt":
        os.chmod(IOT_DIR, 0o700)
    endpoint = aws(cfg, "iot", "describe-endpoint", "--endpoint-type", "iot:Data-ATS")["endpointAddress"]
    (IOT_DIR / "endpoint").write_text(endpoint + "\n", encoding="utf-8", newline="\n")

    for role in ROLES:
        key = f"iot_{role}_cert_id"
        if resources.get(key):
            print(f"certificate {role}: already recorded, skipped")
            continue
        certificate, private_key = IOT_DIR / f"{role}.cert.pem", IOT_DIR / f"{role}.private.key"
        if certificate.exists() or private_key.exists():
            raise LabError(f".local/iot already has {role} files but no recorded ID; inspect before retrying.")
        # The CLI writes both PEM files itself; --query keeps the private key out of its output.
        resources[key] = aws(cfg, "iot", "create-keys-and-certificate", "--set-as-active",
                             "--certificate-pem-outfile", f".local/iot/{certificate.name}",
                             "--private-key-outfile", f".local/iot/{private_key.name}",
                             "--query", "certificateId")
        labctl.save_resources(resources)
        private(certificate)
        private(private_key)
        print(f"{labctl.utc_now()} certificate {role}: ...{resources[key][-4:]}")

    account = aws(cfg, "sts", "get-caller-identity")["Account"]
    for role in ROLES:
        key, policy = f"iot_{role}_policy", plan[role]["policy"]
        if not resources.get(key):
            aws(cfg, "iot", "create-policy", "--policy-name", policy, "--policy-document",
                json.dumps(policy_document(role, code, account, cfg["region"])))
            resources[key] = policy
            labctl.save_resources(resources)
            print(f"{labctl.utc_now()} policy {policy}")
        description = aws(cfg, "iot", "describe-certificate", "--certificate-id",
                          resources[f"iot_{role}_cert_id"])["certificateDescription"]
        aws(cfg, "iot", "attach-policy", "--policy-name", policy, "--target", description["certificateArn"])

    root_ca = IOT_DIR / "AmazonRootCA1.pem"
    if not root_ca.exists():
        with urllib.request.urlopen(ROOT_CA_URL, timeout=20) as response:
            pem = response.read()
        if not pem.startswith(b"-----BEGIN CERTIFICATE-----"):
            raise LabError("Downloaded Root CA is not a PEM certificate.")
        root_ca.write_bytes(pem)

    for role in ROLES:
        description = aws(cfg, "iot", "describe-certificate", "--certificate-id",
                          resources[f"iot_{role}_cert_id"])["certificateDescription"]
        attached = aws(cfg, "iot", "list-attached-policies", "--target", description["certificateArn"])
        print(f"{labctl.utc_now()} read back: {role} certificate ...{description['certificateId'][-4:]} "
              f"{description['status']}, policies {[item['policyName'] for item in attached['policies']]}")
        if description["status"] != "ACTIVE":
            raise LabError(f"The {role} certificate is not ACTIVE.")
    print(f"Endpoint saved to .local/iot/endpoint; topic {plan['topic']}")


if __name__ == "__main__":
    raise SystemExit(labctl.run(main))
