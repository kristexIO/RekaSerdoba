#!/usr/bin/env python3
import argparse
import base64
import ipaddress
import json
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64e(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def b64d(value):
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def list_clients(args):
    config = load(args.server)
    output = []
    for client in config["clients"]:
        output.append(
            {
                "client_id_b64": client["client_id_b64"],
                "tunnel_ipv4": client["tunnel_ipv4"],
                "revoked": client["revoked"],
                "session_lifetime_seconds": client.get(
                    "session_lifetime_seconds", 3600
                ),
                "bandwidth_bytes_per_second": client.get(
                    "bandwidth_bytes_per_second", 25 * 1024 * 1024
                ),
                "session_quota_bytes": client.get("session_quota_bytes", 0),
            }
        )
    print(json.dumps(output, ensure_ascii=False, indent=2))


def next_address(config):
    used = {
        ipaddress.ip_address(client["tunnel_ipv4"])
        for client in config["clients"]
    }
    network = ipaddress.ip_network("10.77.0.0/24")
    for address in network.hosts():
        if address == ipaddress.ip_address("10.77.0.1"):
            continue
        if address not in used:
            return str(address)
    raise SystemExit("tunnel address pool exhausted")


def add_client(args):
    config = load(args.server)
    signing = Ed25519PrivateKey.generate()
    seed = signing.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = signing.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    client_id = os.urandom(16)
    gate_key = os.urandom(32)
    address = args.address or next_address(config)
    parsed = ipaddress.ip_address(address)
    if parsed.version != 4 or not parsed in ipaddress.ip_network("10.77.0.0/24"):
        raise SystemExit("address must be inside 10.77.0.0/24")
    if any(item["tunnel_ipv4"] == address for item in config["clients"]):
        raise SystemExit("address is already allocated")
    config["clients"].append(
        {
            "client_id_b64": b64e(client_id),
            "client_public_key_b64": b64e(public),
            "gate_key_b64": b64e(gate_key),
            "tunnel_ipv4": address,
            "revoked": False,
            "session_lifetime_seconds": args.lifetime,
            "bandwidth_bytes_per_second": args.bandwidth,
            "session_quota_bytes": args.quota,
        }
    )
    identity = Ed25519PrivateKey.from_private_bytes(
        b64d(config["server_signing_seed_b64"])
    )
    server_public = identity.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    import hashlib

    server_key_id = hashlib.sha256(
        b"RekaSerdoba server id" + server_public
    ).digest()[:16]
    bundle = {
        "format": "RekaSerdoba device bundle v1",
        "created_at": int(time.time()),
        "authority": config["authority"],
        "endpoint": f"wss://{config['authority']}{config['tunnel_path']}",
        "client_id_b64": b64e(client_id),
        "client_signing_seed_b64": b64e(seed),
        "client_public_key_b64": b64e(public),
        "gate_key_b64": b64e(gate_key),
        "server_key_id_b64": b64e(server_key_id),
        "server_public_key_b64": b64e(server_public),
        "tunnel_ipv4": address,
        "warning": "Хранить как секрет. Не передавать третьим лицам.",
    }
    if args.manifest_state:
        state = load(args.manifest_state)
        bundle.update(
            {
                "profile_id_b64": state["profile_id_b64"],
                "manifest_signing_public_key_b64": state[
                    "signing_public_key_b64"
                ],
                "manifest_url": f"https://{config['authority'].removesuffix(':443')}/.well-known/rekaserdoba/manifest.cbor",
                "manifest_sequence": state["sequence"],
            }
        )
    save(args.server, config)
    save(args.output, bundle)
    print(
        json.dumps(
            {
                "client_id_b64": b64e(client_id),
                "tunnel_ipv4": address,
                "bundle": str(args.output),
            },
            ensure_ascii=False,
        )
    )


def revoke_client(args):
    config = load(args.server)
    matches = [
        client
        for client in config["clients"]
        if client["client_id_b64"] == args.client_id
    ]
    if len(matches) != 1:
        raise SystemExit("client not found")
    matches[0]["revoked"] = True
    save(args.server, config)
    print(json.dumps({"client_id_b64": args.client_id, "revoked": True}))


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(required=True)
    listing = sub.add_parser("list")
    listing.add_argument("--server", type=Path, required=True)
    listing.set_defaults(run=list_clients)
    add = sub.add_parser("add")
    add.add_argument("--server", type=Path, required=True)
    add.add_argument("--output", type=Path, required=True)
    add.add_argument("--manifest-state", type=Path)
    add.add_argument("--address")
    add.add_argument("--lifetime", type=int, default=3600)
    add.add_argument("--bandwidth", type=int, default=25 * 1024 * 1024)
    add.add_argument("--quota", type=int, default=0)
    add.set_defaults(run=add_client)
    revoke = sub.add_parser("revoke")
    revoke.add_argument("--server", type=Path, required=True)
    revoke.add_argument("client_id")
    revoke.set_defaults(run=revoke_client)
    args = parser.parse_args()
    args.run(args)


if __name__ == "__main__":
    main()
