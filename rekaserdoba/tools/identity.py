#!/usr/bin/env python3
import argparse
import base64
import hashlib
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


def public_from_seed(encoded):
    return Ed25519PrivateKey.from_private_bytes(b64d(encoded)).public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def key_id(public):
    return hashlib.sha256(b"RekaSerdoba server id" + public).digest()[:16]


def atomic_json(path, value, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def stage(args):
    server = json.loads(args.server.read_text(encoding="utf-8"))
    old_seed = server["server_signing_seed_b64"]
    new_seed = b64e(os.urandom(32))
    old_public = public_from_seed(old_seed)
    new_public = public_from_seed(new_seed)
    now = int(time.time())
    overlap_end = now + args.overlap_days * 86400
    expires = now + args.identity_days * 86400
    rotation = {
        "format": "RekaSerdoba identity rotation v1",
        "phase": "staged",
        "created_at": now,
        "overlap_end": overlap_end,
        "old_seed_b64": old_seed,
        "new_seed_b64": new_seed,
        "old_key_id_b64": b64e(key_id(old_public)),
        "new_key_id_b64": b64e(key_id(new_public)),
    }
    overlap = dict(server)
    overlap["manifest_identities"] = [
        {
            "public_key_b64": b64e(old_public),
            "not_before": now - 86400,
            "expires": overlap_end,
        },
        {
            "public_key_b64": b64e(new_public),
            "not_before": now - 300,
            "expires": expires,
        },
    ]
    atomic_json(args.rotation, rotation)
    atomic_json(args.output, overlap)
    print(
        json.dumps(
            {
                "phase": "staged",
                "old_key_id_b64": rotation["old_key_id_b64"],
                "new_key_id_b64": rotation["new_key_id_b64"],
                "overlap_end": overlap_end,
            }
        )
    )


def transition(args, phase):
    rotation = json.loads(args.rotation.read_text(encoding="utf-8"))
    server = json.loads(args.server.read_text(encoding="utf-8"))
    now = int(time.time())
    old_public = public_from_seed(rotation["old_seed_b64"])
    new_public = public_from_seed(rotation["new_seed_b64"])
    server["server_signing_seed_b64"] = rotation["new_seed_b64"]
    if phase == "active":
        server["manifest_identities"] = [
            {
                "public_key_b64": b64e(old_public),
                "not_before": rotation["created_at"] - 86400,
                "expires": rotation["overlap_end"],
            },
            {
                "public_key_b64": b64e(new_public),
                "not_before": rotation["created_at"] - 300,
                "expires": now + args.identity_days * 86400,
            },
        ]
    else:
        if now < rotation["overlap_end"] and not args.force:
            raise ValueError("overlap period has not ended")
        server["manifest_identities"] = [
            {
                "public_key_b64": b64e(new_public),
                "not_before": rotation["created_at"] - 300,
                "expires": now + args.identity_days * 86400,
            }
        ]
    rotation["phase"] = phase
    rotation[f"{phase}_at"] = now
    atomic_json(args.output, server)
    atomic_json(args.rotation, rotation)
    print(
        json.dumps(
            {
                "phase": phase,
                "active_key_id_b64": b64e(key_id(new_public)),
            }
        )
    )


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(required=True)
    create = sub.add_parser("stage")
    create.add_argument("--server", type=Path, required=True)
    create.add_argument("--rotation", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--overlap-days", type=int, default=14)
    create.add_argument("--identity-days", type=int, default=180)
    create.set_defaults(run=stage)
    activate = sub.add_parser("activate")
    activate.add_argument("--server", type=Path, required=True)
    activate.add_argument("--rotation", type=Path, required=True)
    activate.add_argument("--output", type=Path, required=True)
    activate.add_argument("--identity-days", type=int, default=180)
    activate.set_defaults(run=lambda args: transition(args, "active"))
    retire = sub.add_parser("retire")
    retire.add_argument("--server", type=Path, required=True)
    retire.add_argument("--rotation", type=Path, required=True)
    retire.add_argument("--output", type=Path, required=True)
    retire.add_argument("--identity-days", type=int, default=180)
    retire.add_argument("--force", action="store_true")
    retire.set_defaults(run=lambda args: transition(args, "retired"))
    args = parser.parse_args()
    args.run(args)


if __name__ == "__main__":
    main()
