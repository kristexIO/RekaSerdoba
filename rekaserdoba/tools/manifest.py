#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
import struct
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def b64e(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def b64d(value):
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def head(major, value):
    prefix = major << 5
    if value < 24:
        return bytes([prefix | value])
    if value <= 0xFF:
        return bytes([prefix | 24, value])
    if value <= 0xFFFF:
        return bytes([prefix | 25]) + struct.pack(">H", value)
    if value <= 0xFFFFFFFF:
        return bytes([prefix | 26]) + struct.pack(">I", value)
    return bytes([prefix | 27]) + struct.pack(">Q", value)


def encode(value):
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode()
        return head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(encode(item) for item in value)
    if isinstance(value, dict):
        items = [(encode(key), encode(item)) for key, item in value.items()]
        items.sort(key=lambda item: (len(item[0]), item[0]))
        return head(5, len(items)) + b"".join(key + item for key, item in items)
    raise TypeError(type(value).__name__)


def tagged(tag, value):
    return head(6, tag) + encode(value)


class Decoder:
    def __init__(self, value):
        self.value = value
        self.offset = 0

    def take(self, length):
        end = self.offset + length
        if end > len(self.value):
            raise ValueError("truncated CBOR")
        output = self.value[self.offset:end]
        self.offset = end
        return output

    def length(self, additional):
        if additional < 24:
            return additional
        sizes = {24: 1, 25: 2, 26: 4, 27: 8}
        if additional not in sizes:
            raise ValueError("indefinite CBOR is forbidden")
        return int.from_bytes(self.take(sizes[additional]), "big")

    def item(self):
        initial = self.take(1)[0]
        major = initial >> 5
        additional = initial & 31
        if major == 7:
            if additional == 20:
                return False
            if additional == 21:
                return True
            raise ValueError("unsupported CBOR simple value")
        length = self.length(additional)
        if major == 0:
            return length
        if major == 1:
            return -1 - length
        if major == 2:
            return self.take(length)
        if major == 3:
            return self.take(length).decode()
        if major == 4:
            return [self.item() for _ in range(length)]
        if major == 5:
            return {self.item(): self.item() for _ in range(length)}
        if major == 6:
            return length, self.item()
        raise ValueError("unsupported CBOR type")


def decode(value):
    decoder = Decoder(value)
    output = decoder.item()
    if decoder.offset != len(value):
        raise ValueError("trailing CBOR")
    return output


def load_state(path):
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    seed = os.urandom(32)
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    state = {
        "format": "RekaSerdoba manifest authority v1",
        "profile_id_b64": b64e(os.urandom(16)),
        "signing_seed_b64": b64e(seed),
        "signing_public_key_b64": b64e(public),
        "sequence": 0,
    }
    atomic_json(path, state)
    return state


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def generate(args):
    server = json.loads(args.server.read_text(encoding="utf-8"))
    state = load_state(args.state)
    state["sequence"] += 1
    now = int(time.time())
    profile_id = b64d(state["profile_id_b64"])
    seed = b64d(state["signing_seed_b64"])
    identity = Ed25519PrivateKey.from_private_bytes(
        b64d(server["server_signing_seed_b64"])
    )
    identity_public = identity.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    server_key_id = hashlib.sha256(
        b"RekaSerdoba server id" + identity_public
    ).digest()[:16]
    identity_entries = server.get("manifest_identities")
    if identity_entries:
        identities = []
        active_found = False
        for entry in identity_entries:
            public = b64d(entry["public_key_b64"])
            if len(public) != 32:
                raise ValueError("invalid manifest identity")
            key_identifier = hashlib.sha256(
                b"RekaSerdoba server id" + public
            ).digest()[:16]
            active_found |= key_identifier == server_key_id
            identities.append(
                {
                    1: key_identifier,
                    2: public,
                    3: entry["not_before"],
                    4: entry["expires"],
                }
            )
        if not active_found:
            raise ValueError("active identity is absent from overlap")
    else:
        identities = [
            {
                1: server_key_id,
                2: identity_public,
                3: now - 86400,
                4: now + 180 * 86400,
            }
        ]
    authority = server["authority"].removesuffix(":443")
    path = server["tunnel_path"]
    signing_public = b64d(state["signing_public_key_b64"])
    manifest = {
        1: 1,
        2: profile_id,
        3: state["sequence"],
        4: now - 300,
        5: now + args.valid_days * 86400,
        6: 1,
        7: 1,
        8: identities,
        9: [
            {
                1: 1,
                2: authority,
                3: 443,
                4: server_key_id,
                5: [
                    {
                        1: 1,
                        2: "/connect/v1/h3",
                        3: 10,
                        4: 5000,
                        5: 1200,
                        6: 1,
                        7: {1: 1, 2: [[256, 15], [512, 30], [1024, 40], [1400, 15]], 3: 16},
                    },
                    {
                        1: 2,
                        2: "/connect/v1/h2",
                        3: 20,
                        4: 10000,
                        5: 4352,
                        6: 1,
                        7: {1: 1, 2: [[256, 15], [512, 30], [1024, 40], [1400, 15]], 3: 16},
                    },
                    {
                        1: 3,
                        2: path,
                        3: 30,
                        4: 10000,
                        5: 4352,
                        6: 1,
                        7: {1: 1, 2: [[256, 15], [512, 30], [1024, 40], [1400, 15]], 3: 16},
                    }
                ],
                6: [args.ip],
            }
        ],
        10: {1: 1280, 2: True, 3: False, 4: True, 5: ["0.0.0.0/0"], 6: 3600, 7: 30},
        11: {
            1: f"https://{authority}/.well-known/rekaserdoba/manifest.cbor",
            2: 3600,
            3: hashlib.sha256(signing_public).digest(),
        },
    }
    payload = encode(manifest)
    kid = hashlib.sha256(b"RekaSerdoba manifest key" + signing_public).digest()[:16]
    protected = encode({1: -8, 4: kid})
    signature_input = encode(["Signature1", protected, b"", payload])
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(signature_input)
    output = tagged(18, [protected, {}, payload, signature])
    verify_bytes(output, signing_public)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".new")
    temporary.write_bytes(output)
    os.replace(temporary, args.output)
    atomic_json(args.state, state)
    print(
        json.dumps(
            {
                "sequence": state["sequence"],
                "profile_id_b64": state["profile_id_b64"],
                "signing_public_key_b64": state["signing_public_key_b64"],
                "sha256": hashlib.sha256(output).hexdigest(),
            }
        )
    )


def verify_bytes(value, public):
    tag, cose = decode(value)
    if tag != 18 or not isinstance(cose, list) or len(cose) != 4:
        raise ValueError("invalid COSE_Sign1")
    protected, unprotected, payload, signature = cose
    headers = decode(protected)
    if headers.get(1) != -8 or unprotected:
        raise ValueError("invalid COSE headers")
    signature_input = encode(["Signature1", protected, b"", payload])
    Ed25519PublicKey.from_public_bytes(public).verify(signature, signature_input)
    manifest = decode(payload)
    if manifest.get(1) != 1 or manifest.get(6) != 1 or manifest.get(7) != 1:
        raise ValueError("unsupported manifest")
    if encode(manifest) != payload:
        raise ValueError("manifest is not deterministic CBOR")
    return manifest


def verify(args):
    state = json.loads(args.state.read_text(encoding="utf-8"))
    try:
        manifest = verify_bytes(
            args.input.read_bytes(), b64d(state["signing_public_key_b64"])
        )
    except InvalidSignature as error:
        raise SystemExit("invalid signature") from error
    print(
        json.dumps(
            {
                "sequence": manifest[3],
                "not_before": manifest[4],
                "expires": manifest[5],
                "authority": manifest[9][0][2],
            }
        )
    )


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(required=True)
    create = sub.add_parser("generate")
    create.add_argument("--server", type=Path, required=True)
    create.add_argument("--state", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--ip", required=True)
    create.add_argument("--valid-days", type=int, default=30)
    create.set_defaults(run=generate)
    check = sub.add_parser("verify")
    check.add_argument("--state", type=Path, required=True)
    check.add_argument("--input", type=Path, required=True)
    check.set_defaults(run=verify)
    args = parser.parse_args()
    args.run(args)


if __name__ == "__main__":
    main()
