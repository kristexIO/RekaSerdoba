import hashlib
import hmac
import json
import os
import socket
import struct
import threading
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from rekaserdoba.tools.manifest import b64d, verify_bytes
from rekaserdoba.tools.probe import (
    H2Carrier,
    H3ProcessCarrier,
    encode_handshake,
    expand_label,
    frame,
    open_application_record,
    open_carrier,
    open_record,
    recv_ws,
    seal_application_record,
    seal_record,
    send_ws,
    sha,
    transcript,
)


@dataclass
class CarrierChoice:
    name: str
    path: str
    method: str
    priority: int


@dataclass
class SessionParameters:
    session_id: bytes
    ipv4: str
    prefix: int
    mtu: int
    lifetime: int


class FragmentReassembler:
    def __init__(self, maximum_packet):
        self.maximum_packet = maximum_packet
        self.assemblies = {}

    def push(self, body):
        now = time.monotonic()
        self.assemblies = {
            packet_id: value
            for packet_id, value in self.assemblies.items()
            if now - value["created"] < 3
        }
        if len(body) < 10:
            raise ValueError("truncated fragment")
        packet_id = int.from_bytes(body[0:4], "big")
        total = int.from_bytes(body[4:6], "big")
        offset = int.from_bytes(body[6:8], "big")
        length = int.from_bytes(body[8:10], "big")
        data = body[10:]
        if (
            total == 0
            or total > self.maximum_packet
            or length == 0
            or length != len(data)
            or offset + length > total
        ):
            raise ValueError("invalid fragment")
        if packet_id not in self.assemblies:
            if len(self.assemblies) >= 64:
                oldest = min(
                    self.assemblies,
                    key=lambda value: self.assemblies[value]["created"],
                )
                self.assemblies.pop(oldest, None)
            self.assemblies[packet_id] = {
                "total": total,
                "created": now,
                "parts": {},
            }
        assembly = self.assemblies[packet_id]
        if assembly["total"] != total:
            self.assemblies.pop(packet_id, None)
            raise ValueError("fragment total changed")
        parts = assembly["parts"]
        if offset in parts:
            if parts[offset] == data:
                return None
            self.assemblies.pop(packet_id, None)
            raise ValueError("conflicting fragment")
        end = offset + length
        for other_offset, other_data in parts.items():
            other_end = other_offset + len(other_data)
            if offset < other_end and other_offset < end:
                self.assemblies.pop(packet_id, None)
                raise ValueError("overlapping fragment")
        parts[offset] = data
        if sum(len(value) for value in parts.values()) != total:
            return None
        expected = 0
        output = bytearray()
        for part_offset, value in sorted(parts.items()):
            if part_offset != expected:
                return None
            output.extend(value)
            expected += len(value)
        if expected != total:
            return None
        self.assemblies.pop(packet_id, None)
        return bytes(output)


class ReplayWindow:
    def __init__(self, width=4096):
        if width < 256 or width > 16384 or width % 64:
            raise ValueError("invalid replay window width")
        self.width = width
        self.initialized = False
        self.highest = 0
        self.bits = [0] * (width // 64)

    def plausible(self, number):
        if not self.initialized:
            return True
        if number + self.width <= self.highest:
            return False
        if number > self.highest:
            return True
        word, mask = self._slot(number)
        return self.bits[word] & mask == 0

    def commit_authenticated(self, number):
        if not self.plausible(number):
            return False
        if not self.initialized:
            self.initialized = True
            self.highest = number
        elif number > self.highest:
            distance = number - self.highest
            if distance >= self.width:
                self.bits = [0] * len(self.bits)
            else:
                for cleared in range(self.highest + 1, number + 1):
                    word, mask = self._slot(cleared)
                    self.bits[word] &= ~mask
            self.highest = number
        word, mask = self._slot(number)
        if self.bits[word] & mask:
            return False
        self.bits[word] |= mask
        return True

    def _slot(self, number):
        offset = number % self.width
        return offset // 64, 1 << (offset % 64)


class ManifestState:
    def __init__(self, path: Path):
        self.path = path
        self.sequence = 0
        if path.exists():
            value = json.loads(path.read_text(encoding="utf-8"))
            self.sequence = int(value.get("sequence", 0))

    def accept(self, sequence: int):
        if sequence < self.sequence:
            raise ValueError("manifest rollback rejected")
        temporary = self.path.with_suffix(".new")
        temporary.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(
            json.dumps({"sequence": sequence}, separators=(",", ":")),
            encoding="utf-8",
        )
        os.replace(temporary, self.path)
        self.sequence = sequence


class CarrierScores:
    def __init__(self, path: Path):
        self.path = path
        self.values = {}
        if path.exists():
            self.values = json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _key(name, endpoint=None):
        return f"{endpoint}/{name}" if endpoint else name

    def order(self, choices, endpoint=None):
        now = time.time()
        return sorted(
            choices,
            key=lambda item: (
                float(
                    self.values.get(self._key(item.name, endpoint), {}).get(
                        "cooldown", 0
                    )
                )
                > now,
                item.priority
                + int(
                    self.values.get(self._key(item.name, endpoint), {}).get(
                        "failures", 0
                    )
                )
                * 10,
            ),
        )

    def order_candidates(self, endpoints, choices):
        now = time.time()
        candidates = [
            (endpoint, choice) for endpoint in endpoints for choice in choices
        ]
        return sorted(
            candidates,
            key=lambda item: (
                float(
                    self.values.get(self._key(item[1].name, item[0]), {}).get(
                        "cooldown", 0
                    )
                )
                > now,
                item[1].priority
                + int(
                    self.values.get(self._key(item[1].name, item[0]), {}).get(
                        "failures", 0
                    )
                )
                * 10,
            ),
        )

    def success(self, name, endpoint=None):
        key = self._key(name, endpoint)
        entry = self.values.get(key, {})
        self.values[key] = {
            "failures": max(0, int(entry.get("failures", 0)) - 1),
            "cooldown": 0,
            "last_success": int(time.time()),
        }
        self._save()

    def wait_seconds(self, name, now=None, endpoint=None):
        now = time.time() if now is None else now
        cooldown = float(
            self.values.get(self._key(name, endpoint), {}).get("cooldown", 0)
        )
        return max(0, cooldown - now)

    def next_retry_seconds(self, choices, now=None, endpoints=None):
        endpoints = list(endpoints or [None])
        waits = [
            self.wait_seconds(choice.name, now, endpoint)
            for endpoint in endpoints
            for choice in choices
        ]
        positive = [value for value in waits if value > 0]
        return min(positive) if positive else 1

    def failure(self, name, endpoint=None):
        key = self._key(name, endpoint)
        entry = self.values.get(key, {})
        failures = min(int(entry.get("failures", 0)) + 1, 8)
        delay = min(300, 2**failures) + int.from_bytes(os.urandom(1), "big") % 4
        self.values[key] = {
            "failures": failures,
            "cooldown": int(time.time()) + delay,
            "last_failure": int(time.time()),
        }
        self._save()

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".new")
        temporary.write_text(json.dumps(self.values, separators=(",", ":")), encoding="utf-8")
        os.replace(temporary, self.path)


def load_manifest(bundle, state):
    request = urllib.request.Request(
        bundle["manifest_url"],
        headers={"Accept": "application/cose", "Cache-Control": "no-cache"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        encoded = response.read(262144)
    manifest = verify_bytes(encoded, b64d(bundle["manifest_signing_public_key_b64"]))
    now = int(time.time())
    if manifest[2] != b64d(bundle["profile_id_b64"]):
        raise ValueError("manifest profile mismatch")
    if manifest[4] > now + 300 or manifest[5] < now:
        raise ValueError("manifest validity rejected")
    state.accept(int(manifest[3]))
    ingress = manifest[9][0]
    authority = ingress[2]
    port = int(ingress[3])
    addresses = list(ingress[6])
    identities = {entry[1]: entry[2] for entry in manifest[8] if entry[3] <= now <= entry[4]}
    server_public = identities.get(ingress[4])
    if server_public is None:
        raise ValueError("manifest active identity unavailable")
    choices = []
    names = {1: ("h3", "CONNECT"), 2: ("h2", "POST"), 3: ("wss", "GET")}
    for carrier in ingress[5]:
        if carrier[1] in names:
            name, method = names[carrier[1]]
            choices.append(CarrierChoice(name, carrier[2], method, int(carrier[3])))
    return authority, port, addresses, server_public, choices


class RekaSession:
    def __init__(self, bundle, carrier, parameters, secrets):
        self.bundle = bundle
        self.carrier = carrier
        self.parameters = parameters
        self.epoch = 0
        self.c2s_number = 0
        self.s2c_windows = {False: ReplayWindow(), True: ReplayWindow()}
        self.c2s_data_key = secrets["c2s_data_key"]
        self.s2c_data_key = secrets["s2c_data_key"]
        self.c2s_data_iv = secrets["c2s_data_iv"]
        self.s2c_data_iv = secrets["s2c_data_iv"]
        self.c2s_control_key = secrets["c2s_control_key"]
        self.s2c_control_key = secrets["s2c_control_key"]
        self.c2s_control_iv = secrets["c2s_control_iv"]
        self.s2c_control_iv = secrets["s2c_control_iv"]
        self.epoch_secret = secrets["epoch_secret"]
        self.control_transcript = secrets["control_transcript"]
        self.control_number = 0
        self.pending_rekey = None
        self.state_lock = threading.RLock()
        self.send_lock = threading.Lock()
        self.created = time.monotonic()
        self.fragments = FragmentReassembler(parameters.mtu)

    @classmethod
    def connect(cls, bundle_path, choice, host, port, ip, server_public, h3_bridge=None):
        bundle_path = Path(bundle_path)
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        client_id = b64d(bundle["client_id_b64"])
        gate_key = b64d(bundle["gate_key_b64"])
        client_signing = Ed25519PrivateKey.from_private_bytes(
            b64d(bundle["client_signing_seed_b64"])
        )
        client_public = client_signing.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        timestamp = int(time.time())
        gate_nonce = os.urandom(16)
        gate_message = (
            b"RekaSerdoba/1 gate-lab"
            + choice.method.encode()
            + b"\0"
            + f"{host}:{port}".encode()
            + b"\0"
            + choice.path.encode()
            + b"\0"
            + client_id
            + timestamp.to_bytes(8, "big")
            + gate_nonce
        )
        token = (
            client_id
            + timestamp.to_bytes(8, "big")
            + gate_nonce
            + hmac.new(gate_key, gate_message, hashlib.sha256).digest()
        )
        authorization = _b64e(token)
        if choice.name == "h3":
            if h3_bridge is None:
                raise RuntimeError("H3 bridge is unavailable")
            carrier = H3ProcessCarrier(
                Path(h3_bridge), bundle_path, host, port, choice.path, ip
            )
        elif choice.name == "h2":
            carrier = H2Carrier(host, ip, choice.path, authorization)
        else:
            carrier = open_carrier(host, ip, choice.path, authorization)
        try:
            parameters, secrets = _handshake(
                carrier,
                client_id,
                client_signing,
                client_public,
                server_public,
            )
            return cls(bundle, carrier, parameters, secrets)
        except Exception:
            _close_carrier(carrier)
            raise

    def send_packet(self, packet):
        if len(packet) > self.parameters.mtu:
            raise ValueError("packet exceeds negotiated MTU")
        self.send_packets([packet])

    def send_packets(self, packets):
        batches = []
        plaintext = bytearray()
        for packet in packets:
            if len(packet) > self.parameters.mtu:
                raise ValueError("packet exceeds negotiated MTU")
            encoded = frame(0x01, packet)
            if len(encoded) > 4080:
                raise ValueError("packet exceeds record capacity")
            if plaintext and len(plaintext) + len(encoded) > 4080:
                batches.append(bytes(plaintext))
                plaintext.clear()
            plaintext.extend(encoded)
        if plaintext:
            batches.append(bytes(plaintext))
        for batch in batches:
            self._send_data(batch)

    def send_keepalive(self):
        self._send_data(frame(0x04))

    def _send_data(self, plaintext):
        with self.state_lock:
            record = seal_application_record(
                self.c2s_data_key,
                self.c2s_data_iv,
                self.parameters.session_id,
                self.epoch,
                self.c2s_number,
                False,
                plaintext,
            )
            self.c2s_number += 1
            with self.send_lock:
                send_ws(self.carrier, 2, record)

    def receive(self):
        opcode, record = recv_ws(self.carrier)
        if opcode != 2 or len(record) < 31:
            return None
        with self.state_lock:
            flags = record[0]
            if flags >> 4 != 1 or flags & 0x01 or record[1:17] != self.parameters.session_id:
                raise ValueError("invalid application record")
            epoch = int.from_bytes(record[17:21], "big")
            number = int.from_bytes(record[21:29], "big")
            control = bool(flags & 0x08)
            if epoch == self.epoch:
                keys = self._current_receive_keys(control)
                window = self.s2c_windows[control]
                pending = False
            elif self.pending_rekey and epoch == self.pending_rekey["epoch"] and control:
                keys = (
                    self.pending_rekey["s2c_control_key"],
                    self.pending_rekey["s2c_control_iv"],
                )
                window = self.pending_rekey["s2c_windows"][True]
                pending = True
            else:
                raise ValueError("record epoch mismatch")
            if not window.plausible(number):
                raise ValueError("record replay rejected")
            plaintext = open_application_record(
                keys[0],
                keys[1],
                self.parameters.session_id,
                epoch,
                number,
                control,
                record,
            )
            if not window.commit_authenticated(number):
                raise ValueError("record replay rejected")
            frames = _parse_frames(plaintext)
            if control and len(frames) != 1 and any(0x04 <= kind <= 0x11 for kind, _ in frames):
                raise ValueError("security-critical control record must contain one frame")
            packets = []
            for kind, body in frames:
                if kind == 0x01 and not control:
                    packets.append(body)
                elif kind == 0x03 and not control:
                    packet = self.fragments.push(body)
                    if packet is not None:
                        packets.append(packet)
                elif kind == 0x04 and control and not pending:
                    self._accept_update_request(record, body)
                elif kind == 0x06 and control and not pending:
                    self._accept_update_ack(record, body)
                elif kind == 0x08 and control and pending:
                    self._accept_update_done(record, body)
            return packets

    def _current_receive_keys(self, control):
        if control:
            return self.s2c_control_key, self.s2c_control_iv
        return self.s2c_data_key, self.s2c_data_iv

    def _accept_update_request(self, record, body):
        if len(body) != 4 or int.from_bytes(body, "big") != self.epoch:
            raise ValueError("invalid key update request")
        if self.pending_rekey is not None:
            raise ValueError("concurrent key update")
        self.control_transcript = transcript(self.control_transcript, record)
        next_epoch = self.epoch + 1
        nonce = os.urandom(32)
        update_input = (
            b"RekaSerdoba/1 epoch update"
            + self.parameters.session_id
            + struct.pack(">II", self.epoch, next_epoch)
            + nonce
            + self.control_transcript
        )
        context = sha(update_input)
        tag = hmac.new(self.epoch_secret, update_input, hashlib.sha256).digest()
        body = struct.pack(">II", self.epoch, next_epoch) + nonce + tag
        encoded = self._seal_current_control(frame(0x05, body))
        self.control_transcript = transcript(self.control_transcript, encoded)
        self.pending_rekey = {
            "epoch": next_epoch,
            "context": context,
            "started": time.monotonic(),
        }
        with self.send_lock:
            send_ws(self.carrier, 2, encoded)

    def _accept_update_ack(self, record, body):
        pending = self.pending_rekey
        if pending is None or len(body) != 36:
            raise ValueError("unexpected key update acknowledgment")
        next_epoch = int.from_bytes(body[:4], "big")
        if next_epoch != pending["epoch"]:
            raise ValueError("key update acknowledgment epoch mismatch")
        next_secret = hmac.new(
            self.epoch_secret, pending["context"], hashlib.sha256
        ).digest()
        next_context = self.parameters.session_id + struct.pack(">I", next_epoch)
        confirm_key = expand_label(
            next_secret, "epoch confirmation", next_context, 32
        )
        expected = hmac.new(
            confirm_key,
            b"server ack" + pending["context"],
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(body[4:], expected):
            raise ValueError("invalid key update acknowledgment")
        for name, label, length in [
            ("c2s_data_key", "data c2s key", 32),
            ("s2c_data_key", "data s2c key", 32),
            ("c2s_data_iv", "data c2s iv", 12),
            ("s2c_data_iv", "data s2c iv", 12),
            ("c2s_control_key", "control c2s key", 32),
            ("s2c_control_key", "control s2c key", 32),
            ("c2s_control_iv", "control c2s iv", 12),
            ("s2c_control_iv", "control s2c iv", 12),
        ]:
            pending[name] = expand_label(next_secret, label, next_context, length)
        pending["secret"] = next_secret
        pending["confirm_key"] = confirm_key
        pending["s2c_windows"] = {False: ReplayWindow(), True: ReplayWindow()}
        self.control_transcript = transcript(self.control_transcript, record)
        commit_tag = hmac.new(
            confirm_key,
            b"client commit" + pending["context"],
            hashlib.sha256,
        ).digest()
        commit = seal_application_record(
            pending["c2s_control_key"],
            pending["c2s_control_iv"],
            self.parameters.session_id,
            next_epoch,
            0,
            True,
            frame(0x07, struct.pack(">I", next_epoch) + commit_tag),
        )
        self.control_transcript = transcript(self.control_transcript, commit)
        pending["phase"] = "commit"
        with self.send_lock:
            send_ws(self.carrier, 2, commit)

    def _accept_update_done(self, record, body):
        pending = self.pending_rekey
        if pending is None or pending.get("phase") != "commit" or len(body) != 36:
            raise ValueError("unexpected key update completion")
        next_epoch = int.from_bytes(body[:4], "big")
        expected = hmac.new(
            pending["confirm_key"],
            b"server done" + pending["context"],
            hashlib.sha256,
        ).digest()
        if next_epoch != pending["epoch"] or not hmac.compare_digest(body[4:], expected):
            raise ValueError("invalid key update completion")
        self.control_transcript = transcript(self.control_transcript, record)
        for name in [
            "c2s_data_key",
            "s2c_data_key",
            "c2s_data_iv",
            "s2c_data_iv",
            "c2s_control_key",
            "s2c_control_key",
            "c2s_control_iv",
            "s2c_control_iv",
        ]:
            setattr(self, name, pending[name])
        self.epoch_secret = pending["secret"]
        self.epoch = next_epoch
        self.c2s_number = 0
        self.control_number = 1
        self.s2c_windows = pending["s2c_windows"]
        self.pending_rekey = None

    def _seal_current_control(self, plaintext):
        record = seal_application_record(
            self.c2s_control_key,
            self.c2s_control_iv,
            self.parameters.session_id,
            self.epoch,
            self.control_number,
            True,
            plaintext,
        )
        self.control_number += 1
        return record

    def expired(self):
        now = time.monotonic()
        if self.pending_rekey and now - self.pending_rekey["started"] >= 10:
            return True
        margin = min(60, max(5, self.parameters.lifetime // 10))
        return now - self.created >= max(1, self.parameters.lifetime - margin)

    def close(self):
        _close_carrier(self.carrier)


def _handshake(carrier, client_id, client_signing, client_public, server_public):
    handshake_id = os.urandom(16)
    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    client_nonce = os.urandom(32)
    hello_payload = (
        struct.pack(">HH", 1, 1)
        + handshake_id
        + client_id
        + ephemeral_public
        + client_nonce
        + int(time.time()).to_bytes(8, "big")
        + b"\0\0"
        + b"\0\0"
    )
    client_hello = encode_handshake(1, hello_payload)
    t1 = transcript(sha(b"RekaSerdoba/1 transcript"), client_hello)
    send_ws(carrier, 2, client_hello)
    opcode, server_hello = recv_ws(carrier)
    if opcode != 2 or len(server_hello) != 175 or server_hello[0] != 3:
        raise ValueError("invalid SERVER_HELLO")
    payload = server_hello[5:]
    if payload[:4] != b"\0\1\0\1" or payload[4:20] != handshake_id:
        raise ValueError("SERVER_HELLO mismatch")
    server_ephemeral = payload[20:52]
    server_nonce = payload[52:84]
    server_key_id = payload[84:100]
    server_signature = payload[106:170]
    if server_key_id != sha(b"RekaSerdoba server id", server_public)[:16]:
        raise ValueError("server identity mismatch")
    signature_input = sha(
        b"RekaSerdoba/1 server signature",
        t1,
        sha(payload[:106]),
        client_id,
        handshake_id,
    )
    Ed25519PublicKey.from_public_bytes(server_public).verify(
        server_signature, signature_input
    )
    t2 = transcript(t1, server_hello)
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(server_ephemeral))
    extract_salt = sha(
        b"RekaSerdoba/1 handshake extract", client_nonce, server_nonce, t2
    )
    handshake_secret = hmac.new(extract_salt, shared, hashlib.sha256).digest()
    c_hs_key = expand_label(handshake_secret, "client handshake key", t2, 32)
    s_hs_key = expand_label(handshake_secret, "server handshake key", t2, 32)
    c_hs_iv = expand_label(handshake_secret, "client handshake iv", t2, 12)
    s_hs_iv = expand_label(handshake_secret, "server handshake iv", t2, 12)
    c_finished = expand_label(handshake_secret, "client finished", t2, 32)
    s_finished = expand_label(handshake_secret, "server finished", t2, 32)
    client_key_id = sha(b"RekaSerdoba client key", client_public)[:16]
    client_signature = client_signing.sign(
        sha(
            b"RekaSerdoba/1 client signature",
            t2,
            server_signature,
            server_public,
            client_id,
            client_key_id,
        )
    )
    auth_without_finished = (
        client_id + client_key_id + struct.pack(">IHH", 0, 1280, 0) + client_signature
    )
    proof = hmac.new(
        c_finished,
        sha(b"RekaSerdoba/1 client finished", t2, auth_without_finished),
        hashlib.sha256,
    ).digest()
    encrypted_auth = seal_record(
        c_hs_key, c_hs_iv, 4, 0, t2, auth_without_finished + proof
    )
    send_ws(carrier, 2, encrypted_auth)
    t3 = transcript(t2, encrypted_auth)
    opcode, encrypted_finish = recv_ws(carrier)
    if opcode != 2:
        raise ValueError("invalid SERVER_FINISH carrier")
    finish_plain = open_record(s_hs_key, s_hs_iv, 5, 0, t3, encrypted_finish)
    parameters, server_proof = finish_plain[:-32], finish_plain[-32:]
    expected = hmac.new(
        s_finished,
        sha(b"RekaSerdoba/1 server finished", t3, sha(parameters)),
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(server_proof, expected) or len(parameters) != 57:
        raise ValueError("invalid server Finished")
    session_id = parameters[:16]
    lifetime = int.from_bytes(parameters[16:20], "big")
    mtu = int.from_bytes(parameters[20:22], "big")
    prefix = parameters[32]
    ipv4 = socket.inet_ntoa(parameters[33:37])
    t4 = transcript(t3, encrypted_finish)
    confirmation = hmac.new(
        c_finished,
        sha(b"RekaSerdoba/1 client confirm", t4, session_id),
        hashlib.sha256,
    ).digest()
    encrypted_confirm = seal_record(
        c_hs_key, c_hs_iv, 6, 1, t4, session_id + confirmation
    )
    send_ws(carrier, 2, encrypted_confirm)
    t5 = transcript(t4, encrypted_confirm)
    master_secret = expand_label(handshake_secret, "master secret", t5, 32)
    epoch_secret = expand_label(master_secret, "epoch root", t5, 32)
    context = session_id + bytes(4)
    secrets = {}
    for name, label, length in [
        ("c2s_data_key", "data c2s key", 32),
        ("s2c_data_key", "data s2c key", 32),
        ("c2s_data_iv", "data c2s iv", 12),
        ("s2c_data_iv", "data s2c iv", 12),
        ("c2s_control_key", "control c2s key", 32),
        ("s2c_control_key", "control s2c key", 32),
        ("c2s_control_iv", "control c2s iv", 12),
        ("s2c_control_iv", "control s2c iv", 12),
    ]:
        secrets[name] = expand_label(epoch_secret, label, context, length)
    secrets["epoch_secret"] = epoch_secret
    secrets["control_transcript"] = sha(
        b"RekaSerdoba/1 control transcript", t5, session_id
    )
    return SessionParameters(session_id, ipv4, prefix, mtu, lifetime), secrets


def _parse_frames(value):
    output = []
    offset = 0
    while offset < len(value):
        if len(value) - offset < 4:
            raise ValueError("truncated frame")
        kind = value[offset]
        flags = value[offset + 1]
        length = int.from_bytes(value[offset + 2 : offset + 4], "big")
        end = offset + 4 + length
        if flags or end > len(value):
            raise ValueError("invalid frame")
        output.append((kind, value[offset + 4 : end]))
        offset = end
    return output


def _b64e(value):
    import base64

    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _close_carrier(carrier):
    try:
        if isinstance(carrier, H3ProcessCarrier):
            carrier.__exit__(None, None, None)
        elif isinstance(carrier, H2Carrier):
            carrier.__exit__(None, None, None)
        else:
            carrier.close()
    except (OSError, EOFError, BrokenPipeError):
        pass
