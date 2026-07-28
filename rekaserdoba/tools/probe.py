#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import socket
import ssl
import struct
import subprocess
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
try:
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import DataReceived, ResponseReceived, StreamEnded
except ImportError:
    H2Configuration = None
    H2Connection = None
    DataReceived = None
    ResponseReceived = None
    StreamEnded = None


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def sha(*parts: bytes) -> bytes:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


def transcript(previous: bytes, encoded: bytes) -> bytes:
    return sha(previous, encoded)


def expand_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    full_label = f"RekaSerdoba/1 {label}".encode()
    info = struct.pack(">HB", length, len(full_label)) + full_label
    info += struct.pack(">H", len(context)) + context
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(secret)


def nonce(iv: bytes, sequence: int) -> bytes:
    value = bytearray(iv)
    encoded = sequence.to_bytes(8, "big")
    for index, byte in enumerate(encoded):
        value[4 + index] ^= byte
    return bytes(value)


def encode_handshake(message_type: int, payload: bytes) -> bytes:
    return bytes([message_type]) + len(payload).to_bytes(4, "big") + payload


def seal_record(
    key: bytes,
    iv: bytes,
    message_type: int,
    sequence: int,
    transcript_before: bytes,
    plaintext: bytes,
) -> bytes:
    header = bytes([message_type, 0]) + struct.pack(">IH", sequence, len(plaintext) + 16)
    ciphertext = ChaCha20Poly1305(key).encrypt(
        nonce(iv, sequence), plaintext, header + transcript_before
    )
    return header + ciphertext


def open_record(
    key: bytes,
    iv: bytes,
    message_type: int,
    sequence: int,
    transcript_before: bytes,
    encoded: bytes,
) -> bytes:
    if (
        len(encoded) < 24
        or encoded[0] != message_type
        or encoded[1] != 0
        or int.from_bytes(encoded[2:6], "big") != sequence
        or int.from_bytes(encoded[6:8], "big") != len(encoded) - 8
    ):
        raise ValueError("bad encrypted record header")
    return ChaCha20Poly1305(key).decrypt(
        nonce(iv, sequence), encoded[8:], encoded[:8] + transcript_before
    )


def seal_application_record(
    key: bytes,
    iv: bytes,
    session_id: bytes,
    epoch: int,
    number: int,
    control: bool,
    plaintext: bytes,
) -> bytes:
    flags = 0x10 | (0x08 if control else 0) | (0x04 if epoch & 1 else 0)
    header = (
        bytes([flags])
        + session_id
        + struct.pack(">IQH", epoch, number, len(plaintext) + 16)
    )
    ciphertext = ChaCha20Poly1305(key).encrypt(
        nonce(iv, number), plaintext, header
    )
    return header + ciphertext


def open_application_record(
    key: bytes,
    iv: bytes,
    session_id: bytes,
    epoch: int,
    number: int,
    control: bool,
    encoded: bytes,
) -> bytes:
    expected_flags = 0x10 | (0x08 if control else 0) | (0x04 if epoch & 1 else 0)
    if (
        len(encoded) < 47
        or encoded[0] != expected_flags
        or encoded[1:17] != session_id
        or int.from_bytes(encoded[17:21], "big") != epoch
        or int.from_bytes(encoded[21:29], "big") != number
        or int.from_bytes(encoded[29:31], "big") != len(encoded) - 31
    ):
        raise ValueError("bad application record header")
    return ChaCha20Poly1305(key).decrypt(
        nonce(iv, number), encoded[31:], encoded[:31]
    )


def frame(frame_type: int, body: bytes = b"") -> bytes:
    return bytes([frame_type, 0]) + len(body).to_bytes(2, "big") + body


def internet_checksum(value: bytes) -> int:
    if len(value) & 1:
        value += b"\0"
    total = sum(int.from_bytes(value[index : index + 2], "big") for index in range(0, len(value), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def icmp_echo_request() -> bytes:
    payload = os.urandom(16)
    identifier = os.urandom(2)
    icmp = b"\x08\0\0\0" + identifier + b"\0\1" + payload
    icmp = icmp[:2] + internet_checksum(icmp).to_bytes(2, "big") + icmp[4:]
    total_length = 20 + len(icmp)
    ip = (
        b"\x45\0"
        + total_length.to_bytes(2, "big")
        + os.urandom(2)
        + b"\x40\0"
        + b"\x40\x01"
        + b"\0\0"
        + socket.inet_aton("10.77.0.2")
        + socket.inet_aton("10.77.0.1")
    )
    ip = ip[:10] + internet_checksum(ip).to_bytes(2, "big") + ip[12:]
    return ip + icmp


class H2Carrier:
    def __init__(self, host: str, ip: str, path: str, authorization: str):
        if H2Connection is None or H2Configuration is None:
            raise RuntimeError("h2 package is required for the HTTP/2 probe")
        context = ssl.create_default_context()
        context.set_alpn_protocols(["h2"])
        raw = socket.create_connection((ip, 443), timeout=10)
        self.sock = context.wrap_socket(raw, server_hostname=host)
        if self.sock.selected_alpn_protocol() != "h2":
            raise RuntimeError("HTTP/2 ALPN was not negotiated")
        self.connection = H2Connection(
            config=H2Configuration(client_side=True, header_encoding="utf-8")
        )
        self.lock = threading.RLock()
        self.connection.initiate_connection()
        self.stream_id = self.connection.get_next_available_stream_id()
        self.connection.send_headers(
            self.stream_id,
            [
                (":method", "POST"),
                (":scheme", "https"),
                (":authority", host),
                (":path", path),
                ("authorization", f"Bearer {authorization}"),
                ("content-type", "application/octet-stream"),
                ("cache-control", "no-store"),
            ],
            end_stream=False,
        )
        self.sock.sendall(self.connection.data_to_send())
        self.buffer = bytearray()
        self.ended = False
        self._wait_response()

    def _events(self):
        data = self.sock.recv(65535)
        if not data:
            raise EOFError("HTTP/2 carrier closed")
        with self.lock:
            events = self.connection.receive_data(data)
            for event in events:
                if isinstance(event, DataReceived):
                    self.connection.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                    if event.stream_id == self.stream_id:
                        self.buffer.extend(event.data)
                elif isinstance(event, StreamEnded) and event.stream_id == self.stream_id:
                    self.ended = True
            pending = self.connection.data_to_send()
            if pending:
                self.sock.sendall(pending)
        return events

    def _wait_response(self):
        while True:
            for event in self._events():
                if isinstance(event, ResponseReceived) and event.stream_id == self.stream_id:
                    status = dict(event.headers).get(":status")
                    if status != "200":
                        raise RuntimeError(f"HTTP/2 carrier status {status}")
                    return

    def send_message(self, payload: bytes):
        encoded = len(payload).to_bytes(4, "big") + payload
        with self.lock:
            self.connection.send_data(self.stream_id, encoded, end_stream=False)
            self.sock.sendall(self.connection.data_to_send())

    def recv_message(self):
        while True:
            if len(self.buffer) >= 4:
                length = int.from_bytes(self.buffer[:4], "big")
                if length == 0 or length > 8192:
                    raise ValueError("invalid HTTP/2 carrier message length")
                if len(self.buffer) >= 4 + length:
                    payload = bytes(self.buffer[4 : 4 + length])
                    del self.buffer[: 4 + length]
                    return payload
            if self.ended:
                raise EOFError("HTTP/2 response ended")
            self._events()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        try:
            self.connection.end_stream(self.stream_id)
            self.sock.sendall(self.connection.data_to_send())
        except Exception:
            pass
        self.sock.close()


class H3ProcessCarrier:
    def __init__(
        self,
        bridge: Path,
        bundle: Path,
        host: str,
        port: int,
        path: str,
        ip: str,
    ):
        authority = f"{host}:{port}"
        url = f"https://{authority}{path}"
        self.process = subprocess.Popen(
            [str(bridge), str(bundle), url, authority, path, f"{ip}:{port}"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def send_message(self, payload: bytes):
        if self.process.stdin is None:
            raise EOFError("H3 bridge input closed")
        try:
            self.process.stdin.write(len(payload).to_bytes(4, "big") + payload)
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as error:
            raise EOFError(f"H3 bridge input closed{self._diagnostic()}") from error

    def recv_message(self):
        if self.process.stdout is None:
            raise EOFError("H3 bridge output closed")
        try:
            header = read_file_exact(self.process.stdout, 4)
        except EOFError as error:
            raise EOFError(f"H3 bridge closed{self._diagnostic()}") from error
        length = int.from_bytes(header, "big")
        if length == 0 or length > 8192:
            raise ValueError("invalid H3 bridge message length")
        try:
            return read_file_exact(self.process.stdout, length)
        except EOFError as error:
            raise EOFError(f"H3 bridge closed{self._diagnostic()}") from error

    def _diagnostic(self):
        code = self.process.poll()
        if code is None:
            return ""
        detail = ""
        if self.process.stderr is not None:
            detail = self.process.stderr.read().decode(errors="replace").strip()
        suffix = f": {detail[-1000:]}" if detail else ""
        return f" (exit={code}{suffix})"

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=5)


def read_file_exact(stream, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        chunk = stream.read(length - len(output))
        if not chunk:
            raise EOFError("framed carrier closed")
        output.extend(chunk)
    return bytes(output)


def send_ws(sock: ssl.SSLSocket, opcode: int, payload: bytes) -> None:
    if isinstance(sock, (H2Carrier, H3ProcessCarrier)):
        if opcode != 2:
            raise ValueError("framed carrier supports binary RS messages only")
        sock.send_message(payload)
        return
    first = 0x80 | opcode
    length = len(payload)
    if length < 126:
        header = bytes([first, 0x80 | length])
    elif length <= 0xFFFF:
        header = bytes([first, 0x80 | 126]) + struct.pack(">H", length)
    else:
        header = bytes([first, 0x80 | 127]) + struct.pack(">Q", length)
    mask = os.urandom(4)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    sock.sendall(header + mask + masked)


def recv_exact(sock: ssl.SSLSocket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        part = sock.recv(length - len(output))
        if not part:
            raise EOFError("WebSocket closed")
        output.extend(part)
    return bytes(output)


def recv_ws(sock: ssl.SSLSocket) -> tuple[int, bytes]:
    if isinstance(sock, (H2Carrier, H3ProcessCarrier)):
        return 2, sock.recv_message()
    first, second = recv_exact(sock, 2)
    if first & 0x80 == 0:
        raise ValueError("fragmented frame")
    opcode = first & 0x0F
    length = second & 0x7F
    if length == 126:
        length = int.from_bytes(recv_exact(sock, 2), "big")
    elif length == 127:
        length = int.from_bytes(recv_exact(sock, 8), "big")
    mask = recv_exact(sock, 4) if second & 0x80 else None
    payload = recv_exact(sock, length)
    if mask:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return opcode, payload


def open_carrier(host: str, ip: str, path: str, authorization: str) -> ssl.SSLSocket:
    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    raw = socket.create_connection((ip, 443), timeout=10)
    sock = context.wrap_socket(raw, server_hostname=host)
    websocket_key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {websocket_key}\r\n"
        f"Authorization: Bearer {authorization}\r\n\r\n"
    ).encode()
    sock.sendall(request)
    response = bytearray()
    while b"\r\n\r\n" not in response:
        response.extend(sock.recv(4096))
        if len(response) > 16384:
            raise ValueError("oversized HTTP response")
    status = bytes(response).split(b"\r\n", 1)[0]
    if status != b"HTTP/1.1 101 Switching Protocols":
        raise RuntimeError(status.decode("ascii", "replace"))
    return sock


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--ip")
    parser.add_argument("--carrier", choices=["wss", "h2", "h3"], default="wss")
    parser.add_argument("--h3-bridge", type=Path)
    parser.add_argument("--h3-port", type=int, default=443)
    parser.add_argument("--migrate-to-h2", action="store_true")
    args = parser.parse_args()
    bundle = json.loads(args.bundle.read_text(encoding="utf-8"))

    endpoint = bundle["endpoint"]
    host = bundle["authority"].removesuffix(":443")
    target_ip = args.ip or socket.gethostbyname(host)
    if args.carrier == "h2":
        path = "/connect/v1/h2"
        method = "POST"
    elif args.carrier == "h3":
        path = "/connect/v1/h3"
        method = "CONNECT"
    else:
        path = "/" + endpoint.split("/", 3)[3]
        method = "GET"
    client_id = b64url_decode(bundle["client_id_b64"])
    gate_key = b64url_decode(bundle["gate_key_b64"])
    client_seed = b64url_decode(bundle["client_signing_seed_b64"])
    server_public_bytes = b64url_decode(bundle["server_public_key_b64"])
    client_signing = Ed25519PrivateKey.from_private_bytes(client_seed)
    client_public = client_signing.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    timestamp = int(time.time())
    gate_nonce = os.urandom(16)
    gate_message = (
        b"RekaSerdoba/1 gate-lab"
        + method.encode()
        + b"\0"
        + bundle["authority"].encode()
        + b"\0"
        + path.encode()
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

    if args.carrier == "h2":
        opener = H2Carrier
    elif args.carrier == "h3":
        if args.h3_bridge is None:
            raise ValueError("--h3-bridge is required for H3")
        opener = lambda *_: H3ProcessCarrier(
            args.h3_bridge,
            args.bundle,
            host,
            args.h3_port,
            path,
            target_ip,
        )
    else:
        opener = open_carrier
    with opener(host, target_ip, path, b64url_encode(token)) as sock:
        handshake_id = os.urandom(16)
        ephemeral = X25519PrivateKey.generate()
        ephemeral_public = ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
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
        t0 = sha(b"RekaSerdoba/1 transcript")
        t1 = transcript(t0, client_hello)
        send_ws(sock, 2, client_hello)

        opcode, server_hello = recv_ws(sock)
        if opcode != 2 or server_hello[0] != 3:
            raise ValueError("expected SERVER_HELLO")
        payload_length = int.from_bytes(server_hello[1:5], "big")
        if payload_length != len(server_hello) - 5:
            raise ValueError("bad SERVER_HELLO length")
        payload = server_hello[5:]
        if len(payload) != 170 or payload[:4] != b"\0\1\0\1":
            raise ValueError("bad SERVER_HELLO layout")
        if payload[4:20] != handshake_id:
            raise ValueError("handshake id mismatch")
        server_ephemeral = payload[20:52]
        server_nonce = payload[52:84]
        server_key_id = payload[84:100]
        server_signature = payload[106:170]
        expected_key_id = sha(b"RekaSerdoba server id", server_public_bytes)[:16]
        if not hmac.compare_digest(server_key_id, expected_key_id):
            raise ValueError("server key id mismatch")
        signature_input = sha(
            b"RekaSerdoba/1 server signature",
            t1,
            sha(payload[:106]),
            client_id,
            handshake_id,
        )
        Ed25519PublicKey.from_public_bytes(server_public_bytes).verify(
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
        signature_input = sha(
            b"RekaSerdoba/1 client signature",
            t2,
            server_signature,
            server_public_bytes,
            client_id,
            client_key_id,
        )
        client_signature = client_signing.sign(signature_input)
        auth_without_finished = (
            client_id
            + client_key_id
            + struct.pack(">IHH", 0, 1280, 0)
            + client_signature
        )
        client_proof = hmac.new(
            c_finished,
            sha(
                b"RekaSerdoba/1 client finished",
                t2,
                auth_without_finished,
            ),
            hashlib.sha256,
        ).digest()
        encrypted_auth = seal_record(
            c_hs_key, c_hs_iv, 4, 0, t2, auth_without_finished + client_proof
        )
        send_ws(sock, 2, encrypted_auth)
        t3 = transcript(t2, encrypted_auth)

        opcode, encrypted_finish = recv_ws(sock)
        if opcode != 2:
            raise ValueError("expected binary SERVER_FINISH")
        finish_plain = open_record(
            s_hs_key, s_hs_iv, 5, 0, t3, encrypted_finish
        )
        parameters, server_proof = finish_plain[:-32], finish_plain[-32:]
        expected_server_proof = hmac.new(
            s_finished,
            sha(b"RekaSerdoba/1 server finished", t3, sha(parameters)),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(server_proof, expected_server_proof):
            raise ValueError("invalid server Finished")
        session_id = parameters[:16]
        assigned_ipv4 = socket.inet_ntoa(parameters[33:37])
        t4 = transcript(t3, encrypted_finish)

        confirmation = hmac.new(
            c_finished,
            sha(b"RekaSerdoba/1 client confirm", t4, session_id),
            hashlib.sha256,
        ).digest()
        encrypted_confirm = seal_record(
            c_hs_key, c_hs_iv, 6, 1, t4, session_id + confirmation
        )
        send_ws(sock, 2, encrypted_confirm)
        t5 = transcript(t4, encrypted_confirm)

        master_secret = expand_label(handshake_secret, "master secret", t5, 32)
        epoch_secret = expand_label(master_secret, "epoch root", t5, 32)
        epoch_context = session_id + (0).to_bytes(4, "big")
        c2s_data_key = expand_label(epoch_secret, "data c2s key", epoch_context, 32)
        s2c_data_key = expand_label(epoch_secret, "data s2c key", epoch_context, 32)
        c2s_data_iv = expand_label(epoch_secret, "data c2s iv", epoch_context, 12)
        s2c_data_iv = expand_label(epoch_secret, "data s2c iv", epoch_context, 12)
        c2s_control_key = expand_label(
            epoch_secret, "control c2s key", epoch_context, 32
        )
        s2c_control_key = expand_label(
            epoch_secret, "control s2c key", epoch_context, 32
        )
        c2s_control_iv = expand_label(
            epoch_secret, "control c2s iv", epoch_context, 12
        )
        s2c_control_iv = expand_label(
            epoch_secret, "control s2c iv", epoch_context, 12
        )
        migration_secret = expand_label(master_secret, "migration", t5, 32)
        control_transcript = sha(
            b"RekaSerdoba/1 control transcript", t5, session_id
        )
        control_sequence_offset = 0
        migration_carrier = None
        if args.migrate_to_h2:
            migration_time = int(time.time())
            migration_nonce = os.urandom(16)
            migration_message = (
                b"RekaSerdoba/1 migration gate"
                + bytes(32)
                + session_id
                + migration_time.to_bytes(8, "big")
                + migration_nonce
                + (1).to_bytes(4, "big")
            )
            migration_token = (
                session_id
                + migration_time.to_bytes(8, "big")
                + migration_nonce
                + hmac.new(
                    migration_secret,
                    migration_message,
                    hashlib.sha256,
                ).digest()
            )
            migration_carrier = H2Carrier(
                host,
                target_ip,
                "/connect/v1/h2",
                b64url_encode(migration_token),
            )
            opcode, challenge_record = recv_ws(migration_carrier)
            if opcode != 2:
                raise ValueError("expected migration PATH_CHALLENGE")
            challenge_plaintext = open_application_record(
                s2c_control_key,
                s2c_control_iv,
                session_id,
                0,
                0,
                True,
                challenge_record,
            )
            if (
                len(challenge_plaintext) != 52
                or challenge_plaintext[:4] != b"\x0c\0\0\x30"
            ):
                raise ValueError("invalid migration PATH_CHALLENGE")
            carrier_id = challenge_plaintext[4:20]
            challenge = challenge_plaintext[20:52]
            control_transcript = transcript(control_transcript, challenge_record)
            path_response = hmac.new(
                migration_secret,
                b"RekaSerdoba/1 path response"
                + session_id
                + carrier_id
                + challenge
                + control_transcript,
                hashlib.sha256,
            ).digest()
            response_record = seal_application_record(
                c2s_control_key,
                c2s_control_iv,
                session_id,
                0,
                0,
                True,
                frame(0x0D, carrier_id + path_response),
            )
            send_ws(migration_carrier, 2, response_record)
            control_transcript = transcript(control_transcript, response_record)
            control_sequence_offset = 1
            sock = migration_carrier

        control_ping = os.urandom(16)
        send_ws(
            sock,
            2,
            seal_application_record(
                c2s_control_key,
                c2s_control_iv,
                session_id,
                0,
                control_sequence_offset,
                True,
                frame(0x02, control_ping),
            ),
        )
        opcode, control_response = recv_ws(sock)
        if opcode != 2:
            raise ValueError("expected encrypted control response")
        control_plaintext = open_application_record(
            s2c_control_key,
            s2c_control_iv,
            session_id,
            0,
            control_sequence_offset,
            True,
            control_response,
        )
        if control_plaintext != frame(0x03, control_ping):
            raise ValueError("invalid encrypted control PONG")

        send_ws(
            sock,
            2,
            seal_application_record(
                c2s_data_key,
                c2s_data_iv,
                session_id,
                0,
                0,
                False,
                frame(0x04),
            ),
        )
        opcode, data_response = recv_ws(sock)
        if opcode != 2:
            raise ValueError("expected encrypted data response")
        data_plaintext = open_application_record(
            s2c_data_key,
            s2c_data_iv,
            session_id,
            0,
            0,
            False,
            data_response,
        )
        if data_plaintext != frame(0x04):
            raise ValueError("invalid encrypted data keepalive")

        echo_request = icmp_echo_request()
        send_ws(
            sock,
            2,
            seal_application_record(
                c2s_data_key,
                c2s_data_iv,
                session_id,
                0,
                1,
                False,
                frame(0x01, echo_request),
            ),
        )
        opcode, tunnel_response = recv_ws(sock)
        if opcode != 2:
            raise ValueError("expected encrypted TUN response")
        tunnel_plaintext = open_application_record(
            s2c_data_key,
            s2c_data_iv,
            session_id,
            0,
            1,
            False,
            tunnel_response,
        )
        if len(tunnel_plaintext) < 32 or tunnel_plaintext[0] != 0x01:
            raise ValueError("invalid TUN response frame")
        tunnel_packet = tunnel_plaintext[4:]
        if (
            tunnel_packet[0] >> 4 != 4
            or tunnel_packet[12:16] != socket.inet_aton("10.77.0.1")
            or tunnel_packet[16:20] != socket.inet_aton("10.77.0.2")
            or tunnel_packet[20] != 0
        ):
            raise ValueError("invalid ICMP echo reply")

        fragmented_echo = icmp_echo_request()
        packet_id = int.from_bytes(os.urandom(4), "big")
        split = len(fragmented_echo) // 2
        fragments = [
            (split, fragmented_echo[split:]),
            (0, fragmented_echo[:split]),
        ]
        for number, (offset, fragment_data) in enumerate(fragments, start=2):
            fragment_body = (
                packet_id.to_bytes(4, "big")
                + len(fragmented_echo).to_bytes(2, "big")
                + offset.to_bytes(2, "big")
                + len(fragment_data).to_bytes(2, "big")
                + fragment_data
            )
            send_ws(
                sock,
                2,
                seal_application_record(
                    c2s_data_key,
                    c2s_data_iv,
                    session_id,
                    0,
                    number,
                    False,
                    frame(0x03, fragment_body),
                ),
            )
        opcode, fragmented_response = recv_ws(sock)
        if opcode != 2:
            raise ValueError("expected fragmented TUN response")
        fragmented_plaintext = open_application_record(
            s2c_data_key,
            s2c_data_iv,
            session_id,
            0,
            2,
            False,
            fragmented_response,
        )
        fragmented_packet = fragmented_plaintext[4:]
        if (
            len(fragmented_plaintext) < 32
            or fragmented_plaintext[0] != 0x01
            or fragmented_packet[20] != 0
        ):
            raise ValueError(
                "invalid fragmented ICMP echo reply "
                f"length={len(fragmented_plaintext)} "
                f"head={fragmented_plaintext[:32].hex()}"
            )

        update_nonce = os.urandom(32)
        update_input = (
            b"RekaSerdoba/1 epoch update"
            + session_id
            + struct.pack(">II", 0, 1)
            + update_nonce
            + control_transcript
        )
        update_context = sha(update_input)
        update_tag = hmac.new(
            epoch_secret, update_input, hashlib.sha256
        ).digest()
        update_body = struct.pack(">II", 0, 1) + update_nonce + update_tag
        update_init = seal_application_record(
            c2s_control_key,
            c2s_control_iv,
            session_id,
            0,
            1 + control_sequence_offset,
            True,
            frame(0x05, update_body),
        )
        send_ws(sock, 2, update_init)
        control_transcript = transcript(control_transcript, update_init)
        opcode, update_ack = recv_ws(sock)
        if opcode != 2:
            raise ValueError("expected key update ACK")
        update_ack_plaintext = open_application_record(
            s2c_control_key,
            s2c_control_iv,
            session_id,
            0,
            1 + control_sequence_offset,
            True,
            update_ack,
        )
        next_secret = hmac.new(
            epoch_secret, update_context, hashlib.sha256
        ).digest()
        next_context = session_id + struct.pack(">I", 1)
        confirm_key = expand_label(
            next_secret, "epoch confirmation", next_context, 32
        )
        expected_ack = hmac.new(
            confirm_key, b"server ack" + update_context, hashlib.sha256
        ).digest()
        if update_ack_plaintext != frame(
            0x06, struct.pack(">I", 1) + expected_ack
        ):
            raise ValueError("invalid key update ACK")
        control_transcript = transcript(control_transcript, update_ack)

        next_c2s_data_key = expand_label(
            next_secret, "data c2s key", next_context, 32
        )
        next_s2c_data_key = expand_label(
            next_secret, "data s2c key", next_context, 32
        )
        next_c2s_data_iv = expand_label(
            next_secret, "data c2s iv", next_context, 12
        )
        next_s2c_data_iv = expand_label(
            next_secret, "data s2c iv", next_context, 12
        )
        next_c2s_control_key = expand_label(
            next_secret, "control c2s key", next_context, 32
        )
        next_s2c_control_key = expand_label(
            next_secret, "control s2c key", next_context, 32
        )
        next_c2s_control_iv = expand_label(
            next_secret, "control c2s iv", next_context, 12
        )
        next_s2c_control_iv = expand_label(
            next_secret, "control s2c iv", next_context, 12
        )
        commit_tag = hmac.new(
            confirm_key, b"client commit" + update_context, hashlib.sha256
        ).digest()
        update_commit = seal_application_record(
            next_c2s_control_key,
            next_c2s_control_iv,
            session_id,
            1,
            0,
            True,
            frame(0x07, struct.pack(">I", 1) + commit_tag),
        )
        send_ws(sock, 2, update_commit)
        control_transcript = transcript(control_transcript, update_commit)
        opcode, update_done = recv_ws(sock)
        if opcode != 2:
            raise ValueError("expected key update DONE")
        update_done_plaintext = open_application_record(
            next_s2c_control_key,
            next_s2c_control_iv,
            session_id,
            1,
            0,
            True,
            update_done,
        )
        expected_done = hmac.new(
            confirm_key, b"server done" + update_context, hashlib.sha256
        ).digest()
        if update_done_plaintext != frame(
            0x08, struct.pack(">I", 1) + expected_done
        ):
            raise ValueError("invalid key update DONE")
        control_transcript = transcript(control_transcript, update_done)

        send_ws(
            sock,
            2,
            seal_application_record(
                next_c2s_data_key,
                next_c2s_data_iv,
                session_id,
                1,
                0,
                False,
                frame(0x04),
            ),
        )
        opcode, rekey_data_response = recv_ws(sock)
        if opcode != 2:
            raise ValueError("expected post-rekey data response")
        rekey_data_plaintext = open_application_record(
            next_s2c_data_key,
            next_s2c_data_iv,
            session_id,
            1,
            0,
            False,
            rekey_data_response,
        )
        if rekey_data_plaintext != frame(0x04):
            raise ValueError("invalid post-rekey data response")

        full_rekey_id = os.urandom(16)
        full_ephemeral = X25519PrivateKey.generate()
        full_ephemeral_public = full_ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        full_client_input = sha(
            b"RekaSerdoba/1 full rekey client",
            session_id,
            struct.pack(">II", 1, 2),
            full_rekey_id,
            full_ephemeral_public,
            control_transcript,
        )
        full_client_signature = client_signing.sign(full_client_input)
        full_init_body = (
            struct.pack(">II", 1, 2)
            + full_rekey_id
            + full_ephemeral_public
            + full_client_signature
        )
        full_init = seal_application_record(
            next_c2s_control_key,
            next_c2s_control_iv,
            session_id,
            1,
            1,
            True,
            frame(0x09, full_init_body),
        )
        send_ws(sock, 2, full_init)
        control_transcript = transcript(control_transcript, full_init)
        opcode, full_reply = recv_ws(sock)
        if opcode != 2:
            raise ValueError("expected full rekey reply")
        full_reply_plaintext = open_application_record(
            next_s2c_control_key,
            next_s2c_control_iv,
            session_id,
            1,
            1,
            True,
            full_reply,
        )
        if (
            len(full_reply_plaintext) != 124
            or full_reply_plaintext[:4] != b"\x0a\0\0x"
        ):
            raise ValueError("invalid full rekey reply frame")
        full_reply_body = full_reply_plaintext[4:]
        if (
            full_reply_body[:8] != struct.pack(">II", 1, 2)
            or full_reply_body[8:24] != full_rekey_id
        ):
            raise ValueError("invalid full rekey reply context")
        full_server_ephemeral = full_reply_body[24:56]
        full_server_signature = full_reply_body[56:120]
        full_server_input = sha(
            b"RekaSerdoba/1 full rekey server",
            session_id,
            struct.pack(">II", 1, 2),
            full_rekey_id,
            full_ephemeral_public,
            full_server_ephemeral,
            control_transcript,
        )
        Ed25519PublicKey.from_public_bytes(server_public_bytes).verify(
            full_server_signature, full_server_input
        )
        control_transcript = transcript(control_transcript, full_reply)
        full_context = sha(
            b"RekaSerdoba/1 full rekey",
            session_id,
            struct.pack(">II", 1, 2),
            full_rekey_id,
            full_ephemeral_public,
            full_server_ephemeral,
            full_client_signature,
            full_server_signature,
            control_transcript,
        )
        full_shared = full_ephemeral.exchange(
            X25519PublicKey.from_public_bytes(full_server_ephemeral)
        )
        full_secret = hmac.new(
            next_secret, full_shared + full_context, hashlib.sha256
        ).digest()
        full_context_key = session_id + struct.pack(">I", 2)
        full_c2s_data_key = expand_label(
            full_secret, "data c2s key", full_context_key, 32
        )
        full_s2c_data_key = expand_label(
            full_secret, "data s2c key", full_context_key, 32
        )
        full_c2s_data_iv = expand_label(
            full_secret, "data c2s iv", full_context_key, 12
        )
        full_s2c_data_iv = expand_label(
            full_secret, "data s2c iv", full_context_key, 12
        )
        full_c2s_control_key = expand_label(
            full_secret, "control c2s key", full_context_key, 32
        )
        full_s2c_control_key = expand_label(
            full_secret, "control s2c key", full_context_key, 32
        )
        full_c2s_control_iv = expand_label(
            full_secret, "control c2s iv", full_context_key, 12
        )
        full_s2c_control_iv = expand_label(
            full_secret, "control s2c iv", full_context_key, 12
        )
        full_confirm_key = expand_label(
            full_secret, "full rekey confirm", full_context, 32
        )
        full_confirm_tag = hmac.new(
            full_confirm_key,
            b"client confirm" + full_context,
            hashlib.sha256,
        ).digest()
        full_confirm = seal_application_record(
            full_c2s_control_key,
            full_c2s_control_iv,
            session_id,
            2,
            0,
            True,
            frame(0x0B, struct.pack(">I", 2) + full_confirm_tag),
        )
        send_ws(sock, 2, full_confirm)
        control_transcript = transcript(control_transcript, full_confirm)
        opcode, full_done = recv_ws(sock)
        if opcode != 2:
            raise ValueError("expected full rekey DONE")
        full_done_plaintext = open_application_record(
            full_s2c_control_key,
            full_s2c_control_iv,
            session_id,
            2,
            0,
            True,
            full_done,
        )
        full_done_tag = hmac.new(
            full_confirm_key,
            b"server done" + full_context,
            hashlib.sha256,
        ).digest()
        if full_done_plaintext != frame(
            0x08, struct.pack(">I", 2) + full_done_tag
        ):
            raise ValueError("invalid full rekey DONE")
        control_transcript = transcript(control_transcript, full_done)
        send_ws(
            sock,
            2,
            seal_application_record(
                full_c2s_data_key,
                full_c2s_data_iv,
                session_id,
                2,
                0,
                False,
                frame(0x04),
            ),
        )
        opcode, full_data_response = recv_ws(sock)
        if opcode != 2:
            raise ValueError("expected post-full-rekey data response")
        full_data_plaintext = open_application_record(
            full_s2c_data_key,
            full_s2c_data_iv,
            session_id,
            2,
            0,
            False,
            full_data_response,
        )
        if full_data_plaintext != frame(0x04):
            raise ValueError("invalid post-full-rekey data response")

        if args.carrier == "wss" and not args.migrate_to_h2:
            ping = os.urandom(8)
            send_ws(sock, 9, ping)
            opcode, pong = recv_ws(sock)
            if opcode != 10 or pong != ping:
                raise ValueError("carrier health check failed")

        print(
            f"carrier={args.carrier} handshake=ok records=ok fragments=ok tun=ok rekey=ok full_rekey=ok migration={'ok' if args.migrate_to_h2 else 'not-run'} session={b64url_encode(session_id)} ipv4={assigned_ipv4}"
        )
        if migration_carrier is not None:
            migration_carrier.__exit__()


if __name__ == "__main__":
    main()
