import json
import hashlib
import hmac
import os
import struct
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

from client_core import (
    CarrierChoice,
    CarrierScores,
    FragmentReassembler,
    H3ProcessCarrier,
    ManifestState,
    ReplayWindow,
    RekaSession,
    SessionParameters,
    _close_carrier,
    _parse_frames,
)
from reka_service import (
    TunnelRuntime,
    _valid_ipv4_packet,
    create_diagnostics,
    redact_log,
    select_transport_choices,
    start_service,
    stop_service,
    transport_mode,
    write_status,
)
from network_policy import NetworkPolicy
from secret_store import protect, unprotect
from setup import activate_staged_version, rollback_staged_version
from wintun_adapter import Guid, open_or_create_adapter
from rekaserdoba.tools.probe import (
    H2_RECEIVE_WINDOW,
    expand_h2_receive_window,
    expand_label,
    frame,
    open_application_record,
    seal_application_record,
)


def session_secrets(session_id, epoch_secret, control_transcript=None):
    context = session_id + bytes(4)
    secrets = {
        name: expand_label(epoch_secret, label, context, length)
        for name, label, length in [
            ("c2s_data_key", "data c2s key", 32),
            ("s2c_data_key", "data s2c key", 32),
            ("c2s_data_iv", "data c2s iv", 12),
            ("s2c_data_iv", "data s2c iv", 12),
            ("c2s_control_key", "control c2s key", 32),
            ("s2c_control_key", "control s2c key", 32),
            ("c2s_control_iv", "control c2s iv", 12),
            ("s2c_control_iv", "control s2c iv", 12),
        ]
    }
    secrets["epoch_secret"] = epoch_secret
    secrets["control_transcript"] = control_transcript or bytes(32)
    return secrets


class ClientTests(unittest.TestCase):
    def test_h2_receive_window_covers_high_latency_links(self):
        connection = Mock()
        expand_h2_receive_window(connection, 7)
        increment = H2_RECEIVE_WINDOW - 65535
        self.assertEqual(
            connection.increment_flow_control_window.call_args_list,
            [unittest.mock.call(increment), unittest.mock.call(increment, 7)],
        )

    @patch("network_policy._ps")
    def test_endpoint_route_is_prepared_before_tunnel_activation(self, powershell):
        powershell.side_effect = [
            '{"InterfaceIndex":7,"NextHop":"192.0.2.1","EndpointExists":false}',
            "",
            '{"InterfaceIndex":11,"LowExists":false,"HighExists":false,"Dns":["192.0.2.53"],"PhysicalAliases":["Ethernet"]}',
            "",
            "",
        ]
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "network-policy.json"
            policy = NetworkPolicy(state_path, "service.exe", "RekaSerdoba")
            policy.prepare("192.0.2.10")
            self.assertFalse(
                json.loads(state_path.read_text(encoding="utf-8"))["active"]
            )
            policy.install("192.0.2.10")
            self.assertTrue(
                json.loads(state_path.read_text(encoding="utf-8"))["active"]
            )
            policy.recover()
            self.assertFalse(state_path.exists())
            recovery = powershell.call_args_list[-1].args[0]
            self.assertIn("-InterfaceIndex 11", recovery)
            self.assertIn("-InterfaceIndex 7", recovery)
            self.assertIn("RekaSerdoba IPv6", recovery)

    @patch("network_policy._ps")
    def test_preexisting_routes_are_never_removed(self, powershell):
        powershell.side_effect = [
            '{"InterfaceIndex":7,"NextHop":"192.0.2.1","EndpointExists":true}',
            '{"InterfaceIndex":11,"LowExists":true,"HighExists":true,"Dns":[],"PhysicalAliases":[]}',
            "",
            "",
        ]
        with tempfile.TemporaryDirectory() as temporary:
            policy = NetworkPolicy(
                Path(temporary) / "network-policy.json",
                "service.exe",
                "RekaSerdoba",
            )
            policy.install("192.0.2.10")
            activation = powershell.call_args_list[-2].args[0]
            self.assertNotIn("New-NetRoute", activation)
            policy.recover()
            recovery = powershell.call_args_list[-1].args[0]
            self.assertNotIn("Remove-NetRoute", recovery)

    @patch("rekaserdoba.tools.probe.subprocess.Popen")
    def test_h3_bridge_uses_pinned_server_address(self, popen):
        process = Mock()
        process.stdin = Mock()
        process.stdout = Mock()
        process.stderr = Mock()
        popen.return_value = process
        H3ProcessCarrier(
            Path("bridge.exe"),
            Path("bundle.json"),
            "vpn.example.com",
            443,
            "/h3",
            "192.0.2.10",
        )
        self.assertEqual(
            popen.call_args.args[0][-1],
            "192.0.2.10:443",
        )

    def test_transport_selection(self):
        choices = [
            CarrierChoice("h3", "/h3", "CONNECT", 10),
            CarrierChoice("h2", "/h2", "POST", 20),
            CarrierChoice("wss", "/wss", "GET", 30),
        ]
        self.assertEqual(
            [item.name for item in select_transport_choices(choices, "auto")],
            ["h3", "h2", "wss"],
        )
        self.assertEqual(
            [item.name for item in select_transport_choices(choices, "h2")],
            ["h2"],
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "settings.json"
            path.write_text('{"transport":"wss"}', encoding="utf-8")
            self.assertEqual(transport_mode(path), "wss")

    @patch("reka_service.wait_service_state")
    @patch("reka_service.subprocess.run")
    def test_service_start_waits_until_running(self, run, wait):
        start_service()
        run.assert_called_once_with(["sc.exe", "start", "RekaSerdoba"], check=True)
        wait.assert_called_once_with("RUNNING")

    @patch("reka_service.NetworkPolicy")
    @patch("reka_service.wait_service_state")
    @patch("reka_service.subprocess.run")
    def test_service_stop_waits_and_recovers_network(self, run, wait, policy):
        stop_service()
        run.assert_called_once_with(["sc.exe", "stop", "RekaSerdoba"], check=False)
        wait.assert_called_once_with("STOPPED")
        policy.return_value.recover.assert_called_once_with()

    def test_existing_wintun_adapter_is_reused(self):
        dll = Mock()
        dll.WintunOpenAdapter.return_value = 17
        adapter = open_or_create_adapter(dll, "RekaSerdoba", Guid())
        self.assertEqual(adapter, 17)
        dll.WintunCreateAdapter.assert_not_called()

    def test_wintun_adapter_is_created_when_missing(self):
        dll = Mock()
        dll.WintunOpenAdapter.return_value = 0
        dll.WintunCreateAdapter.return_value = 23
        adapter = open_or_create_adapter(dll, "RekaSerdoba", Guid())
        self.assertEqual(adapter, 23)
        dll.WintunCreateAdapter.assert_called_once()

    def test_fragment_reassembly(self):
        fragments = FragmentReassembler(1280)
        second = (9).to_bytes(4, "big") + (6).to_bytes(2, "big")
        second += (3).to_bytes(2, "big") + (3).to_bytes(2, "big") + b"def"
        first = (9).to_bytes(4, "big") + (6).to_bytes(2, "big")
        first += (0).to_bytes(2, "big") + (3).to_bytes(2, "big") + b"abc"
        self.assertIsNone(fragments.push(second))
        self.assertEqual(fragments.push(first), b"abcdef")

    def test_fragment_pressure_evicts_without_closing_session(self):
        fragments = FragmentReassembler(1280)
        for packet_id in range(65):
            body = packet_id.to_bytes(4, "big") + (2).to_bytes(2, "big")
            body += (0).to_bytes(2, "big") + (1).to_bytes(2, "big") + b"x"
            self.assertIsNone(fragments.push(body))
        self.assertEqual(len(fragments.assemblies), 64)

    def test_replay_window_rejects_records_outside_window(self):
        replay = ReplayWindow(4096)
        self.assertTrue(replay.commit_authenticated(0))
        self.assertTrue(replay.commit_authenticated(4096))
        self.assertFalse(replay.plausible(0))
        self.assertFalse(replay.commit_authenticated(0))

    def test_failed_authentication_does_not_consume_record_number(self):
        session_id = bytes(range(16))
        secrets = session_secrets(session_id, bytes(range(32)))
        session = RekaSession(
            {},
            Mock(),
            SessionParameters(session_id, "10.77.0.2", 24, 1280, 3600),
            secrets,
        )
        record = seal_application_record(
            secrets["s2c_data_key"],
            secrets["s2c_data_iv"],
            session_id,
            0,
            0,
            False,
            frame(0x01, b"packet"),
        )
        damaged = record[:-1] + bytes([record[-1] ^ 1])
        with patch("client_core.recv_ws", return_value=(2, damaged)):
            with self.assertRaises(Exception):
                session.receive()
        with patch("client_core.recv_ws", return_value=(2, record)):
            self.assertEqual(session.receive(), [b"packet"])

    def test_client_batches_full_mtu_packets(self):
        session_id = bytes(range(16))
        secrets = session_secrets(session_id, bytes(range(32)))
        session = RekaSession(
            {},
            Mock(),
            SessionParameters(session_id, "10.77.0.2", 24, 1280, 3600),
            secrets,
        )
        sent = []
        packets = [bytes([value]) * 1280 for value in range(3)]
        with patch("client_core.send_ws", side_effect=lambda _, __, value: sent.append(value)):
            session.send_packets(packets)
        self.assertEqual(len(sent), 1)
        plaintext = open_application_record(
            secrets["c2s_data_key"],
            secrets["c2s_data_iv"],
            session_id,
            0,
            0,
            False,
            sent[0],
        )
        self.assertEqual([body for kind, body in _parse_frames(plaintext)], packets)

    def test_client_completes_server_requested_rekey(self):
        session_id = bytes(range(16))
        epoch_secret = bytes(range(32))
        initial_transcript = bytes(reversed(range(32)))
        secrets = session_secrets(session_id, epoch_secret, initial_transcript)
        session = RekaSession(
            {},
            Mock(),
            SessionParameters(session_id, "10.77.0.2", 24, 1280, 3600),
            secrets,
        )
        request = seal_application_record(
            secrets["s2c_control_key"],
            secrets["s2c_control_iv"],
            session_id,
            0,
            0,
            True,
            frame(0x04, struct.pack(">I", 0)),
        )
        sent = []
        with (
            patch("client_core.recv_ws", return_value=(2, request)),
            patch("client_core.send_ws", side_effect=lambda _, __, value: sent.append(value)),
        ):
            self.assertEqual(session.receive(), [])
        self.assertEqual(len(sent), 1)
        pending = session.pending_rekey
        next_secret = hmac.new(
            epoch_secret, pending["context"], hashlib.sha256
        ).digest()
        next_context = session_id + struct.pack(">I", 1)
        confirm_key = expand_label(next_secret, "epoch confirmation", next_context, 32)
        expected_ack = hmac.new(
            confirm_key,
            b"server ack" + pending["context"],
            hashlib.sha256,
        ).digest()
        ack = seal_application_record(
            secrets["s2c_control_key"],
            secrets["s2c_control_iv"],
            session_id,
            0,
            1,
            True,
            frame(0x06, struct.pack(">I", 1) + expected_ack),
        )
        with (
            patch("client_core.recv_ws", return_value=(2, ack)),
            patch("client_core.send_ws", side_effect=lambda _, __, value: sent.append(value)),
        ):
            self.assertEqual(session.receive(), [])
        next_s2c_control_key = expand_label(
            next_secret, "control s2c key", next_context, 32
        )
        next_s2c_control_iv = expand_label(
            next_secret, "control s2c iv", next_context, 12
        )
        done_tag = hmac.new(
            confirm_key,
            b"server done" + pending["context"],
            hashlib.sha256,
        ).digest()
        done = seal_application_record(
            next_s2c_control_key,
            next_s2c_control_iv,
            session_id,
            1,
            0,
            True,
            frame(0x08, struct.pack(">I", 1) + done_tag),
        )
        with patch("client_core.recv_ws", return_value=(2, done)):
            self.assertEqual(session.receive(), [])
        self.assertEqual(session.epoch, 1)
        self.assertIsNone(session.pending_rekey)

    def test_minimum_lifetime_does_not_expire_immediately(self):
        session_id = bytes(range(16))
        session = RekaSession(
            {},
            Mock(),
            SessionParameters(session_id, "10.77.0.2", 24, 1280, 60),
            session_secrets(session_id, bytes(range(32))),
        )
        self.assertFalse(session.expired())

    def test_carrier_close_is_idempotent(self):
        class ClosedCarrier:
            def close(self):
                raise OSError(22, "closed")

        _close_carrier(ClosedCarrier())

    def test_ipv4_tunnel_filter(self):
        packet = bytearray(20)
        packet[0] = 0x45
        packet[2:4] = (20).to_bytes(2, "big")
        packet[12:16] = bytes((10, 77, 0, 2))
        self.assertTrue(_valid_ipv4_packet(bytes(packet), "10.77.0.2"))
        packet[0] = 0x60
        self.assertFalse(_valid_ipv4_packet(bytes(packet), "10.77.0.2"))

    def test_manifest_rollback_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = ManifestState(Path(temporary) / "state.json")
            state.accept(7)
            with self.assertRaises(ValueError):
                state.accept(6)
            self.assertEqual(ManifestState(state.path).sequence, 7)

    def test_carrier_failure_changes_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            scores = CarrierScores(Path(temporary) / "scores.json")
            choices = [
                CarrierChoice("h3", "/h3", "CONNECT", 10),
                CarrierChoice("h2", "/h2", "POST", 20),
            ]
            scores.failure("h3")
            self.assertEqual(scores.order(choices)[0].name, "h2")
            value = json.loads(scores.path.read_text(encoding="utf-8"))
            self.assertGreater(value["h3"]["cooldown"], time.time())
            self.assertGreater(scores.wait_seconds("h3"), 0)
            self.assertGreater(scores.next_retry_seconds(choices), 0)

    def test_endpoint_failure_rotates_address(self):
        with tempfile.TemporaryDirectory() as temporary:
            scores = CarrierScores(Path(temporary) / "scores.json")
            choices = [CarrierChoice("h3", "/h3", "CONNECT", 10)]
            addresses = ["192.0.2.10", "192.0.2.11"]
            scores.failure("h3", addresses[0])
            ordered = scores.order_candidates(addresses, choices)
            self.assertEqual(ordered[0][0], addresses[1])
            self.assertGreater(
                scores.wait_seconds("h3", endpoint=addresses[0]),
                0,
            )
            self.assertEqual(
                scores.wait_seconds("h3", endpoint=addresses[1]),
                0,
            )

    def test_diagnostics_excludes_secrets_and_redacts_logs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                "ROOT": root,
                "STATUS": root / "status.json",
                "SCORES": root / "carrier-scores.json",
                "SETTINGS": root / "settings.json",
                "LOG_PATH": root / "service.log",
            }
            paths["STATUS"].write_text('{"state":"connected"}', encoding="utf-8")
            paths["SCORES"].write_text('{"h3":{"failures":0}}', encoding="utf-8")
            paths["SETTINGS"].write_text('{"transport":"auto"}', encoding="utf-8")
            paths["LOG_PATH"].write_text(
                "normal line\nauthorization Bearer secret\n",
                encoding="utf-8",
            )
            bundle = root / "device.dpapi"
            bundle.write_bytes(b"private")
            output = root / "diagnostics.zip"
            with patch.multiple("reka_service", **paths):
                create_diagnostics(output)
            with zipfile.ZipFile(output) as archive:
                self.assertNotIn("device.dpapi", archive.namelist())
                log = archive.read("service.log").decode("utf-8")
                self.assertIn("normal line", log)
                self.assertIn("[redacted]", log)
                self.assertNotIn("secret", log)

    def test_status_includes_traffic_counters(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            status = root / "status.json"
            with patch.multiple("reka_service", ROOT=root, STATUS=status):
                write_status(
                    "connected",
                    "h3",
                    endpoint="192.0.2.10",
                    traffic={
                        "tx_packets": 7,
                        "tx_bytes": 700,
                        "rx_packets": 9,
                        "rx_bytes": 900,
                    },
                )
            value = json.loads(status.read_text(encoding="utf-8"))
            self.assertEqual(value["traffic"]["rx_bytes"], 900)

    def test_runtime_bundle_replaces_stale_plaintext_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stale = root / "rs-device-stale.json"
            stale.write_text("private", encoding="utf-8")
            runtime = TunnelRuntime(Mock())
            with (
                patch("reka_service.ROOT", root),
                patch.dict(os.environ, {"REKASERDOBA_DEV_ACL": "1"}),
            ):
                active = runtime._materialize_bundle({"client_id_b64": "value"})
            self.assertFalse(stale.exists())
            self.assertEqual(
                json.loads(active.read_text(encoding="utf-8"))["client_id_b64"],
                "value",
            )
            active.unlink()

    def test_log_redaction_is_bounded(self):
        value = redact_log("x" * 5000)
        self.assertLessEqual(len(value), 2001)

    def test_staged_update_can_restore_previous_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "RekaSerdoba"
            destination.mkdir()
            (destination / "version.txt").write_text("old", encoding="utf-8")

            def copy_new(path):
                path.mkdir()
                (path / "version.txt").write_text("new", encoding="utf-8")
                (path / "reka-service.exe").write_bytes(b"service")

            with patch("setup.copy_assets", side_effect=copy_new):
                previous = activate_staged_version(destination)
            self.assertEqual(
                (destination / "version.txt").read_text(encoding="utf-8"),
                "new",
            )
            with patch("setup.run"):
                rollback_staged_version(destination, previous)
            self.assertEqual(
                (destination / "version.txt").read_text(encoding="utf-8"),
                "old",
            )

    def test_staged_activation_restores_previous_version_on_swap_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "RekaSerdoba"
            destination.mkdir()
            (destination / "version.txt").write_text("old", encoding="utf-8")

            def copy_new(path):
                path.mkdir()
                (path / "version.txt").write_text("new", encoding="utf-8")

            real_replace = os.replace

            def replace(source, target):
                if Path(source).name.endswith(".new"):
                    raise OSError("swap failed")
                return real_replace(source, target)

            with (
                patch("setup.copy_assets", side_effect=copy_new),
                patch("setup.os.replace", side_effect=replace),
            ):
                with self.assertRaises(OSError):
                    activate_staged_version(destination)
            self.assertEqual(
                (destination / "version.txt").read_text(encoding="utf-8"),
                "old",
            )

    def test_frame_bounds(self):
        self.assertEqual(_parse_frames(b"\x01\0\0\x03abc"), [(1, b"abc")])
        with self.assertRaises(ValueError):
            _parse_frames(b"\x01\0\0\x04abc")

    def test_dpapi_round_trip(self):
        value = b"RekaSerdoba test secret"
        self.assertEqual(unprotect(protect(value)), value)


if __name__ == "__main__":
    unittest.main()
