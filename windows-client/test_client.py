import json
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
    _close_carrier,
    _parse_frames,
)
from reka_service import (
    _valid_ipv4_packet,
    create_diagnostics,
    redact_log,
    select_transport_choices,
    transport_mode,
)
from network_policy import NetworkPolicy
from secret_store import protect, unprotect
from setup import activate_staged_version, rollback_staged_version


class ClientTests(unittest.TestCase):
    @patch("network_policy._ps")
    def test_endpoint_route_is_prepared_before_tunnel_activation(self, powershell):
        powershell.side_effect = [
            '{"InterfaceIndex":7,"NextHop":"192.0.2.1"}',
            "",
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

    def test_frame_bounds(self):
        self.assertEqual(_parse_frames(b"\x01\0\0\x03abc"), [(1, b"abc")])
        with self.assertRaises(ValueError):
            _parse_frames(b"\x01\0\0\x04abc")

    def test_dpapi_round_trip(self):
        value = b"RekaSerdoba test secret"
        self.assertEqual(unprotect(protect(value)), value)


if __name__ == "__main__":
    unittest.main()
