import json
import tempfile
import time
import unittest
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
from reka_service import _valid_ipv4_packet, select_transport_choices, transport_mode
from network_policy import NetworkPolicy
from secret_store import protect, unprotect


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

    def test_frame_bounds(self):
        self.assertEqual(_parse_frames(b"\x01\0\0\x03abc"), [(1, b"abc")])
        with self.assertRaises(ValueError):
            _parse_frames(b"\x01\0\0\x04abc")

    def test_dpapi_round_trip(self):
        value = b"RekaSerdoba test secret"
        self.assertEqual(unprotect(protect(value)), value)


if __name__ == "__main__":
    unittest.main()
