import json
import tempfile
import unittest
from pathlib import Path

from check_repository_secrets import scan
from generate_sbom import generate


class SupplyChainTests(unittest.TestCase):
    def test_sbom_is_deterministic_and_contains_application(self):
        lock = Path(__file__).resolve().parents[1] / "Cargo.lock"
        first = generate(lock, "0.2.0", "abc")
        second = generate(lock, "0.2.0", "abc")
        self.assertEqual(first, second)
        self.assertEqual(
            first["metadata"]["component"]["name"],
            "rekaserdoba-server",
        )
        self.assertGreater(len(first["components"]), 10)
        json.dumps(first)

    def test_scanner_ignores_normal_repository(self):
        root = Path(__file__).resolve().parents[2]
        self.assertEqual(scan(root), [])


if __name__ == "__main__":
    unittest.main()
