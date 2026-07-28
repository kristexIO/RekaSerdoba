#!/usr/bin/env python3
import argparse
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

import identity
import manifest


class IdentityRotationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.server = self.root / "server.json"
        self.authority = self.root / "authority.json"
        identity.atomic_json(
            self.server,
            {
                "listen": "127.0.0.1:9080",
                "authority": "vpn.example.com:443",
                "tunnel_path": "/connect/v1/stream",
                "server_signing_seed_b64": identity.b64e(os.urandom(32)),
                "clients": [],
                "tun": {},
            },
        )

    def tearDown(self):
        self.temporary.cleanup()

    def quiet(self, function, args, *extra):
        with contextlib.redirect_stdout(io.StringIO()):
            function(args, *extra)

    def build_manifest(self, server, name):
        output = self.root / name
        self.quiet(
            manifest.generate,
            argparse.Namespace(
                server=server,
                state=self.authority,
                output=output,
                ip="192.0.2.10",
                valid_days=30,
            ),
        )
        state = json.loads(self.authority.read_text(encoding="utf-8"))
        return manifest.verify_bytes(
            output.read_bytes(),
            manifest.b64d(state["signing_public_key_b64"]),
        )

    def test_stage_activate_retire(self):
        rotation = self.root / "rotation.json"
        staged = self.root / "staged.json"
        active = self.root / "active.json"
        retired = self.root / "retired.json"
        self.quiet(
            identity.stage,
            argparse.Namespace(
                server=self.server,
                rotation=rotation,
                output=staged,
                overlap_days=14,
                identity_days=180,
            ),
        )
        staged_manifest = self.build_manifest(staged, "staged.cbor")
        self.assertEqual(len(staged_manifest[8]), 2)
        self.assertIn(staged_manifest[9][0][4], [item[1] for item in staged_manifest[8]])
        self.quiet(
            identity.transition,
            argparse.Namespace(
                server=staged,
                rotation=rotation,
                output=active,
                identity_days=180,
                force=False,
            ),
            "active",
        )
        active_manifest = self.build_manifest(active, "active.cbor")
        active_config = json.loads(active.read_text(encoding="utf-8"))
        active_public = identity.public_from_seed(
            active_config["server_signing_seed_b64"]
        )
        self.assertEqual(len(active_manifest[8]), 2)
        self.assertEqual(active_manifest[9][0][4], identity.key_id(active_public))
        with self.assertRaisesRegex(ValueError, "overlap period has not ended"):
            self.quiet(
                identity.transition,
                argparse.Namespace(
                    server=active,
                    rotation=rotation,
                    output=retired,
                    identity_days=180,
                    force=False,
                ),
                "retired",
            )
        self.quiet(
            identity.transition,
            argparse.Namespace(
                server=active,
                rotation=rotation,
                output=retired,
                identity_days=180,
                force=True,
            ),
            "retired",
        )
        retired_manifest = self.build_manifest(retired, "retired.cbor")
        self.assertEqual(len(retired_manifest[8]), 1)
        self.assertEqual(retired_manifest[9][0][4], retired_manifest[8][0][1])


if __name__ == "__main__":
    unittest.main()
