"""Verified loopback observation, offline audit and checkpoint-constrained repair."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from wireledger.lab import certificates, tls_server

ROOT = Path(__file__).resolve().parents[1]


class EndToEndTests(unittest.TestCase):
    def cli(self, *args, expected=0, timeout=30):
        result = subprocess.run([sys.executable, "-m", "wireledger", *map(str, args)], cwd=ROOT,
                                capture_output=True, text=True, timeout=timeout)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return json.loads(result.stdout) if result.stdout else result.stderr

    def test_rotation_independent_views_and_signed_fork_demo(self):
        report = self.cli("demo")
        self.assertTrue(report["offline_certificate_audit"]["ok"])
        self.assertEqual(report["signed_fork"]["history"]["relation"], "divergent")
        self.assertEqual(report["old_prefix"]["history"]["relation"], "left-prefix")

    def test_observe_audit_retain_recover_and_reject_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, retained = root / "witness", root / "anchors"
            self.cli("init", state)
            ca, variants = certificates(root)
            cert, private = variants[0]
            public, ledger = state / "witness.pub", state / "observations.jsonl"
            with tls_server(cert, private) as port:
                self.cli("observe", state, "localhost", "--port", port, "--connect-ip", "127.0.0.1",
                         "--ca-file", ca, "--timeout", "3")
            self.assertTrue(self.cli("audit", ledger, "--public-key", public, "--ca-file", ca)["ok"])
            before_audit = ledger.read_bytes()
            fifo = root / "unavailable-ca.pem"
            os.mkfifo(fifo)
            self.cli("audit", ledger, "--public-key", public, "--ca-file", fifo, expected=1, timeout=3)
            self.assertEqual(ledger.read_bytes(), before_audit)
            ca_link = root / "trusted-ca-link.pem"
            ca_link.symlink_to(ca)
            self.assertTrue(self.cli("audit", ledger, "--public-key", public, "--ca-file", ca_link)["ok"])
            timeline = self.cli("timeline", ledger, "--public-key", public, "--json")
            self.assertTrue(timeline)
            checkpoint = root / "checkpoint.json"
            self.cli("checkpoint", state, checkpoint)
            self.cli("retain-checkpoint", checkpoint, "--store", retained, "--public-key", public)
            original = ledger.read_bytes()
            ledger.write_bytes(original + b'{"body":')
            damaged = ledger.read_bytes()
            plan = root / "plan.json"
            preview = self.cli("recovery-preview", ledger, "--public-key", public, "--store", retained)
            plan.write_text(json.dumps(preview))
            self.assertEqual(ledger.read_bytes(), damaged)
            evidence = root / "evidence"
            self.cli("recovery-apply", ledger, "--public-key", public, "--store", retained,
                     "--plan", plan, "--evidence", evidence)
            self.assertEqual(ledger.read_bytes(), original)
            self.assertTrue(self.cli("check-retained", ledger, "--public-key", public, "--store", retained)["ok"])
            ledger.write_bytes(original.replace(b"localhost", b"tampered!", 1))
            self.cli("verify", ledger, "--public-key", public, expected=1)
            self.cli("recovery-preview", ledger, "--public-key", public, "--store", retained, expected=1)
