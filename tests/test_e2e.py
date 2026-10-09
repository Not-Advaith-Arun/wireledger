"""Verified loopback observation, offline audit and checkpoint-constrained repair."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from wireledger.lab import certificates, tls_server

ROOT = Path(__file__).resolve().parents[1]


class EndToEndTests(unittest.TestCase):
    def cli(self, *args, expected=0):
        result = subprocess.run([sys.executable, "-m", "wireledger", *map(str, args)], cwd=ROOT,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return json.loads(result.stdout) if result.stdout else result.stderr

    def test_rotation_independent_views_and_signed_fork_demo(self):
        report = self.cli("demo")
        self.assertTrue(report["offline_certificate_audit"]["ok"])
        self.assertEqual(report["signed_fork"]["history"]["relation"], "divergent")
        self.assertEqual(report["old_prefix"]["history"]["relation"], "left-prefix")
