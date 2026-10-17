"""Verified loopback observation, offline audit and checkpoint-constrained repair."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from wireledger.lab import certificates, tls_server
from wireledger.ledger import append, canonical, load_private, make_checkpoint, verify

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
            self.assertEqual(timeline["total_records"], 2)
            selected = self.cli("timeline", ledger, "--public-key", public, "--json",
                                "--host", "localhost", "--port", port, "--vantage", "local", "--changes-only")
            self.assertEqual(selected["selected_records"], 1)
            self.assertEqual(selected["results"][0]["sequence"], 1)
            missing = self.cli("timeline", ledger, "--public-key", public, "--json", "--host", "absent.test")
            self.assertEqual(missing["results"], [])
            future = self.cli("timeline", ledger, "--public-key", public, "--json", "--since", "2100-01-01T00:00:00Z")
            self.assertEqual(future["results"], [])
            self.cli("timeline", ledger, "--public-key", public, "--since", "2026-01-01", expected=1)
            checkpoint = root / "checkpoint.json"
            self.cli("checkpoint", state, checkpoint)
            self.cli("retain-checkpoint", checkpoint, "--store", retained, "--public-key", public)
            retained_bytes = {p.name: p.read_bytes() for p in retained.glob("anchor-*.json")}
            inventory = self.cli("list-retained", "--store", retained, "--public-key", public)
            self.assertEqual(inventory["count"], 1)
            self.assertEqual(inventory["checkpoints"][0]["count"], 2)
            self.assertEqual(inventory["conflicting_heads"], [])
            self.assertFalse(inventory["ancestry_unproven"])
            self.assertEqual(retained_bytes, {p.name: p.read_bytes() for p in retained.glob("anchor-*.json")})
            foreign = root / "foreign"
            self.cli("init", foreign)
            self.cli("list-retained", "--store", retained, "--public-key", foreign / "witness.pub", expected=1)
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
            key = load_private(state / "witness.key")  # Disposable witness created by this journey.
            records = verify(ledger, key.public_key())
            sampled = root / "synthetic-clock.jsonl"
            sampled.touch()
            for stamp in ("2026-01-01T00:00:00Z", "2026-01-01T00:02:00Z", "2026-01-01T00:01:00Z"):
                append(sampled, key, {**records[0]["body"]["observation"], "observed_at": stamp})
            views = self.cli("vantages", sampled, "--public-key", public)
            self.assertEqual(views["results"][0]["coverage"], "one-view-only")
            other = json.loads(json.dumps(records[0]["body"]["observation"]))
            other.update(vantage="other-view", peer_ip="127.0.0.2", connect_ip="127.0.0.2")
            resolution = other["evidence"]["resolution"]
            resolution["query"] = "127.0.0.2"
            for address in resolution["candidates"] + resolution["attempted"] + [resolution["selected"]] + [a["address"] for a in other["network_attempt"]["attempts"]]:
                address["ip"] = "127.0.0.2"  # Deliberately self-consistent synthetic observer claim.
            append(sampled, key, other)
            views = self.cli("vantages", sampled, "--public-key", public)
            self.assertEqual(views["results"][0]["coverage"], "multiple-views")
            self.assertIn("peer_ip", views["results"][0]["comparisons"][0]["differences"])
            self.assertEqual(views["results"][0]["views"]["local"]["sequence"], 3)
            append(sampled, key, {**records[0]["body"]["observation"], "vantage": "third-view"})
            limited = self.cli("vantages", sampled, "--public-key", public, "--max-pairs", "1", expected=2)
            self.assertFalse(limited["comparisons_complete"])
            self.assertEqual(limited["results"][0]["omitted_pairs"], 2)
            sampled_before = sampled.read_bytes()
            continuity = self.cli("continuity", sampled, "--public-key", public,
                                  "--as-of", "2026-01-01T00:05:00Z", "--max-gap-seconds", "90", expected=2)
            group = next(row for row in continuity["results"] if row["vantage"] == "local")
            self.assertEqual(group["gaps"][0]["seconds"], 120)
            self.assertEqual(group["clock_reversals"][0]["seconds"], -60)
            self.assertEqual(group["age_seconds"], 240)
            self.assertEqual(group["sampling_state"], "stale-sample")
            self.cli("continuity", sampled, "--public-key", public, "--as-of", "2026-01-01", expected=1)
            self.cli("continuity", sampled, "--public-key", public, "--as-of", "2026-01-01T00:05:00Z", "--max-gap-seconds", "nan", expected=1)
            self.assertEqual(sampled_before, sampled.read_bytes())
            fork = root / "fork.jsonl"
            fork.write_bytes(canonical(records[0]) + b"\n")
            append(fork, key, {**records[1]["body"]["observation"], "vantage": "deliberate-fork"})
            fork_checkpoint = root / "fork-checkpoint.json"
            fork_checkpoint.write_bytes(canonical(make_checkpoint(verify(fork, key.public_key()), key)))
            self.cli("retain-checkpoint", fork_checkpoint, "--store", retained, "--public-key", public, expected=2)
            conflicts = self.cli("list-retained", "--store", retained, "--public-key", public, expected=2)
            self.assertEqual(conflicts["count"], 2)
            self.assertEqual(len(conflicts["conflicting_heads"]), 1)
            self.assertEqual(len(conflicts["conflicting_heads"][0]["heads"]), 2)
            ledger.write_bytes(original.replace(b"localhost", b"tampered!", 1))
            self.cli("verify", ledger, "--public-key", public, expected=1)
            self.cli("timeline", ledger, "--public-key", public, "--json", "--host", "absent.test", expected=1)
            self.cli("recovery-preview", ledger, "--public-key", public, "--store", retained, expected=1)
