"""Verified loopback observation, offline audit and checkpoint-constrained repair."""
import json
import hashlib
from datetime import datetime, timedelta
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import socket
import threading
import time
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
            inventory = self.cli("endpoints", ledger, "--public-key", public)
            self.assertEqual(inventory["total_records"], 2)
            self.assertEqual(inventory["results"][0]["status_counts"], {"verified": 2})
            self.assertEqual(inventory["results"][0]["latest"]["sequence"], 2)
            self.assertEqual(ledger.read_bytes(), before_audit)
            expected_file = root / "expected.json"
            intended = {"host": "LOCALHOST.", "port": port, "vantage": "local"}
            expected_file.write_text(json.dumps([intended, {**intended, "vantage": "absent"}]))
            policy_bytes = expected_file.read_bytes()
            coverage = self.cli("coverage", ledger, "--public-key", public, "--expected", expected_file, expected=2)
            self.assertEqual({r["vantage"]: r["collection_state"] for r in coverage["results"]},
                             {"local": "observed-verified", "absent": "missing"})
            self.assertEqual(expected_file.read_bytes(), policy_bytes)
            expected_file.write_text(json.dumps([intended]))
            self.assertFalse(self.cli("coverage", ledger, "--public-key", public, "--expected", expected_file)["needs_attention"])
            for policy in ([intended, {**intended, "host": "localhost"}], [{**intended, "port": True}], []):
                expected_file.write_text(json.dumps(policy))
                self.cli("coverage", ledger, "--public-key", public, "--expected", expected_file, expected=1)
            expected_file.write_text(json.dumps([intended]))
            self.assertEqual(ledger.read_bytes(), before_audit)
            strict_history = root / "coverage-with-extra.jsonl"
            strict_history.write_bytes(before_audit)
            append(strict_history, load_private(state / "witness.key"), {
                "host": "unexpected.test", "port": 443, "vantage": "extra",
                "status": "error", "error": "Synthetic extra collection claim", "observed_at": "2026-09-20T12:00:00Z"})
            args = ("coverage", strict_history, "--public-key", public, "--expected", expected_file)
            advisory = self.cli(*args)
            self.assertFalse(advisory["needs_attention"])
            self.assertEqual(advisory["unexpected_groups"], [{"host": "unexpected.test", "port": 443, "vantage": "extra"}])
            exact = self.cli(*args, "--exact", expected=2)
            self.assertTrue(exact["exact_collection_required"])
            self.assertTrue(exact["needs_attention"])
            self.assertEqual(exact["results"], advisory["results"])
            self.assertFalse(self.cli("coverage", ledger, "--public-key", public, "--expected", expected_file,
                                      "--exact")["needs_attention"])
            saved = strict_history.read_bytes()
            rows = [json.loads(line) for line in saved.splitlines()]
            rows[-1]["body"]["observation"]["error"] = "Unsigned excluded group change"
            strict_history.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
            damaged = strict_history.read_bytes()
            self.cli(*args, "--exact", expected=1)
            self.assertEqual(strict_history.read_bytes(), damaged)
            self.assertEqual(ledger.read_bytes(), before_audit)
            fifo = root / "unavailable-ca.pem"
            os.mkfifo(fifo)
            self.cli("audit", ledger, "--public-key", public, "--ca-file", fifo, expected=1, timeout=3)
            self.assertEqual(ledger.read_bytes(), before_audit)
            ca_link = root / "trusted-ca-link.pem"
            ca_link.symlink_to(ca)
            self.assertTrue(self.cli("audit", ledger, "--public-key", public, "--ca-file", ca_link)["ok"])
            timeline = self.cli("timeline", ledger, "--public-key", public, "--json", "--at-observed-time")
            self.assertEqual(timeline["total_records"], 2)
            first_page = self.cli("timeline", ledger, "--public-key", public, "--json", "--limit", "1", "--at-observed-time")
            self.assertEqual(first_page["matching_records"], 2)
            self.assertEqual(first_page["remaining_after_cursor"], 2)
            self.assertTrue(first_page["has_more"])
            self.assertEqual(first_page["next_after_sequence"], 1)
            second_page = self.cli("timeline", ledger, "--public-key", public, "--json", "--limit", "1",
                                   "--after-sequence", str(first_page["next_after_sequence"]), "--at-observed-time")
            self.assertEqual(first_page["results"] + second_page["results"], timeline["results"])
            self.assertFalse(second_page["has_more"])
            self.assertIsNone(second_page["next_after_sequence"])
            self.assertEqual(second_page["remaining_after_cursor"], 1)
            self.assertEqual(second_page["results"][0]["changes"], [])
            for args in (("--after-sequence", "2"), ("--after-sequence", "1", "--changes-only"),
                         ("--host", "absent.test", "--limit", "1")):
                empty = self.cli("timeline", ledger, "--public-key", public, "--json", *args)
                self.assertEqual(empty["results"], [])
                self.assertFalse(empty["has_more"])
                self.assertIsNone(empty["next_after_sequence"])
            for args in (("--limit", "0"), ("--limit", "1001"), ("--after-sequence", "-1")):
                self.cli("timeline", ledger, "--public-key", public, *args, expected=1)
            page_view = subprocess.check_output([sys.executable, "-m", "wireledger", "timeline", str(ledger),
                "--public-key", str(public), "--html", "--limit", "1"], cwd=ROOT, text=True)
            self.assertIn("next after sequence: 1", page_view)
            self.assertIn("not a locked snapshot", page_view)
            page_text = subprocess.check_output([sys.executable, "-m", "wireledger", "timeline", str(ledger),
                "--public-key", str(public), "--limit", "1"], cwd=ROOT, text=True)
            self.assertIn("Page: 1 returned; 2 after cursor; 2 matching; next after sequence: 1", page_text)
            view = subprocess.check_output([sys.executable, "-m", "wireledger", "timeline", str(ledger),
                "--public-key", str(public), "--html", "--max-rows", "1"], cwd=ROOT, text=True)
            self.assertIn("Showing 1 of 2 selected samples from 2 verified records", view)
            self.assertIn("observer claims", view)
            self.assertNotIn("<script", view)
            self.assertNotIn("PRIVATE KEY", view)
            self.cli("timeline", ledger, "--public-key", public, "--html", "--max-rows", "0", expected=1)
            self.assertEqual(ledger.read_bytes(), before_audit)
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
            expires = records[0]["body"]["observation"]["not_after"]
            nearing = self.cli("expiry", ledger, "--public-key", public, "--as-of", expires, "--within-days", "1", expected=2)
            self.assertEqual(nearing["results"][0]["certificate_window"], "expires-within-horizon")
            after_expiry = (datetime.fromisoformat(expires.replace("Z", "+00:00")) + timedelta(seconds=1)).isoformat()
            expired = self.cli("expiry", ledger, "--public-key", public, "--as-of", after_expiry, expected=2)
            self.assertEqual(expired["results"][0]["certificate_window"], "expired")
            self.cli("expiry", ledger, "--public-key", public, "--as-of", expires, "--within-days", "nan", expected=1)
            self.assertEqual(ledger.read_bytes(), original)

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
            reuse_history = root / "reuse.jsonl"
            reuse_history.touch()
            first = records[0]["body"]["observation"]
            append(reuse_history, key, first)
            second = {**first, "port": first["port"] + 1}
            # Port is an observer claim outside certificate evidence identity.
            second = json.loads(json.dumps(second))
            # Use legacy supported observation shape for synthetic cross-port claims.
            second.pop("evidence", None)
            second.pop("network_attempt", None)
            append(reuse_history, key, second)
            reuse_bytes = reuse_history.read_bytes()
            reused = self.cli("fingerprint-reuse", reuse_history, "--public-key", public)
            self.assertEqual(reused["shared"]["spki_sha256"][0]["distinct_endpoints"], 2)
            self.assertEqual(reused["shared"]["certificate_sha256"][0]["distinct_endpoints"], 2)
            self.assertEqual(reuse_history.read_bytes(), reuse_bytes)
            append(reuse_history, key, {"host": second["host"], "port": second["port"], "vantage": second["vantage"], "status": "error", "error": "Synthetic failure", "observed_at": second["observed_at"]})
            failed_latest = self.cli("fingerprint-reuse", reuse_history, "--public-key", public)
            self.assertEqual(failed_latest["shared"]["spki_sha256"], [])
            self.assertEqual(len(failed_latest["unavailable_samples"]), 1)
            failed_inventory = self.cli("endpoints", reuse_history, "--public-key", public)
            failed_group = next(r for r in failed_inventory["results"] if r["port"] == second["port"])
            self.assertEqual(failed_group["latest"]["status"], "error")
            self.assertIsNone(failed_group["latest"]["certificate_sha256"])
            self.assertEqual(failed_group["status_counts"], {"verified":1, "error":1})
            expected_file.write_text(json.dumps([{k: second[k] for k in ("host", "port", "vantage")}]))
            failed_coverage = self.cli("coverage", reuse_history, "--public-key", public, "--expected", expected_file, expected=2)
            self.assertEqual(failed_coverage["results"][0]["collection_state"], "latest-failed")
            self.assertEqual(len(failed_coverage["unexpected_groups"]), 1)
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
            self.cli("endpoints", ledger, "--public-key", public, expected=1)
            self.cli("coverage", ledger, "--public-key", public, "--expected", expected_file, expected=1)
            self.cli("timeline", ledger, "--public-key", public, "--json", "--host", "absent.test", expected=1)
            self.cli("timeline", ledger, "--public-key", public, "--json", "--after-sequence", "1000", "--limit", "1", expected=1)
            self.cli("recovery-preview", ledger, "--public-key", public, "--store", retained, expected=1)


    def test_loopback_handshakes_reject_wrong_hostname_and_untrusted_ca_before_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "witness"
            self.cli("init", state)
            ca, variants = certificates(root)
            other = root / "untrusted-ca"
            other.mkdir()
            wrong_ca, _ = certificates(other)
            cert, private = variants[0]
            with tls_server(cert, private) as port:
                failures = [self.cli("observe", state, host, "--port", port, "--connect-ip", "127.0.0.1",
                    "--ca-file", trust, "--timeout", "3", expected=2)["observation"]
                    for host, trust in (("wrong.invalid", ca), ("localhost", wrong_ca))]
                success = self.cli("observe", state, "localhost", "--port", port, "--connect-ip", "127.0.0.1",
                    "--ca-file", ca, "--timeout", "3")["observation"]
            for failed in failures:
                self.assertEqual(failed["status"], "verification-failed")
                self.assertIsInstance(failed["error_code"], int)
                self.assertTrue(failed["connection_attempt"]["verifier_policy"]["check_hostname"])
                self.assertNotIn("evidence", failed)
                self.assertNotIn("certificate_sha256", failed)
            self.assertEqual(success["status"], "verified")
            ledger, public = state / "observations.jsonl", state / "witness.pub"
            saved = ledger.read_bytes()
            self.assertEqual(self.cli("verify", ledger, "--public-key", public)["count"], 3)
            inventory = self.cli("endpoints", ledger, "--public-key", public)
            localhost = next(row for row in inventory["results"] if row["host"] == "localhost")
            self.assertEqual(localhost["status_counts"], {"verification-failed": 1, "verified": 1})
            self.assertEqual(localhost["latest"]["sequence"], 3)
            wrong = next(row for row in inventory["results"] if row["host"] == "wrong.invalid")
            self.assertEqual(wrong["latest"]["status"], "verification-failed")
            self.assertEqual(ledger.read_bytes(), saved)

    def test_stalled_loopback_tls_becomes_signed_failed_observation_within_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "witness"
            self.cli("init", state)
            ca, _ = certificates(root)
            release, accepted = threading.Event(), threading.Event()
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(3)
                port = listener.getsockname()[1]
                def stalled_peer():
                    try:
                        connection, _ = listener.accept()
                    except OSError:
                        return
                    with connection:
                        accepted.set()
                        release.wait(3)
                worker = threading.Thread(target=stalled_peer, daemon=True)
                worker.start()
                try:
                    started = time.monotonic()
                    result = self.cli("observe", state, "localhost", "--port", port, "--connect-ip", "127.0.0.1",
                        "--ca-file", ca, "--timeout", "0.3", expected=2, timeout=5)
                    self.assertLess(time.monotonic() - started, 3)
                    self.assertTrue(accepted.is_set())
                finally:
                    release.set()
                    worker.join(timeout=4)
                self.assertFalse(worker.is_alive())
            observation = result["observation"]
            self.assertEqual(observation["status"], "connection-failed")
            self.assertEqual(observation["network_attempt"]["phase"], "tls")
            self.assertEqual(observation["network_attempt"]["attempts"][-1]["status"], "tls-failed")
            self.assertEqual(observation["network_attempt"]["timeout_seconds"], 0.3)
            self.assertTrue(observation["network_attempt"]["deadline_exceeded"])
            self.assertNotIn("certificate_sha256", observation)
            ledger, public = state / "observations.jsonl", state / "witness.pub"
            saved = ledger.read_bytes()
            verified = self.cli("verify", ledger, "--public-key", public)
            self.assertTrue(verified["valid"])
            self.assertEqual(verified["count"], 1)
            expiry = self.cli("expiry", ledger, "--public-key", public, "--as-of", observation["observed_at"], expected=2)
            self.assertEqual(expiry["results"][0]["certificate_window"], "unavailable")
            self.assertEqual(expiry["results"][0]["observed_status"], "connection-failed")
            self.assertEqual(ledger.read_bytes(), saved)

    def test_expiry_distinguishes_leaf_windows_observer_age_and_latest_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "witness"
            self.cli("init", state)
            ledger, public = state / "observations.jsonl", state / "witness.pub"
            key = load_private(state / "witness.key")
            sample = {"host": "fixture.test", "port": 443, "vantage": "local", "status": "verified",
                      "observed_at": "2026-10-12T13:00:00Z", "not_before": "2026-10-12T13:00:00Z", "not_after": "2026-10-12T14:00:00Z",
                      "certificate_sha256": "a" * 64, "spki_sha256": "b" * 64}
            append(ledger, key, sample)
            original = ledger.read_bytes()
            future = self.cli("expiry", ledger, "--public-key", public, "--as-of", "2026-10-12T12:00:00Z", expected=2)["results"][0]
            self.assertEqual(future["certificate_window"], "not-yet-valid")
            self.assertEqual(future["sampling_state"], "future-sample")
            expired = self.cli("expiry", ledger, "--public-key", public, "--as-of", "2026-10-12T15:00:00Z", "--max-age-seconds", "3600", expected=2)["results"][0]
            self.assertEqual(expired["certificate_window"], "expired")
            self.assertEqual(expired["sampling_state"], "stale-sample")
            self.assertEqual(ledger.read_bytes(), original)
            append(ledger, key, {"host": "fixture.test", "port": 443, "vantage": "local", "status": "error", "observed_at": "2026-10-12T13:30:00Z"})
            last = self.cli("expiry", ledger, "--public-key", public, "--as-of", "2026-10-12T13:30:00Z", expected=2)["results"][0]
            self.assertEqual(last["certificate_window"], "unavailable")
            self.assertIsNone(last["not_after"])
            self.assertEqual(last["sequence"], 2)
            append(ledger, key, {**sample, "vantage": "clock-unknown", "observed_at": "not-a-time"})
            unknown = self.cli("expiry", ledger, "--public-key", public, "--as-of", "2026-10-12T13:30:00Z", expected=2)
            self.assertEqual(next(r for r in unknown["results"] if r["vantage"] == "clock-unknown")["sampling_state"], "unknown-time")
            uncertain = self.cli("continuity", ledger, "--public-key", public, "--as-of", "2026-10-12T13:30:00Z", expected=2)
            latest = next(r for r in uncertain["results"] if r["vantage"] == "clock-unknown")
            self.assertEqual(latest["latest_sequence"], 3)
            self.assertEqual(latest["latest_status"], "verified")
            self.assertIsNone(latest["age_seconds"])
            append(ledger, key, {"host":"fixture.test", "port":443, "vantage":"clock-unknown", "status":"error", "observed_at":"unavailable"})
            saved = ledger.read_bytes()
            uncertain = self.cli("continuity", ledger, "--public-key", public, "--as-of", "2026-10-12T13:30:00Z", expected=2)
            latest = next(r for r in uncertain["results"] if r["vantage"] == "clock-unknown")
            self.assertEqual(latest["latest_sequence"], 4)
            self.assertEqual(latest["latest_status"], "error")
            self.assertEqual(latest["sampling_state"], "time-unavailable")
            self.assertEqual(ledger.read_bytes(), saved)


    def test_vantage_pair_budget_is_global_and_never_skips_signature_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "witness"
            self.cli("init", state)
            ledger, public = state / "observations.jsonl", state / "witness.pub"
            key = load_private(state / "witness.key")
            for host, labels in (("a.test", ("a", "b", "c")), ("z.test", ("x", "y"))):
                for label in labels:
                    append(ledger, key, {"host": host, "port": 443, "vantage": label, "status": "error",
                        "error": "Synthetic unavailable observer claim", "observed_at": "2026-09-19T12:00:00Z"})
            original = ledger.read_bytes()
            limited = self.cli("vantages", ledger, "--public-key", public, "--max-pairs", "2", expected=2)
            self.assertFalse(limited["comparisons_complete"])
            self.assertEqual(sum(len(row["comparisons"]) for row in limited["results"]), 2)
            self.assertEqual([(row["host"], row["omitted_pairs"]) for row in limited["results"]],
                             [("a.test", 1), ("z.test", 1)])
            self.assertEqual(set(limited["results"][1]["views"]), {"x", "y"})
            self.assertEqual(limited["results"][1]["comparisons"], [])
            complete = self.cli("vantages", ledger, "--public-key", public, "--max-pairs", "4")
            self.assertTrue(complete["comparisons_complete"])
            pairs = {row["host"]: {(pair["left_vantage"], pair["right_vantage"])
                                   for pair in row["comparisons"]} for row in complete["results"]}
            self.assertEqual(pairs, {"a.test": {("a", "b"), ("a", "c"), ("b", "c")}, "z.test": {("x", "y")}})
            self.assertTrue(all(row["omitted_pairs"] == 0 for row in complete["results"]))
            self.assertEqual(ledger.read_bytes(), original)
            rows = [json.loads(line) for line in original.splitlines()]
            rows[-1]["body"]["observation"]["error"] = "Unsigned change in an unexamined endpoint"
            ledger.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
            damaged = ledger.read_bytes()
            self.cli("vantages", ledger, "--public-key", public, "--max-pairs", "1", expected=1)
            self.assertEqual(ledger.read_bytes(), damaged)

    def test_compare_retained_stores_distinguishes_missing_claims_equal_sets_and_signed_conflicts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, left, right = root / "witness", root / "left", root / "right"
            self.cli("init", state)
            ledger, public = state / "observations.jsonl", state / "witness.pub"
            key = load_private(state / "witness.key")
            sample = {"host": "fixture.test", "port": 443, "vantage": "local", "status": "error",
                      "error": "Synthetic observer claim", "observed_at": "2026-09-20T12:00:00Z"}
            checkpoints = []
            for count in (1, 2):
                append(ledger, key, sample)
                checkpoint = root / f"prefix-{count}.json"
                self.cli("checkpoint", state, checkpoint)
                self.cli("retain-checkpoint", checkpoint, "--store", left, "--public-key", public)
                if count == 1:
                    self.cli("retain-checkpoint", checkpoint, "--store", right, "--public-key", public)
                checkpoints.append(checkpoint)
            args = ("compare-retained", left, right, "--public-key", public)
            missing = self.cli(*args, expected=2)
            self.assertEqual([row["count"] for row in missing["shared"]], [1])
            self.assertEqual([row["count"] for row in missing["only_left"]], [2])
            self.assertEqual(missing["only_right"], [])
            self.assertTrue(missing["ancestry_unproven"])
            self.cli("retain-checkpoint", checkpoints[1], "--store", right, "--public-key", public)
            equal = self.cli(*args)
            self.assertTrue(equal["identical_claim_sets"])
            self.assertFalse(equal["needs_attention"])
            self.assertTrue(equal["ancestry_unproven"])
            fork = root / "fork.jsonl"
            fork.write_bytes(ledger.read_bytes().splitlines(keepends=True)[0])
            append(fork, key, {**sample, "error": "Correctly signed alternative claim"})
            fork_checkpoint = root / "fork-checkpoint.json"
            fork_checkpoint.write_bytes(canonical(make_checkpoint(verify(fork, key.public_key()), key)))
            self.cli("retain-checkpoint", fork_checkpoint, "--store", right, "--public-key", public, expected=2)
            protected = {p: p.read_bytes() for p in (ledger, public, *checkpoints, fork_checkpoint,
                         *left.glob("anchor-*.json"), *right.glob("anchor-*.json"))}
            conflict = self.cli(*args, expected=2)
            self.assertEqual([row["count"] for row in conflict["conflicting_heads"]], [2])
            self.assertEqual(len(conflict["conflicting_heads"][0]["heads"]), 2)
            self.assertFalse(conflict["identical_claim_sets"])
            self.assertEqual([row["count"] for row in conflict["only_right"]], [2])
            self.assertEqual({p: p.read_bytes() for p in protected}, protected)

    def test_mixed_trust_checkpoint_store_fails_closed_without_replacing_evidence(self):
        # A valid signature from an untrusted witness must not be silently filtered.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            retained, absent = root / "retained", root / "must-not-be-created"
            states, checkpoints = [], []
            for label in ("trusted", "foreign"):
                state, checkpoint = root / label, root / (label + ".json")
                self.cli("init", state)
                key = load_private(state / "witness.key")
                append(state / "observations.jsonl", key, {"host": "fixture.test", "port": 443,
                    "vantage": "local", "status": "error", "error": "Synthetic observer claim",
                    "observed_at": "2026-09-20T12:00:00Z"})
                self.cli("checkpoint", state, checkpoint)
                states.append(state)
                checkpoints.append(checkpoint)
            public, ledger = states[0] / "witness.pub", states[0] / "observations.jsonl"
            self.cli("retain-checkpoint", checkpoints[1], "--store", absent, "--public-key", public, expected=1)
            self.assertFalse(absent.exists())
            self.cli("retain-checkpoint", checkpoints[0], "--store", retained, "--public-key", public)
            foreign = json.loads(checkpoints[1].read_text())
            copied = retained / ("anchor-" + hashlib.sha256(canonical(foreign["body"])).hexdigest() + ".json")
            copied.write_bytes(checkpoints[1].read_bytes())
            protected = {p: p.read_bytes() for p in (*checkpoints, public, ledger, *retained.glob("anchor-*.json"))}
            for args in (("list-retained", "--store", retained, "--public-key", public),
                         ("check-retained", ledger, "--store", retained, "--public-key", public),
                         ("retain-checkpoint", checkpoints[0], "--store", retained, "--public-key", public)):
                self.cli(*args, expected=1)
                self.assertEqual({p: p.read_bytes() for p in protected}, protected)
                self.assertEqual(len(list(retained.glob("anchor-*.json"))), 2)
            # Caller removes only the deliberately injected foreign test fixture.
            copied.unlink()
            self.assertTrue(self.cli("check-retained", ledger, "--store", retained, "--public-key", public)["ok"])

    def test_competing_checkpoint_retention_keeps_both_prefixes_and_idempotent_retries(self):
        # Concurrency across real CLI processes cannot be checked by a single function call.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, retained = root / "witness", root / "retained"
            self.cli("init", state)
            ledger, public = state / "observations.jsonl", state / "witness.pub"
            key = load_private(state / "witness.key")
            checkpoints = []
            for count in (1, 2):
                append(ledger, key, {"host": "fixture.test", "port": 443, "vantage": "local",
                    "status": "error", "error": "Synthetic retained prefix", "observed_at": "2026-09-19T12:00:00Z"})
                checkpoint = root / f"prefix-{count}.json"
                self.cli("checkpoint", state, checkpoint)
                checkpoints.append(checkpoint)
            saved = {p: p.read_bytes() for p in (ledger, public, *checkpoints)}
            workers = []
            try:
                for checkpoint in checkpoints * 3:
                    workers.append(subprocess.Popen([sys.executable, "-m", "wireledger", "retain-checkpoint",
                        str(checkpoint), "--store", str(retained), "--public-key", str(public)],
                        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
                results = []
                for worker in workers:
                    out, err = worker.communicate(timeout=15)
                    self.assertEqual(worker.returncode, 0, out + err)
                    results.append(json.loads(out))
            finally:
                for worker in workers:
                    if worker.poll() is None:
                        worker.kill()
                        worker.communicate(timeout=5)
            self.assertEqual(sum(not row["already_retained"] for row in results), 2)
            self.assertEqual(sum(row["already_retained"] for row in results), 4)
            anchors = {p.name: p.read_bytes() for p in retained.glob("anchor-*.json")}
            self.assertEqual(len(anchors), 2)
            checked = self.cli("check-retained", ledger, "--store", retained, "--public-key", public)
            self.assertTrue(checked["ok"])
            self.assertEqual([row["relation"] for row in checked["checkpoints"]], ["consistent-prefix"] * 2)
            for checkpoint in checkpoints:
                self.assertTrue(self.cli("retain-checkpoint", checkpoint, "--store", retained,
                                         "--public-key", public)["already_retained"])
            self.assertEqual({p.name: p.read_bytes() for p in retained.glob("anchor-*.json")}, anchors)
            self.assertEqual({p: p.read_bytes() for p in saved}, saved)
            self.assertEqual(list(retained.glob(".pending-anchor-*")), [])

    def test_successive_retained_prefixes_reject_signed_rollback_and_fork(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, retained = root / "witness", root / "retained"
            older = root / "older-anchor"
            self.cli("init", state)
            ledger, public = state / "observations.jsonl", state / "witness.pub"
            key = load_private(state / "witness.key")
            sample = {"host": "fixture.test", "port": 443, "vantage": "local", "status": "error",
                      "error": "Synthetic first sample", "observed_at": "2026-09-20T00:00:00Z"}
            append(ledger, key, sample)
            first = ledger.read_bytes()
            for count in (1, 2):
                if count == 2:
                    append(ledger, key, {**sample, "error": "Synthetic second sample"})
                checkpoint = root / f"checkpoint-{count}.json"
                self.cli("checkpoint", state, checkpoint)
                self.cli("retain-checkpoint", checkpoint, "--store", retained, "--public-key", public)
                if count == 1:
                    self.cli("retain-checkpoint", checkpoint, "--store", older, "--public-key", public)
            original = ledger.read_bytes()
            multi_args = ("check-retained", ledger, "--store", retained, "--store", older, "--public-key", public)
            complete = self.cli(*multi_args)
            self.assertTrue(complete["ok"])
            self.assertEqual([row["store_index"] for row in complete["stores"]], [1, 2])
            self.cli("check-retained", ledger, "--store", retained, "--store", retained / ".", "--public-key", public, expected=1)
            older_bytes = {p.name: p.read_bytes() for p in older.glob("anchor-*.json")}
            anchors = {p.name: p.read_bytes() for p in retained.glob("anchor-*.json")}
            self.assertEqual(len(anchors), 2)
            args = ("check-retained", ledger, "--store", retained, "--public-key", public)
            self.assertTrue(self.cli(*args)["ok"])
            ledger.write_bytes(first)  # Still correctly signed; merely an older prefix.
            rollback = self.cli(*args, expected=2)
            self.assertEqual([r["relation"] for r in rollback["checkpoints"]],
                             ["consistent-prefix", "shorter-than-retained"])
            self.assertEqual(ledger.read_bytes(), first)
            append(ledger, key, {**sample, "error": "Deliberately signed alternative second sample"})
            fork = ledger.read_bytes()
            divergent = self.cli(*args, expected=2)
            self.assertEqual([r["relation"] for r in divergent["checkpoints"]],
                             ["consistent-prefix", "divergent"])
            self.assertEqual(ledger.read_bytes(), fork)
            self.assertTrue(self.cli("check-retained", ledger, "--store", older, "--public-key", public)["ok"])
            combined = self.cli(*multi_args, expected=2)
            self.assertFalse(combined["ok"])
            self.assertEqual([row["ok"] for row in combined["stores"]], [False, True])
            self.assertEqual({p.name: p.read_bytes() for p in older.glob("anchor-*.json")}, older_bytes)
            ledger.write_bytes(original)
            restored = self.cli(*args)
            self.assertTrue(restored["ok"])
            self.assertEqual([r["relation"] for r in restored["checkpoints"]], ["consistent-prefix"] * 2)
            self.assertEqual(ledger.read_bytes(), original)
            self.assertEqual({p.name: p.read_bytes() for p in retained.glob("anchor-*.json")}, anchors)

    def test_recovery_stale_bytes_are_refused_and_exact_retry_keeps_original_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, retained = root / "witness", root / "retained"
            self.cli("init", state)
            ledger, public = state / "observations.jsonl", state / "witness.pub"
            key = load_private(state / "witness.key")
            append(ledger, key, {"host":"fixture.test", "port":443, "vantage":"local", "status":"error", "observed_at":"2026-10-12T00:00:00Z"})
            checkpoint = root / "checkpoint.json"
            self.cli("checkpoint", state, checkpoint)
            self.cli("retain-checkpoint", checkpoint, "--store", retained, "--public-key", public)
            valid = ledger.read_bytes()
            ledger.write_bytes(valid + b'{"body":')
            damaged = ledger.read_bytes()
            plan = root / "reviewed.json"
            plan.write_text(json.dumps(self.cli("recovery-preview", ledger, "--public-key", public, "--store", retained)))
            ledger.write_bytes(damaged + b'{')
            changed = ledger.read_bytes()
            evidence = root / "evidence"
            args = ("recovery-apply", ledger, "--public-key", public, "--store", retained, "--plan", plan, "--evidence", evidence)
            self.cli(*args, expected=1)
            self.assertEqual(ledger.read_bytes(), changed)
            self.assertFalse(evidence.exists())
            ledger.write_bytes(damaged)
            recovered = self.cli(*args)
            self.assertFalse(recovered["already_recovered"])
            self.assertEqual(ledger.read_bytes(), valid)

            self.assertEqual((evidence / "original.jsonl").read_bytes(), damaged)
            evidence_bytes = {p.name:p.read_bytes() for p in evidence.iterdir()}
            retried = self.cli(*args)
            self.assertTrue(retried["already_recovered"])
            self.assertEqual({p.name:p.read_bytes() for p in evidence.iterdir()}, evidence_bytes)
            self.assertEqual(ledger.read_bytes(), valid)

    def test_competing_recovery_writers_repair_once_and_reuse_identical_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, retained = root / "witness", root / "retained"
            self.cli("init", state)
            ledger, public = state / "observations.jsonl", state / "witness.pub"
            append(ledger, load_private(state / "witness.key"),
                   {"host": "fixture.test", "port": 443, "vantage": "local", "status": "error",
                    "observed_at": "2026-09-22T00:00:00Z"})
            checkpoint = root / "checkpoint.json"
            self.cli("checkpoint", state, checkpoint)
            self.cli("retain-checkpoint", checkpoint, "--store", retained, "--public-key", public)
            anchors = {p.name: p.read_bytes() for p in retained.glob("anchor-*.json")}
            valid = ledger.read_bytes()
            ledger.write_bytes(valid + b'{"body":')
            damaged = ledger.read_bytes()
            plan, evidence, ready, release = [root / name for name in ("plan.json", "evidence", "ready", "release")]
            reviewed = self.cli("recovery-preview", ledger, "--public-key", public, "--store", retained)
            plan.write_text(json.dumps(reviewed))
            args = ["recovery-apply", str(ledger), "--public-key", str(public), "--store", str(retained),
                    "--plan", str(plan), "--evidence", str(evidence)]
            held = ("import os,sys,time; from pathlib import Path; from unittest.mock import patch; from wireledger.__main__ import main\n"
                    "ready=Path(sys.argv.pop(1)); release=Path(sys.argv.pop(1)); original=os.ftruncate\n"
                    "def wait(fd,length):\n"
                    " ready.touch(); deadline=time.monotonic()+10\n"
                    " while not release.exists():\n"
                    "  if time.monotonic()>deadline: raise TimeoutError('test release missing')\n"
                    "  time.sleep(.01)\n"
                    " return original(fd,length)\n"
                    "with patch('wireledger.recovery.os.ftruncate',wait): raise SystemExit(main())\n")
            workers = [subprocess.Popen([sys.executable, "-c", held, str(ready), str(release), *args],
                                        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)]
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(ready.exists(), "writer never reached the protected truncation boundary")
                self.assertEqual(ledger.read_bytes(), damaged)
                saved_evidence = {p.name: p.read_bytes() for p in evidence.iterdir()}
                waiting = ("import sys; from pathlib import Path; from unittest.mock import patch; from wireledger.__main__ import main; from wireledger.recovery import _inputs\n"
                           "ready=Path(sys.argv.pop(1))\n"
                           "def entering(*args,**kwargs):\n"
                           " ready.touch(); return _inputs(*args,**kwargs)\n"
                           "with patch('wireledger.recovery._inputs',entering): raise SystemExit(main())\n")
                waiting_files = [root / ("waiting-" + str(index)) for index in range(2)]
                for marker in waiting_files:
                    workers.append(subprocess.Popen([sys.executable, "-c", waiting, str(marker), *args],
                                                     cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
                deadline = time.monotonic() + 5
                while not all(p.exists() for p in waiting_files) and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(all(p.exists() for p in waiting_files), "competitors did not enter recovery")
                self.assertTrue(all(p.poll() is None for p in workers))
                release.touch()
                results = []
                for worker in workers:
                    out, err = worker.communicate(timeout=10)
                    self.assertEqual(worker.returncode, 0, out + err)
                    results.append(json.loads(out))
                self.assertEqual([row["already_recovered"] for row in results], [False, True, True])
                self.assertEqual(ledger.read_bytes(), valid)
                self.assertEqual((evidence / "original.jsonl").read_bytes(), damaged)
                self.assertEqual({p.name: p.read_bytes() for p in evidence.iterdir()}, saved_evidence)
                self.assertEqual({p.name: p.read_bytes() for p in retained.glob("anchor-*.json")}, anchors)
                self.assertEqual(list(evidence.glob(".pending-recovery-*")), [])
                self.assertTrue(self.cli("check-retained", ledger, "--public-key", public, "--store", retained)["ok"])
            finally:
                release.touch()
                for worker in workers:
                    if worker.poll() is None:
                        worker.kill()
                        worker.communicate(timeout=5)

    def test_recovery_process_death_at_truncation_preserves_evidence_and_exact_retry(self):
        for phase in ("before", "after"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                state, retained = root / "witness", root / "retained"
                self.cli("init", state)
                ledger, public = state / "observations.jsonl", state / "witness.pub"
                append(ledger, load_private(state / "witness.key"),
                       {"host": "fixture.test", "port": 443, "vantage": "local", "status": "error",
                        "observed_at": "2026-09-22T00:00:00Z"})
                checkpoint = root / "checkpoint.json"
                self.cli("checkpoint", state, checkpoint)
                self.cli("retain-checkpoint", checkpoint, "--store", retained, "--public-key", public)
                anchors = {p.name: p.read_bytes() for p in retained.glob("anchor-*.json")}
                valid = ledger.read_bytes()
                ledger.write_bytes(valid + b'{"body":')
                damaged = ledger.read_bytes()
                plan, evidence = root / "reviewed.json", root / "evidence"
                reviewed = self.cli("recovery-preview", ledger, "--public-key", public, "--store", retained)
                plan.write_text(json.dumps(reviewed))
                args = ["recovery-apply", str(ledger), "--public-key", str(public), "--store", str(retained),
                        "--plan", str(plan), "--evidence", str(evidence)]
                # A real CLI process exits without unwinding locks or cleanup, at the destructive boundary.
                injected = ("import os,sys; from wireledger.__main__ import main; from unittest.mock import patch\n"
                            "phase=sys.argv.pop(1); original=os.ftruncate\n"
                            "def stop(fd,length):\n"
                            " if phase=='after': original(fd,length)\n"
                            " os._exit(77 if phase=='before' else 78)\n"
                            "with patch('wireledger.recovery.os.ftruncate',stop): main()\n")
                killed = subprocess.run([sys.executable, "-c", injected, phase, *args], cwd=ROOT,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(killed.returncode, 77 if phase == "before" else 78, killed.stdout + killed.stderr)
                self.assertEqual(ledger.read_bytes(), damaged if phase == "before" else valid)
                self.assertEqual((evidence / "original.jsonl").read_bytes(), damaged)
                self.assertEqual(json.loads((evidence / "plan.json").read_text()), reviewed)
                original_evidence = {p.name: p.read_bytes() for p in evidence.iterdir()}
                recovered = self.cli(*args, timeout=5)  # A fresh process must reacquire the dead writer's locks.
                self.assertEqual(recovered["already_recovered"], phase == "after")
                self.assertEqual(ledger.read_bytes(), valid)
                self.assertEqual({p.name: p.read_bytes() for p in evidence.iterdir()}, original_evidence)
                self.assertEqual({p.name: p.read_bytes() for p in retained.glob("anchor-*.json")}, anchors)
                self.assertTrue(self.cli("check-retained", ledger, "--public-key", public, "--store", retained)["ok"])
