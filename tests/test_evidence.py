import base64
import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from wireledger.evidence import (MAX_CA_FILE, audit, decode_chain, encode_chain, load_trust,
                                  trust_fingerprint, validate_evidence)
from wireledger.lab import certificates, tls_server
from wireledger.ledger import append, initialize, load_private, verify
from wireledger.probe import client_context, observe


def duplicate_extension(der):
    """Mutate a generated public certificate without relying on a mock parser."""
    def tlv(tag, content):
        size = len(content)
        count = (size.bit_length() + 7) // 8
        length = bytes([size]) if size < 128 else bytes([0x80 | count]) + size.to_bytes(count, "big")
        return bytes([tag]) + length + content

    def fields(data):
        result, offset = [], 0
        while offset < len(data):
            start = offset
            tag, size = data[offset], data[offset + 1]
            offset += 2
            if size & 0x80:
                count = size & 0x7F
                size = int.from_bytes(data[offset:offset + count], "big")
                offset += count
            content = data[offset:offset + size]
            offset += size
            result.append((tag, content, data[start:offset]))
        return result

    certificate = fields(fields(der)[0][1])
    tbs = fields(certificate[0][1])
    for index, (tag, content, encoded) in enumerate(tbs):
        if tag == 0xA3:
            extensions = fields(content)[0][1]
            duplicate = fields(extensions)[0][2]
            tbs[index] = (tag, content, tlv(0xA3, tlv(0x30, extensions + duplicate)))
            break
    else:
        raise AssertionError("generated fixture has no certificate extensions")
    return tlv(0x30, tlv(0x30, b"".join(part[2] for part in tbs)) + b"".join(part[2] for part in certificate[1:]))


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.ca, cls.pairs = certificates(cls.root)
        with tls_server(*cls.pairs[0]) as port:
            cls.observation = observe("localhost", port, connect_ip="127.0.0.1", cafile=str(cls.ca))
        assert cls.observation["status"] == "verified", cls.observation
        cls.roots = load_trust(cls.ca)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def rows(self, observation=None):
        return [{"body": {"sequence": 1, "observation": copy.deepcopy(observation or self.observation)}}]

    def test_real_chain_audits_with_independent_ca_and_no_network(self):
        with patch("socket.create_connection", side_effect=AssertionError("audit attempted network")):
            result = audit(self.rows(), self.roots)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["results"][0]["verified_chain_length"], 2)
        self.assertTrue(result["results"][0]["captured_ca_set_matches_audit_set"])

    def test_full_chain_or_leaf_fallback_is_explicit(self):
        evidence = self.observation["evidence"]
        chain = decode_chain(evidence["chain_der"])
        self.assertGreaterEqual(len(chain), 1)
        leaf = copy.deepcopy(self.observation)
        leaf["evidence"]["chain_der"] = leaf["evidence"]["chain_der"][:1]
        leaf["evidence"]["chain_capture"] = "leaf-only"
        self.assertTrue(audit(self.rows(leaf), self.roots)["ok"])

    def test_embedded_root_does_not_bootstrap_trust(self):
        with tempfile.TemporaryDirectory() as temporary:
            wrong_ca, _ = certificates(temporary)
            result = audit(self.rows(), load_trust(wrong_ca))
        self.assertFalse(result["ok"])
        self.assertEqual(result["results"][0]["status"], "failed")

    def test_wrong_hostname_fails_even_with_genuine_certificate(self):
        observation = copy.deepcopy(self.observation)
        observation["host"] = "wrong.invalid"
        result = audit(self.rows(observation), self.roots)
        self.assertFalse(result["ok"])

    def test_expiry_and_observer_time_are_distinct(self):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        self.assertFalse(audit(self.rows(), self.roots, now=future)["ok"])
        historical = audit(self.rows(), self.roots, now=future, at_observed_time=True)
        self.assertTrue(historical["ok"])
        self.assertEqual(historical["time_policy"], "observer-asserted-time")

    def test_naive_timestamp_and_malformed_runtime_fail(self):
        for field, value in (("observed_at", "2026-09-16T12:00:00"), ("port", True)):
            observation = copy.deepcopy(self.observation)
            observation[field] = value
            self.assertFalse(audit(self.rows(observation), self.roots)["ok"])
        observation = copy.deepcopy(self.observation)
        observation["evidence"]["runtime"] = {"python": "unknown"}
        self.assertFalse(audit(self.rows(observation), self.roots)["ok"])

    def test_metadata_disagreement_is_detected_even_when_history_is_valid(self):
        observation = copy.deepcopy(self.observation)
        observation["certificate_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "witness"
            initialize(state)
            key = load_private(state / "witness.key")
            append(state / "observations.jsonl", key, observation)
            records = verify(state / "observations.jsonl", key.public_key())
            self.assertEqual(len(records), 1)
            result = audit(records, self.roots)
            self.assertFalse(result["ok"])
            self.assertIn("certificate_sha256", result["results"][0]["detail"])

    def assert_malformed_signed_evidence_rejected(self, observation):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "witness"
            initialize(state)
            key = load_private(state / "witness.key")
            append(state / "observations.jsonl", key, observation)
            records = verify(state / "observations.jsonl", key.public_key())
            result = audit(records, self.roots)
            self.assertFalse(result["ok"])
            self.assertEqual(result["results"][0]["status"], "failed")
            for action, expected in (("audit", 2), ("report", 1)):
                command = [sys.executable, "-m", "wireledger", action, str(state / "observations.jsonl"),
                           "--public-key", str(state / "witness.pub")]
                if action == "audit":
                    command.extend(["--ca-file", str(self.ca)])
                completed = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(completed.returncode, expected, completed.stderr)
                output = json.loads(completed.stdout if action == "audit" else completed.stderr)
                self.assertIn("results" if action == "audit" else "error", output)
                self.assertNotIn("Traceback", completed.stderr)

    def test_out_of_range_utc_timestamps_fail_without_crashing(self):
        for timestamp in ("0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"):
            with self.subTest(timestamp=timestamp):
                observation = copy.deepcopy(self.observation)
                observation["observed_at"] = timestamp
                self.assert_malformed_signed_evidence_rejected(observation)

    def test_duplicate_certificate_extensions_fail_without_crashing(self):
        observation = copy.deepcopy(self.observation)
        malformed = duplicate_extension(base64.b64decode(observation["evidence"]["chain_der"][0]))
        observation["evidence"]["chain_der"][0] = base64.b64encode(malformed).decode()
        self.assert_malformed_signed_evidence_rejected(observation)

    def test_unsupported_certificate_key_type_fails_without_crashing(self):
        observation = copy.deepcopy(self.observation)
        der = base64.b64decode(observation["evidence"]["chain_der"][0])
        known_oid = bytes.fromhex("06072a8648ce3d0201")
        self.assertIn(known_oid, der)
        malformed = der.replace(known_oid, bytes.fromhex("06072a8648ce3d027f"), 1)
        observation["evidence"]["chain_der"][0] = base64.b64encode(malformed).decode()
        self.assert_malformed_signed_evidence_rejected(observation)

    def test_der_size_format_duplicates_and_canonical_encoding(self):
        valid = self.observation["evidence"]["chain_der"]
        for malformed in ([], valid * 17, [valid[0], valid[0]], ["not base64!"], ["a" * 100_000],
                          [base64.b64encode(b"not a certificate").decode()]):
            with self.assertRaises(ValueError):
                decode_chain(malformed)
        self.assertEqual(encode_chain(decode_chain(valid)), valid)

    def test_missing_evidence_and_failed_handshakes_do_not_pass(self):
        observation = copy.deepcopy(self.observation)
        del observation["evidence"]
        self.assertEqual(audit(self.rows(observation), self.roots)["results"][0]["status"], "evidence-missing")
        observation["status"] = "verification-failed"
        self.assertEqual(audit(self.rows(observation), self.roots)["results"][0]["status"], "no-successful-handshake")
        self.assertFalse(audit([], self.roots)["ok"])

    def test_trust_digest_is_set_order_independent(self):
        self.assertEqual(trust_fingerprint([b"a", b"b", b"a"]), trust_fingerprint([b"b", b"a"]))
        self.assertNotEqual(trust_fingerprint([b"a"]), trust_fingerprint([b"b"]))

    def test_context_does_not_create_environment_session_key_log(self):
        with tempfile.TemporaryDirectory() as temporary:
            keylog = Path(temporary) / "session-secrets.txt"
            with patch.dict(os.environ, {"SSLKEYLOGFILE": str(keylog)}):
                context = client_context(str(self.ca))
                self.assertIsNone(context.keylog_filename)
                with tls_server(*self.pairs[0]) as port:
                    result = observe("localhost", port, connect_ip="127.0.0.1", cafile=str(self.ca))
            self.assertEqual(result["status"], "verified")
            self.assertFalse(keylog.exists())

    def test_cli_audit_passes_and_requires_separate_trust(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "witness"
            initialize(state)
            append(state / "observations.jsonl", load_private(state / "witness.key"), self.observation)
            command = [sys.executable, "-m", "wireledger", "audit", str(state / "observations.jsonl"),
                       "--public-key", str(state / "witness.pub")]
            missing = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(missing.returncode, 2)
            result = subprocess.run([*command, "--ca-file", str(self.ca)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
