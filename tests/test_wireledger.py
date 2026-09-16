import base64
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wireledger.ledger import (LedgerError, append, canonical, initialize, load_private,
                               load_public, make_checkpoint, parse, verify, verify_records)


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "witness"
        initialize(self.state)
        self.key = load_private(self.state / "witness.key")
        self.path = self.state / "observations.jsonl"

    def add(self, n=3):
        for value in range(n):
            append(self.path, self.key, {"value": value})
        return verify(self.path, self.key.public_key())

    def test_round_trip_and_file_permissions(self):
        self.assertEqual(len(self.add()), 3)
        self.assertEqual((self.state / "witness.key").stat().st_mode & 0o777, 0o600)
        self.assertEqual(load_public(self.state / "witness.pub").public_bytes_raw(), self.key.public_key().public_bytes_raw())

    def test_initialization_does_not_overwrite(self):
        before = (self.state / "witness.key").read_bytes()
        with self.assertRaises(FileExistsError):
            initialize(self.state)
        self.assertEqual(before, (self.state / "witness.key").read_bytes())

    def test_tampering_and_wrong_identity_rejected(self):
        self.add()
        with self.assertRaises(LedgerError):
            verify_records(self.path.read_bytes().replace(b'"value":0', b'"value":9'), self.key.public_key())
        with self.assertRaises(LedgerError):
            verify(self.path, Ed25519PrivateKey.generate().public_key())

    def test_reordering_and_middle_deletion_rejected(self):
        records = self.add()
        for modified in ([records[1], records[0], records[2]], [records[0], records[2]]):
            with self.assertRaises(LedgerError):
                verify_records(b"".join(canonical(item) + b"\n" for item in modified), self.key.public_key())

    def test_tail_requires_external_checkpoint(self):
        records = self.add()
        truncated = canonical(records[0]) + b"\n"
        self.assertEqual(len(verify_records(truncated, self.key.public_key())), 1)
        with self.assertRaises(LedgerError):
            verify_records(truncated, self.key.public_key(), make_checkpoint(records, self.key))

    def test_checkpoint_accepts_extension_and_rejects_fork(self):
        records = self.add(1)
        anchor = make_checkpoint(records, self.key)
        append(self.path, self.key, {"later": True})
        self.assertEqual(len(verify(self.path, self.key.public_key(), anchor)), 2)
        other = self.root / "other.jsonl"
        other.write_bytes(b"")
        append(other, self.key, {"different": True})
        with self.assertRaises(LedgerError):
            verify(other, self.key.public_key(), anchor)

    def test_partial_append_fails_closed_and_is_preserved(self):
        self.add(1)
        damaged = self.path.read_bytes()[:-1]
        self.path.write_bytes(damaged)
        with self.assertRaises(LedgerError):
            append(self.path, self.key, {"next": 2})
        self.assertEqual(self.path.read_bytes(), damaged)

    def test_duplicate_keys_unsigned_fields_and_nonfinite_rejected(self):
        with self.assertRaises(LedgerError):
            parse('{"a":1,"a":2}')
        with self.assertRaises(LedgerError):
            parse('{"a":NaN}')
        records = self.add(1)
        records[0]["extra"] = "unsigned"
        with self.assertRaises(LedgerError):
            verify_records(canonical(records[0]) + b"\n", self.key.public_key())

    def test_rejects_symlink_and_publicly_readable_private_key(self):
        link = self.root / "link"
        link.symlink_to(self.path)
        with self.assertRaises((LedgerError, OSError)):
            append(link, self.key, {})
        os.chmod(self.state / "witness.key", 0o644)
        with self.assertRaises(LedgerError):
            load_private(self.state / "witness.key")

    def test_concurrent_cli_writers_preserve_sequence(self):
        code = "from pathlib import Path; from wireledger.ledger import *; import sys; p=Path(sys.argv[1]); append(p/'observations.jsonl',load_private(p/'witness.key'),{'worker':sys.argv[2]})"
        workers = [subprocess.Popen([sys.executable, "-c", code, str(self.state), str(i)]) for i in range(5)]
        for worker in workers:
            self.assertEqual(worker.wait(timeout=10), 0)
        self.assertEqual(len(verify(self.path, self.key.public_key())), 5)


    def test_signature_base64_aliases_rejected_for_records_and_checkpoints(self):
        records = self.add(1)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        def alias(signature):
            # A 64-byte Ed25519 signature ends in ==; final sextet has four unused bits.
            result = signature[:-3] + alphabet[alphabet.index(signature[-3]) | 1] + "=="
            self.assertEqual(base64.b64decode(signature), base64.b64decode(result))
            self.assertNotEqual(signature, result)
            return result
        forged = copy.deepcopy(records[0])
        forged["signature"] = alias(forged["signature"])
        with self.assertRaises(LedgerError):
            verify_records(canonical(forged) + b"\n", self.key.public_key())
        checkpoint = make_checkpoint(records, self.key)
        checkpoint["signature"] = alias(checkpoint["signature"])
        with self.assertRaises(LedgerError):
            verify(self.path, self.key.public_key(), checkpoint)

    def test_invalid_append_does_not_change_history(self):
        self.add(1)
        original = self.path.read_bytes()
        for observation in ([], None, "text", {"bad": float("nan")}):
            with self.assertRaises(ValueError):
                append(self.path, self.key, observation)
            self.assertEqual(self.path.read_bytes(), original)

    def test_tampered_checkpoint_fails_signature_verification(self):
        checkpoint = make_checkpoint(self.add(), self.key)
        checkpoint["body"]["count"] = 1
        with self.assertRaises(LedgerError):
            verify(self.path, self.key.public_key(), checkpoint)




if __name__ == "__main__":
    unittest.main()
