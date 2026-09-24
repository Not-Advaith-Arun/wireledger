"""Actual CLI security acceptance for record/checkpoint signature domains."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from wireledger.ledger import append, canonical, load_private, make_checkpoint, verify

ROOT = Path(__file__).resolve().parents[1]


class SignatureDomainAcceptance(unittest.TestCase):
    def cli(self, *args, expected=0):
        result = subprocess.run([sys.executable, "-m", "wireledger", *map(str,args)], cwd=ROOT,
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def test_equal_signature_bytes_cannot_alias_signed_chain_or_retained_claims(self):
        # Unused base64 padding bits permit a different spelling of identical
        # valid signature bytes. Envelope hashes must not accept those aliases.
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

        def alias(signature):
            self.assertTrue(signature.endswith("=="))
            index = alphabet.index(signature[-3])
            self.assertEqual(index % 16, 0)
            changed = signature[:-3] + alphabet[index + 1] + "=="
            self.assertNotEqual(changed, signature)
            self.assertEqual(base64.b64decode(changed, validate=True), base64.b64decode(signature))
            return changed

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, retained, absent = root / "witness", root / "retained", root / "absent"
            self.cli("init", state)
            key = load_private(state / "witness.key")
            ledger, public = state / "observations.jsonl", state / "witness.pub"
            append(ledger, key, {"host":"fixture.test", "port":443, "vantage":"local", "status":"error"})
            original = ledger.read_bytes()
            good = make_checkpoint(verify(ledger, key.public_key()), key)
            checkpoint = root / "good.json"
            checkpoint.write_text(json.dumps(good))
            self.cli("retain-checkpoint", checkpoint, "--store", retained, "--public-key", public)
            anchors = {p.name:p.read_bytes() for p in retained.glob("anchor-*.json")}
            changed = {**good, "signature":alias(good["signature"])}
            key.public_key().verify(base64.b64decode(changed["signature"]),
                                    b"wireledger/v1/checkpoint\x00" + canonical(good["body"]))
            imported = root / "alias.json"
            imported.write_text(json.dumps(changed))
            refusal = self.cli("retain-checkpoint", imported, "--store", absent, "--public-key", public, expected=1)
            self.assertIn("signature verification failed", refusal.stderr)
            self.assertFalse(absent.exists())
            bundle = root / "bundle.json"
            bundle.write_text(json.dumps({"format":"wireledger.checkpoint-bundle.v1",
                "witness":good["body"]["witness"], "checkpoints":[changed]}))
            self.cli("import-retained", bundle, "--store", retained, "--public-key", public, expected=1)
            self.assertEqual({p.name:p.read_bytes() for p in retained.glob("anchor-*.json")}, anchors)
            record = json.loads(original)
            record["signature"] = alias(record["signature"])
            key.public_key().verify(base64.b64decode(record["signature"]),
                                    b"wireledger/v1/record\x00" + canonical(record["body"]))
            history = root / "alias.jsonl"
            history.write_bytes(canonical(record) + b"\n")
            saved = history.read_bytes()
            for command in ("verify", "timeline"):
                refusal = self.cli(command, history, "--public-key", public, expected=1)
                self.assertIn("signature verification failed", refusal.stderr)
                self.assertEqual(refusal.stdout, "")
            self.assertEqual(history.read_bytes(), saved)
            self.assertEqual(ledger.read_bytes(), original)
            self.assertTrue(json.loads(self.cli("check-retained", ledger, "--store", retained,
                                               "--public-key", public).stdout)["ok"])

    def test_valid_ed25519_signatures_from_the_wrong_protocol_domain_are_rejected(self):
        # Same independently trusted key and valid message shapes: only the
        # signed protocol domain changes, so generic signature tampering cannot
        # establish this cross-protocol boundary.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, retained, absent = root / "witness", root / "retained", root / "absent"
            self.cli("init",state)
            key = load_private(state / "witness.key")
            ledger, public = state / "observations.jsonl", state / "witness.pub"
            append(ledger,key,{"host":"fixture.test","port":443,"vantage":"local","status":"error"})
            original = ledger.read_bytes()
            good = make_checkpoint(verify(ledger,key.public_key()),key)
            checkpoint = root / "good.json"; checkpoint.write_text(json.dumps(good))
            self.cli("retain-checkpoint",checkpoint,"--store",retained,"--public-key",public)
            anchors = {p.name:p.read_bytes() for p in retained.glob("anchor-*.json")}
            foreign = {**good,"signature":base64.b64encode(key.sign(b"wireledger/v1/record\x00"+canonical(good["body"]))).decode("ascii")}
            bad = root / "wrong-domain.json"; bad.write_text(json.dumps(foreign))
            rejected = self.cli("retain-checkpoint",bad,"--store",absent,"--public-key",public,expected=1)
            self.assertIn("signature verification failed",rejected.stderr)
            self.assertFalse(absent.exists())
            bundle = root / "bundle.json"
            bundle.write_text(json.dumps({"format":"wireledger.checkpoint-bundle.v1","witness":good["body"]["witness"],"checkpoints":[foreign]}))
            self.cli("import-retained",bundle,"--store",retained,"--public-key",public,expected=1)
            self.assertEqual({p.name:p.read_bytes() for p in retained.glob("anchor-*.json")},anchors)
            record = json.loads(original)
            record["signature"] = base64.b64encode(key.sign(b"wireledger/v1/checkpoint\x00"+canonical(record["body"]))).decode("ascii")
            wrong_history = root / "wrong-domain.jsonl"; wrong_history.write_bytes(canonical(record)+b"\n")
            saved_wrong = wrong_history.read_bytes()
            for command in ("verify","timeline"):
                failure = self.cli(command,wrong_history,"--public-key",public,expected=1)
                self.assertIn("signature verification failed",failure.stderr)
                self.assertEqual(failure.stdout,"")
            self.assertEqual(wrong_history.read_bytes(),saved_wrong)
            self.assertEqual(ledger.read_bytes(),original)
            self.assertTrue(json.loads(self.cli("check-retained",ledger,"--store",retained,"--public-key",public).stdout)["ok"])
