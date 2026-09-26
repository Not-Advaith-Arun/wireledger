"""Detached signed claims are checked without a history, store or signing key."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


class CheckpointInspectionAcceptance(unittest.TestCase):
    def test_detached_claim_requires_explicit_key_and_never_implies_ancestry(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);state=root/'witness';foreign=root/'foreign';claim=root/'claim.json';public=root/'trusted.pub'
            def cli(*args,expected=0):
                r=subprocess.run([sys.executable,'-m','wireledger',*map(str,args)],cwd=ROOT,
                                 capture_output=True,text=True,timeout=6)
                self.assertEqual(r.returncode,expected,r.stdout+r.stderr)
                return json.loads(r.stdout) if r.stdout else r
            cli('init',state);cli('init',foreign);cli('checkpoint',state,claim)
            public.write_bytes((state/'witness.pub').read_bytes());shutil.rmtree(state)
            original=claim.read_bytes();keys=public.read_bytes();entries=sorted(p.name for p in root.iterdir())
            report=cli('inspect-checkpoint',claim,'--public-key',public)
            self.assertTrue(report['signature_verified']);self.assertEqual(report['claim']['count'],0)
            self.assertEqual(report['history_relation'],'not_checked');self.assertEqual(report['freshness'],'not_checked')
            self.assertIn('independently trust the key',report['scope'])
            self.assertEqual(sorted(p.name for p in root.iterdir()),entries)
            cli('inspect-checkpoint',claim,'--public-key',foreign/'witness.pub',expected=1)
            modified=json.loads(original);modified['body']['count']=1;modified['body']['head']='f'*64
            claim.write_text(json.dumps(modified));cli('inspect-checkpoint',claim,'--public-key',public,expected=1)
            claim.write_bytes(original)
            self.assertEqual(public.read_bytes(),keys);self.assertEqual(claim.read_bytes(),original)
            self.assertFalse(state.exists())
