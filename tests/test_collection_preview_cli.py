"""Collection dry runs do not contact endpoints or open the witness private key."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
class CollectionPreviewAcceptance(unittest.TestCase):
    def test_normalized_preview_authenticates_history_without_collection_or_private_key_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);state=root/'witness';policy=root/'policy.json'
            initialized=subprocess.run([sys.executable,'-m','wireledger','init',str(state)],cwd=ROOT,capture_output=True,text=True,timeout=5);self.assertEqual(initialized.returncode,0,initialized.stderr)
            policy.write_text(json.dumps([{'host':'LOCALHOST.','port':443,'vantage':'review'}]));original={p.name:p.read_bytes() for p in state.iterdir() if p.is_file()};policy_bytes=policy.read_bytes()
            code=("from unittest.mock import patch;from wireledger.__main__ import main\n"
                  "with patch('wireledger.collection.observe',side_effect=RuntimeError('network forbidden')),patch('wireledger.collection.load_private',side_effect=RuntimeError('private key forbidden')):\n"
                  " raise SystemExit(main())\n")
            def cli(expected=0,*extra):
                r=subprocess.run([sys.executable,'-c',code,'observe-policy',str(state),'--expected',str(policy),'--preview',*extra],cwd=ROOT,capture_output=True,text=True,timeout=5)
                self.assertEqual(r.returncode,expected,r.stdout+r.stderr);return json.loads(r.stdout) if r.stdout else None
            result=cli();self.assertTrue(result['preview']);self.assertEqual(result['endpoints'],[{'host':'localhost','port':443,'vantage':'review'}]);self.assertEqual(result['history_records'],0);self.assertEqual(result['history_head'],'0'*64)
            cli(1,'--timeout','0');self.assertEqual(policy.read_bytes(),policy_bytes);self.assertEqual({p.name:p.read_bytes() for p in state.iterdir() if p.is_file()},original)
            (state/'observations.jsonl').write_text('forged history\n');saved=(state/'observations.jsonl').read_bytes();cli(1);self.assertEqual((state/'observations.jsonl').read_bytes(),saved)
