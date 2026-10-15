"""Coverage output reduction preserves missing/failed/unexpected obligations."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from wireledger.lab import certificates,tls_server
from wireledger.ledger import append,load_private
ROOT=Path(__file__).resolve().parents[1]
class AttentionCoverageAcceptance(unittest.TestCase):
    def test_verified_rows_omit_without_hiding_missing_failed_or_unexpected_groups(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);state=root/'witness';policy=root/'policy.json'
            def cli(*args,expected=0):
                r=subprocess.run([sys.executable,'-m','wireledger',*map(str,args)],cwd=ROOT,capture_output=True,text=True,timeout=10)
                self.assertEqual(r.returncode,expected,r.stdout+r.stderr);return json.loads(r.stdout) if r.stdout else None
            cli('init',state);ca,variants=certificates(root);cert,key=variants[0]
            with tls_server(cert,key) as port:cli('observe',state,'localhost','--port',port,'--vantage','good','--connect-ip','127.0.0.1','--ca-file',ca)
            ledger=state/'observations.jsonl';public=state/'witness.pub';private=load_private(state/'witness.key')
            append(ledger,private,{'host':'failed.test','port':443,'vantage':'failed','status':'error'})
            expected=[{'host':'localhost','port':port,'vantage':'good'},{'host':'failed.test','port':443,'vantage':'failed'},{'host':'missing.test','port':443,'vantage':'missing'}];policy.write_text(json.dumps(expected));original=ledger.read_bytes()
            args=('coverage',ledger,'--public-key',public,'--expected',policy,'--attention-only')
            report=cli(*args,expected=2);self.assertEqual(report['checked_expected_groups'],3);self.assertEqual(report['omitted_verified_groups'],1)
            self.assertEqual({r['collection_state'] for r in report['results']},{'missing','latest-failed'})
            policy.write_text(json.dumps(expected[:1]));report=cli(*args);self.assertEqual(report['results'],[]);self.assertFalse(report['needs_attention']);self.assertEqual(len(report['unexpected_groups']),1)
            exact=cli(*args,'--exact',expected=2);self.assertTrue(exact['needs_attention']);self.assertEqual(exact['results'],[]);self.assertEqual(ledger.read_bytes(),original)
