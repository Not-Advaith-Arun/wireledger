"""Bootstrap an explicitly reviewed policy from authenticated observed groups."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from wireledger.lab import certificates,tls_server
from wireledger.ledger import append,load_private

ROOT=Path(__file__).resolve().parents[1]


class PolicyExportAcceptance(unittest.TestCase):
    def test_exported_policy_roundtrips_to_coverage_and_collection_without_claiming_intent(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);state=root/'witness';policy=root/'policy.json'
            def cli(*args,expected=0):
                r=subprocess.run([sys.executable,'-m','wireledger',*map(str,args)],cwd=ROOT,capture_output=True,text=True,timeout=12)
                self.assertEqual(r.returncode,expected,r.stdout+r.stderr)
                return json.loads(r.stdout) if r.stdout else r
            cli('init',state);ledger=state/'observations.jsonl';public=state/'witness.pub'
            cli('endpoints',ledger,'--public-key',public,'--policy',expected=1)
            ca,variants=certificates(root);cert,key=variants[0]
            with tls_server(cert,key) as port:
                expected=[{'host':'localhost','port':port,'vantage':v} for v in ('one','two')]
                for row in expected:cli('observe',state,row['host'],'--port',port,'--vantage',row['vantage'],'--connect-ip','127.0.0.1','--ca-file',ca)
                original=ledger.read_bytes();exported=cli('endpoints',ledger,'--public-key',public,'--policy')
                self.assertEqual(exported,expected);self.assertEqual(ledger.read_bytes(),original)
                policy.write_text(json.dumps(exported));saved=policy.read_bytes()
                self.assertFalse(cli('coverage',ledger,'--public-key',public,'--expected',policy,'--exact')['needs_attention'])
                collected=cli('observe-policy',state,'--expected',policy,'--connect-ip','127.0.0.1','--ca-file',ca)
                self.assertEqual([r['sequence'] for r in collected['samples']],[3,4]);self.assertTrue(collected['all_verified'])
                self.assertEqual(policy.read_bytes(),saved)
                append(ledger,load_private(state/'witness.key'),{'host':'LOCALHOST.','port':port,'vantage':'one','status':'error'})
                ambiguous=ledger.read_bytes();cli('endpoints',ledger,'--public-key',public,'--policy',expected=1)
                self.assertEqual(ledger.read_bytes(),ambiguous)
                damaged=ledger.read_bytes().replace(b'localhost',b'forged-host',1);ledger.write_bytes(damaged)
                cli('endpoints',ledger,'--public-key',public,'--policy',expected=1);self.assertEqual(ledger.read_bytes(),damaged)
