"""Verify a new collection window without mistaking old signed samples for it."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from wireledger.lab import certificates,tls_server

ROOT=Path(__file__).resolve().parents[1]


class CollectionWindowAcceptance(unittest.TestCase):
    def test_sequence_window_excludes_old_samples_but_never_excludes_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);state=root/'witness';policy=root/'policy.json'
            def cli(*args,expected=0):
                r=subprocess.run([sys.executable,'-m','wireledger',*map(str,args)],cwd=ROOT,
                                 capture_output=True,text=True,timeout=12)
                self.assertEqual(r.returncode,expected,r.stdout+r.stderr)
                return json.loads(r.stdout) if r.stdout else r
            cli('init',state);ca,variants=certificates(root);cert,key=variants[0]
            with tls_server(cert,key) as port:
                policy.write_text(json.dumps([{'host':'localhost','port':port,'vantage':v} for v in ('one','two')]))
                cli('observe-policy',state,'--expected',policy,'--connect-ip','127.0.0.1','--ca-file',ca)
                ledger=state/'observations.jsonl';public=state/'witness.pub';original=ledger.read_bytes();saved=policy.read_bytes()
                args=('coverage',ledger,'--public-key',public,'--expected',policy)
                self.assertFalse(cli(*args)['needs_attention'])
                empty=cli(*args,'--after-sequence','2',expected=2)
                self.assertEqual((empty['total_records'],empty['selected_records']),(2,0))
                self.assertEqual({r['collection_state'] for r in empty['results']},{'missing'})
                cli('observe',state,'localhost','--port',port,'--vantage','one','--connect-ip','127.0.0.1','--ca-file',ca)
                partial=cli(*args,'--after-sequence','2',expected=2)
                self.assertEqual({r['vantage']:r['collection_state'] for r in partial['results']},{'one':'observed-verified','two':'missing'})
                cli('observe',state,'localhost','--port',port,'--vantage','two','--connect-ip','127.0.0.1','--ca-file',ca)
                complete=cli(*args,'--after-sequence','2','--exact')
                self.assertEqual((complete['total_records'],complete['selected_records']),(4,2))
                self.assertEqual([r['samples'] for r in complete['results']],[1,1])
                current=ledger.read_bytes();self.assertTrue(current.startswith(original))
                for cursor in ('-1',str(2**63)):cli(*args,'--after-sequence',cursor,expected=1)
                self.assertEqual(ledger.read_bytes(),current);self.assertEqual(policy.read_bytes(),saved)
                rows=current.splitlines();changed=json.loads(rows[0]);changed['body']['observation']['vantage']='forged'
                rows[0]=json.dumps(changed).encode();damaged=b'\n'.join(rows)+b'\n';ledger.write_bytes(damaged)
                cli(*args,'--after-sequence','2',expected=1)
                self.assertEqual(ledger.read_bytes(),damaged)
