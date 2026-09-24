"""Failure runs follow each signed sequence group, not interleaved wall-clock rows."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from wireledger.lab import certificates,tls_server
from wireledger.ledger import append,load_private
ROOT=Path(__file__).resolve().parents[1]
class FailureStreakAcceptance(unittest.TestCase):
    def test_interleaved_failures_and_real_tls_recovery_preserve_group_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);state=root/'witness'
            def cli(*args,expected=0):
                r=subprocess.run([sys.executable,'-m','wireledger',*map(str,args)],cwd=ROOT,capture_output=True,text=True,timeout=10)
                self.assertEqual(r.returncode,expected,r.stdout+r.stderr);return json.loads(r.stdout) if r.stdout else None
            cli('init',state);ledger=state/'observations.jsonl';public=state/'witness.pub';private=load_private(state/'witness.key');args=('failures',ledger,'--public-key',public)
            self.assertFalse(cli(*args)['needs_attention']);ca,variants=certificates(root);cert,key=variants[0]
            with tls_server(cert,key) as port:
                observe=('observe',state,'localhost','--port',port,'--vantage','local','--connect-ip','127.0.0.1','--ca-file',ca);cli(*observe)
                for host,p,v in [('localhost',port,'local'),('other.test',443,'other'),('localhost',port,'local')]:append(ledger,private,{'host':host,'port':p,'vantage':v,'status':'error'})
                before=ledger.read_bytes();failed=cli(*args,expected=2);row=next(r for r in failed['results'] if r['host']=='localhost');self.assertEqual(row['consecutive_failures'],2);self.assertEqual(row['last_verified_sequence'],1);self.assertEqual(row['latest']['sequence'],4);self.assertEqual(ledger.read_bytes(),before)
                cli(*observe);after=ledger.read_bytes();recovered=cli(*args,expected=2);self.assertEqual(recovered['failing_groups'],1);self.assertEqual(recovered['omitted_nonfailing_groups'],1);self.assertEqual(recovered['results'][0]['host'],'other.test');self.assertEqual(ledger.read_bytes(),after)
                damaged=after.replace(b'localhost',b'bad-host!',1);ledger.write_bytes(damaged);cli(*args,expected=1);self.assertEqual(ledger.read_bytes(),damaged)
