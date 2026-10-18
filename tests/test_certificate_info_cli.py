"""Selected captured certificate metadata remains distinct from a trust verdict."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from wireledger.lab import certificates,tls_server
from wireledger.ledger import append,load_private
ROOT=Path(__file__).resolve().parents[1]
class CertificateInfoAcceptance(unittest.TestCase):
    def test_actual_capture_metadata_and_whole_chain_validation_before_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);state=root/'witness'
            def cli(*args,expected=0):
                r=subprocess.run([sys.executable,'-m','wireledger',*map(str,args)],cwd=ROOT,capture_output=True,text=True,timeout=10)
                self.assertEqual(r.returncode,expected,r.stdout+r.stderr);return json.loads(r.stdout) if r.stdout else None
            cli('init',state);ca,variants=certificates(root);cert,key=variants[0]
            with tls_server(cert,key) as port:cli('observe',state,'localhost','--port',port,'--connect-ip','127.0.0.1','--ca-file',ca)
            ledger=state/'observations.jsonl';public=state/'witness.pub';before=ledger.read_bytes();observed=json.loads(before.splitlines()[0])['body']['observation']
            args=('certificate-info',ledger,'--public-key',public,'--sequence','1');info=cli(*args)
            self.assertEqual(info['metadata']['certificate_sha256'],observed['certificate_sha256']);self.assertEqual(info['metadata']['spki_sha256'],observed['spki_sha256']);self.assertIn('localhost',info['metadata']['sans']);self.assertNotIn('pem',info);self.assertNotIn('PRIVATE KEY',json.dumps(info))
            cli(*args,'--index','0',expected=1);cli(*args,'--index','99',expected=1);self.assertEqual(ledger.read_bytes(),before)
            malformed=copy.deepcopy(observed);field=next(k for k,v in malformed['evidence'].items() if isinstance(v,list));malformed['evidence'][field].append('bm90LWRlcg==');append(ledger,load_private(state/'witness.key'),malformed);saved=ledger.read_bytes()
            cli('certificate-info',ledger,'--public-key',public,'--sequence','2','--index','1',expected=1);self.assertEqual(ledger.read_bytes(),saved)
