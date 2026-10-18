"""A valid witness signature cannot turn forged certificate bytes into evidence."""
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
class SignedMalformedCaptureAcceptance(unittest.TestCase):
    def test_signed_bad_capture_refuses_complete_pem_export_without_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);state=root/'witness'
            def cli(*args,expected=0):
                r=subprocess.run([sys.executable,'-m','wireledger',*map(str,args)],cwd=ROOT,capture_output=True,text=True,timeout=10)
                self.assertEqual(r.returncode,expected,r.stdout+r.stderr);return r
            cli('init',state);ca,variants=certificates(root);cert,key=variants[0]
            with tls_server(cert,key) as port:cli('observe',state,'localhost','--port',port,'--connect-ip','127.0.0.1','--ca-file',ca)
            ledger=state/'observations.jsonl';public=state/'witness.pub';private=load_private(state/'witness.key')
            valid=json.loads(ledger.read_bytes().splitlines()[0])['body']['observation']
            self.assertIn('CERTIFICATE',cli('certificate-chain',ledger,'--public-key',public,'--sequence','1').stdout)
            malformed=copy.deepcopy(valid);field=next(k for k,v in malformed['evidence'].items() if isinstance(v,list));malformed['evidence'][field].append('bm90IGEgY2VydGlmaWNhdGU=')
            append(ledger,private,malformed);saved=ledger.read_bytes()
            # Signature-only verification remains a different claim from certificate validation.
            self.assertTrue(json.loads(cli('verify',ledger,'--public-key',public).stdout)['valid'])
            for extra in ([],['--json']):
                failed=cli('certificate-chain',ledger,'--public-key',public,'--sequence','2',*extra,expected=1)
                self.assertEqual(failed.stdout,'');self.assertNotIn('Traceback',failed.stderr);self.assertEqual(ledger.read_bytes(),saved)
            mismatch=copy.deepcopy(valid);mismatch['certificate_sha256']='0'*64;append(ledger,private,mismatch);saved=ledger.read_bytes()
            failed=cli('certificate-chain',ledger,'--public-key',public,'--sequence','3',expected=1);self.assertEqual(failed.stdout,'');self.assertEqual(ledger.read_bytes(),saved)
