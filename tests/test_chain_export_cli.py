"""Public captured chain bytes can feed independent offline certificate tools."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from wireledger.lab import certificates,tls_server
from wireledger.ledger import append,load_private

ROOT=Path(__file__).resolve().parents[1]


class ChainExportAcceptance(unittest.TestCase):
    def test_signed_selected_capture_exports_only_public_bytes_and_authenticates_excluded_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);state=root/'witness';foreign=root/'foreign'
            def cli(*args,expected=0,raw=False):
                r=subprocess.run([sys.executable,'-m','wireledger',*map(str,args)],cwd=ROOT,capture_output=True,text=True,timeout=12)
                self.assertEqual(r.returncode,expected,r.stdout+r.stderr)
                return r.stdout if raw else json.loads(r.stdout) if r.stdout else r
            cli('init',state);cli('init',foreign);ca,variants=certificates(root);cert,key=variants[0]
            with tls_server(cert,key) as port:
                for vantage in ('one','two'):cli('observe',state,'localhost','--port',port,'--vantage',vantage,'--connect-ip','127.0.0.1','--ca-file',ca)
            ledger=state/'observations.jsonl';public=state/'witness.pub'
            append(ledger,load_private(state/'witness.key'),{'host':'legacy.test','port':443,'vantage':'legacy','status':'error'})
            original=ledger.read_bytes();args=('certificate-chain',ledger,'--public-key',public,'--sequence','2')
            report=cli(*args,'--json');pem=cli(*args,raw=True);self.assertEqual(pem,report['pem'])
            blocks=re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',pem,re.S)
            digests=[hashlib.sha256(x509.load_pem_x509_certificate(block.encode()).public_bytes(serialization.Encoding.DER)).hexdigest() for block in blocks]
            self.assertEqual(digests,report['sha256']);self.assertEqual(len(blocks),report['certificate_count'])
            selected=json.loads(original.splitlines()[1])['body']['observation'];self.assertEqual(digests[0],selected['certificate_sha256'])
            self.assertNotIn('PRIVATE KEY',pem);self.assertEqual(ledger.read_bytes(),original)
            for sequence in ('0','3','4'):cli('certificate-chain',ledger,'--public-key',public,'--sequence',sequence,expected=1)
            cli('certificate-chain',ledger,'--public-key',foreign/'witness.pub','--sequence','2',expected=1)
            self.assertEqual(ledger.read_bytes(),original)
            rows=original.splitlines();changed=json.loads(rows[0]);changed['body']['observation']['vantage']='forged';rows[0]=json.dumps(changed).encode();damaged=b'\n'.join(rows)+b'\n';ledger.write_bytes(damaged)
            cli(*args,expected=1);self.assertEqual(ledger.read_bytes(),damaged)
