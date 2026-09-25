"""One explicit policy drives signed loopback success and failure collection."""
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

from wireledger.lab import certificates, tls_server

ROOT=Path(__file__).resolve().parents[1]


class PolicyCollectionAcceptance(unittest.TestCase):
    def test_complete_policy_validation_precedes_loopback_collection_and_failures_are_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); state=root/'witness'; policy=root/'policy.json'
            def cli(*args,expected=0,trapped=False):
                code=("import sys; from unittest.mock import patch; from wireledger.__main__ import main\n"
                      "with patch('wireledger.collection.observe',side_effect=RuntimeError('network must not start')):\n"
                      " raise SystemExit(main(sys.argv[1:]))\n")
                command=[sys.executable,'-c',code] if trapped else [sys.executable,'-m','wireledger']
                r=subprocess.run([*command,*map(str,args)],cwd=ROOT,capture_output=True,text=True,timeout=15)
                self.assertEqual(r.returncode,expected,r.stdout+r.stderr)
                return json.loads(r.stdout) if r.stdout else r
            cli('init',state); ca,variants=certificates(root); cert,key=variants[0]
            ledger=state/'observations.jsonl'; original=ledger.read_bytes()
            with tls_server(cert,key) as good, socket.socket() as refused:
                refused.bind(('127.0.0.1',0)); bad=refused.getsockname()[1]
                rows=[{'host':'LOCALHOST.','port':good,'vantage':'selected-good'},
                      {'host':'localhost','port':bad,'vantage':'selected-failed'}]
                args=('observe-policy',state,'--expected',policy,'--connect-ip','127.0.0.1','--ca-file',ca,'--timeout','1')
                for invalid in ([], rows+[rows[0]], rows+[{'host':'other','port':True,'vantage':'bad'}],
                                [{'host':'localhost','port':good,'vantage':str(i)} for i in range(17)]):
                    policy.write_text(json.dumps(invalid)); cli(*args,expected=1,trapped=True)
                    self.assertEqual(ledger.read_bytes(),original)
                policy.write_text(json.dumps(rows)); saved=policy.read_bytes()
                report=cli(*args,expected=2)
                self.assertFalse(report['all_verified']); self.assertEqual(report['recorded_samples'],2)
                self.assertEqual({r['status'] for r in report['samples']},{'verified','connection-failed'})
                self.assertEqual([r['sequence'] for r in report['samples']],[1,2])
                self.assertTrue(all(r['host']=='localhost' for r in report['samples']))
                public=state/'witness.pub'
                self.assertEqual(cli('verify',ledger,'--public-key',public)['count'],2)
                coverage=cli('coverage',ledger,'--public-key',public,'--expected',policy,expected=2)
                self.assertEqual({r['collection_state'] for r in coverage['results']},{'observed-verified','latest-failed'})
                first=ledger.read_bytes(); again=cli(*args,expected=2)
                self.assertEqual([r['sequence'] for r in again['samples']],[3,4])
                self.assertTrue(ledger.read_bytes().startswith(first)); self.assertEqual(policy.read_bytes(),saved)
                damaged=ledger.read_bytes().replace(b'localhost',b'forged-host',1);ledger.write_bytes(damaged)
                cli(*args,expected=1,trapped=True); self.assertEqual(ledger.read_bytes(),damaged)
