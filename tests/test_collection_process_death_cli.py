"""An interrupted multi-endpoint collection can have a valid published prefix."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from wireledger.lab import certificates, tls_server

ROOT=Path(__file__).resolve().parents[1]


class CollectionProcessDeathAcceptance(unittest.TestCase):
    def test_published_prefix_survives_process_exit_and_retry_records_new_samples(self):
        # Actual process death bypasses Python cleanup and command output. This
        # targets the acknowledgement boundary, not hardware power-loss behavior.
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);state=root/'witness';policy=root/'policy.json'
            def cli(*args,expected=0):
                r=subprocess.run([sys.executable,'-m','wireledger',*map(str,args)],cwd=ROOT,
                                 capture_output=True,text=True,timeout=12)
                self.assertEqual(r.returncode,expected,r.stdout+r.stderr)
                return json.loads(r.stdout)
            cli('init',state);ca,variants=certificates(root);cert,key=variants[0]
            with tls_server(cert,key) as port:
                rows=[{'host':'localhost','port':port,'vantage':label} for label in ('one','two')]
                policy.write_text(json.dumps(rows));original=policy.read_bytes()
                args=['observe-policy',str(state),'--expected',str(policy),'--connect-ip','127.0.0.1','--ca-file',str(ca),'--timeout','2']
                code=("import os; from unittest.mock import patch; import wireledger.collection as c; from wireledger.__main__ import main\n"
                      "real_append=c.append\n"
                      "def terminate(*args,**kwargs):\n"
                      " record=real_append(*args,**kwargs)\n"
                      " os._exit(73)\n"
                      "with patch.object(c,'append',side_effect=terminate):\n"
                      " raise SystemExit(main())\n")
                died=subprocess.run([sys.executable,'-c',code,*args],cwd=ROOT,capture_output=True,text=True,timeout=12)
                self.assertEqual(died.returncode,73,died.stdout+died.stderr);self.assertEqual(died.stdout,'')
                ledger=state/'observations.jsonl';public=state/'witness.pub';published=ledger.read_bytes()
                self.assertEqual(cli('verify',ledger,'--public-key',public)['count'],1)
                incomplete=cli('coverage',ledger,'--public-key',public,'--expected',policy,expected=2)
                self.assertEqual({r['collection_state'] for r in incomplete['results']},{'observed-verified','missing'})
                retried=cli(*args)
                self.assertTrue(retried['all_verified']);self.assertEqual([r['sequence'] for r in retried['samples']],[2,3])
                self.assertTrue(ledger.read_bytes().startswith(published))
                self.assertEqual(cli('verify',ledger,'--public-key',public)['count'],3)
                completed=cli('coverage',ledger,'--public-key',public,'--expected',policy)
                self.assertEqual({r['vantage']:r['samples'] for r in completed['results']},{'one':2,'two':1})
                self.assertEqual(policy.read_bytes(),original)
