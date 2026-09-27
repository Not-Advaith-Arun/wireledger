"""Scoped signed inventory still authenticates omitted observations."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from wireledger.ledger import append,load_private
ROOT=Path(__file__).resolve().parents[1]
class ScopedInventoryAcceptance(unittest.TestCase):
    def test_selection_retains_global_counts_rejects_policy_and_excluded_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory)/'witness'
            def cli(*args,expected=0):
                r=subprocess.run([sys.executable,'-m','wireledger',*map(str,args)],cwd=ROOT,capture_output=True,text=True,timeout=5)
                self.assertEqual(r.returncode,expected,r.stdout+r.stderr);return json.loads(r.stdout) if r.stdout else None
            cli('init',state);ledger=state/'observations.jsonl';public=state/'witness.pub';private=load_private(state/'witness.key')
            for host,vantage in [('one.test','private-a'),('two.test','private-b'),('one.test','private-c')]:append(ledger,private,{'host':host,'port':443,'vantage':vantage,'status':'error'})
            original=ledger.read_bytes();args=('endpoints',ledger,'--public-key',public)
            chosen=cli(*args,'--host','one.test','--vantage','private-c','--failed-only')
            self.assertEqual(chosen['total_records'],3);self.assertEqual(chosen['endpoint_vantage_groups'],3)
            self.assertEqual(chosen['selected_groups'],1);self.assertEqual(chosen['omitted_groups'],2)
            self.assertEqual(chosen['results'][0]['latest']['sequence'],3);self.assertNotIn('private-b',json.dumps(chosen))
            self.assertEqual(cli(*args,'--host','ONE.TEST')['selected_groups'],0)
            cli(*args,'--policy','--failed-only',expected=1);self.assertEqual(ledger.read_bytes(),original)
            damaged=original.replace(b'two.test',b'bad.test',1);ledger.write_bytes(damaged)
            cli(*args,'--host','one.test',expected=1);self.assertEqual(ledger.read_bytes(),damaged)
