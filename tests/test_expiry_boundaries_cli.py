"""Critical certificate/observer threshold arithmetic through signed-history CLI."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from wireledger.ledger import append,load_private

ROOT=Path(__file__).resolve().parents[1]


class CertificateTimeBoundaryAcceptance(unittest.TestCase):
    def test_inclusive_leaf_window_and_sampling_cutoffs_keep_microsecond_and_timezone_precision(self):
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory)/'witness'
            def cli(*args,expected=0):
                r=subprocess.run([sys.executable,'-m','wireledger',*map(str,args)],cwd=ROOT,
                                 capture_output=True,text=True,timeout=6)
                self.assertEqual(r.returncode,expected,r.stdout+r.stderr)
                return json.loads(r.stdout)
            cli('init',state);ledger=state/'observations.jsonl';public=state/'witness.pub'
            # Synthetic signed observer claims isolate time calculations; these
            # are not a TLS handshake or an independent certificate-path audit.
            sample={'host':'fixture.test','port':443,'vantage':'local','status':'verified',
                    'observed_at':'2028-02-29T00:00:00Z','not_before':'2028-02-28T00:00:00Z',
                    'not_after':'2028-03-01T00:00:00Z','certificate_sha256':'a'*64,'spki_sha256':'b'*64}
            append(ledger,load_private(state/'witness.key'),sample);original=ledger.read_bytes()
            args=('expiry',ledger,'--public-key',public,'--within-days','1','--max-age-seconds','86400')
            def at(instant):return cli(*args,'--as-of',instant,expected=2)['results'][0]
            horizon=at('2028-02-29T00:00:00Z')
            self.assertEqual(horizon['certificate_window'],'expires-within-horizon');self.assertEqual(horizon['seconds_until_expiry'],86400)
            just_before=at('2028-02-28T23:59:59.999999Z')
            self.assertEqual(just_before['certificate_window'],'beyond-horizon');self.assertEqual(just_before['sampling_state'],'future-sample')
            edge=at('2028-03-01T00:00:00Z');equivalent=at('2028-03-01T05:30:00+05:30')
            self.assertEqual(edge,equivalent);self.assertEqual(edge['certificate_window'],'expires-within-horizon')
            self.assertEqual(edge['seconds_until_expiry'],0);self.assertEqual(edge['age_seconds'],86400)
            self.assertEqual(edge['sampling_state'],'within-observer-threshold')
            beyond=at('2028-03-01T00:00:00.000001Z')
            self.assertEqual(beyond['certificate_window'],'expired');self.assertEqual(beyond['sampling_state'],'stale-sample')
            self.assertLess(beyond['seconds_until_expiry'],0)
            before_start=at('2028-02-27T23:59:59.999999Z');start=at('2028-02-28T00:00:00Z')
            self.assertEqual(before_start['certificate_window'],'not-yet-valid');self.assertEqual(start['certificate_window'],'beyond-horizon')
            zero=cli('expiry',ledger,'--public-key',public,'--as-of','2028-03-01T00:00:00Z','--within-days','0',expected=2)
            self.assertEqual(zero['results'][0]['certificate_window'],'expires-within-horizon')
            self.assertEqual(ledger.read_bytes(),original)
