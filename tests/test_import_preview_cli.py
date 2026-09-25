"""Review authenticated imports before publication, then revalidate on apply."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from wireledger.ledger import append, load_private, make_checkpoint, verify

ROOT = Path(__file__).resolve().parents[1]


class ImportPreviewAcceptance(unittest.TestCase):
    def cli(self, *args, expected=0):
        result = subprocess.run([sys.executable, '-m', 'wireledger', *map(str, args)],
                                cwd=ROOT, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return json.loads(result.stdout) if result.stdout else result.stderr

    def test_preview_conflicts_and_fresh_apply_without_publishing_reviewed_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, store, absent = root/'witness', root/'retained', root/'absent'
            self.cli('init', state)
            ledger, public = state/'observations.jsonl', state/'witness.pub'
            key = load_private(state/'witness.key')
            observation = {'host':'fixture.test', 'port':443, 'vantage':'local', 'status':'error'}
            append(ledger, key, observation)
            first = make_checkpoint(verify(ledger, key.public_key()), key)
            one = root/'one.json'; one.write_text(json.dumps(first))
            self.cli('retain-checkpoint', one, '--store', store, '--public-key', public)
            original = ledger.read_bytes()
            append(ledger, key, observation)
            second = make_checkpoint(verify(ledger, key.public_key()), key)
            fork = root/'fork.jsonl'; fork.touch()
            append(fork, key, {**observation, 'vantage':'other'})
            conflicting = make_checkpoint(verify(fork, key.public_key()), key)
            bundle = root/'bundle.json'
            payload = {'format':'wireledger.checkpoint-bundle.v1', 'witness':first['body']['witness'],
                       'checkpoints':[first, second]}
            bundle.write_text(json.dumps(payload))
            saved = bundle.read_bytes()
            anchors = {p.name:p.read_bytes() for p in store.glob('anchor-*.json')}
            args = ('import-retained', bundle, '--public-key', public)
            preview = self.cli(*args, '--store', store, '--preview')
            self.assertTrue(preview['preview']); self.assertFalse(preview['retained'])
            self.assertEqual((preview['added_claims'], preview['already_retained_claims'], preview['total_claims']), (1,1,2))
            self.assertIn('not a reservation', preview['scope'])
            self.assertEqual({p.name:p.read_bytes() for p in store.glob('anchor-*.json')}, anchors)
            new = self.cli(*args, '--store', absent, '--preview')
            self.assertEqual(new['added_claims'], 2); self.assertFalse(absent.exists())
            capacity = root/'capacity.json'
            capacity.write_text(json.dumps({**payload, 'checkpoints':[second, conflicting]}))
            # Reduce only the subprocess budget to reach a real union-capacity boundary.
            refused = subprocess.run([sys.executable, '-c',
                'import wireledger.retention as r; r.MAX_CHECKPOINTS=2; '
                'from wireledger.__main__ import main; raise SystemExit(main())',
                'import-retained', str(capacity), '--store', str(store), '--public-key', str(public), '--preview'],
                cwd=ROOT, capture_output=True, text=True, timeout=15)
            self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
            self.assertIn('remaining checkpoint store capacity', refused.stderr)
            self.assertEqual({p.name:p.read_bytes() for p in store.glob('anchor-*.json')}, anchors)
            conflict_file = root/'conflict.json'; conflict_file.write_text(json.dumps(conflicting))
            self.cli('retain-checkpoint', conflict_file, '--store', store, '--public-key', public, expected=2)
            # A preview does not lock in the earlier counts or conceal a new signed conflict.
            applied = self.cli(*args, '--store', store, expected=2)
            self.assertEqual(applied['total_claims'], 3)
            self.assertTrue(applied['conflicting_heads']); self.assertTrue(applied['retained'])
            self.assertEqual(self.cli(*args, '--store', store, '--preview', expected=2)['added_claims'], 0)
            self.assertEqual(bundle.read_bytes(), saved)
            bad = json.loads(saved); bad['checkpoints'][1]['body']['head'] = 'f'*64
            bundle.write_text(json.dumps(bad))
            self.cli(*args, '--store', absent, '--preview', expected=1)
            self.assertFalse(absent.exists())
            self.assertTrue(ledger.read_bytes().startswith(original))
            self.assertEqual(self.cli('list-retained', '--store', store, '--public-key', public, expected=2)['count'], 3)
