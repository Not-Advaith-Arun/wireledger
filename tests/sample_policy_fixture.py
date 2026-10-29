from pathlib import Path
import json,sys,subprocess,runpy
root=Path(sys.argv[1]);runpy.run_path(str(Path(__file__).with_name('certificate_pair_fixture.py')),run_name='__main__');store=root/'w';ledger=store/'observations.jsonl';public=store/'witness.pub';before=ledger.read_bytes()
def cli(*args):return subprocess.run([sys.executable,'-m','wireledger',*map(str,args)],capture_output=True,text=True)
base=['policy-from-samples',ledger,'--public-key',public,'--sequence','3','--sequence','1'];r=cli(*base);assert r.returncode==0,r.stderr;expected=json.loads(r.stdout);assert len(expected)==1 and expected[0]['host']=='localhost';(root/'expected.json').write_text(r.stdout);h=cli(*base,'--html');assert h.returncode==0,h.stderr;assert 'PRIVATE KEY' not in h.stdout and 'BEGIN CERTIFICATE' not in h.stdout;(root/'picker.html').write_text(h.stdout)
for extra in [['--sequence','1'],['--sequence','0'],['--sequence','4']]:
 r=cli(*base,*extra);assert r.returncode==1 and not r.stdout
ledger.write_bytes(before.replace(b'localhost',b'tampered'));r=cli(*base);assert r.returncode==1 and not r.stdout;ledger.write_bytes(before)
code="from unittest.mock import patch;from wireledger.__main__ import main\nwith patch('socket.getaddrinfo',side_effect=RuntimeError('DNS forbidden')),patch('wireledger.__main__.load_private',side_effect=RuntimeError('key forbidden')):raise SystemExit(main("+repr(list(map(str,base)))+"))";assert subprocess.run([sys.executable,'-c',code],capture_output=True).returncode==0
if len(sys.argv)>2:
 assert json.loads((root/'download.json').read_text())==expected
 from wireledger.collection import preview_policy
 assert preview_policy(store,expected)['selected_endpoints']==1
assert ledger.read_bytes()==before
