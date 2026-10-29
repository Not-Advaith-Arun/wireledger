from pathlib import Path
import sys,json,subprocess,runpy
root=Path(sys.argv[1]);runpy.run_path(str(Path(__file__).with_name('certificate_pair_fixture.py')),run_name='__main__');store=root/'w';ledger=store/'observations.jsonl';public=store/'witness.pub';before=ledger.read_bytes()
def cli(*args):return subprocess.run([sys.executable,'-m','wireledger',*map(str,args)],capture_output=True,text=True)
base=['history-prefix',ledger,'--public-key',public,'--count','2'];r=cli(*base);assert r.returncode==0,r.stderr;data=json.loads(r.stdout);assert data['source_records']==3 and data['selected_records']==2 and data['omitted_suffix_records']==1;assert 'BEGIN CERTIFICATE' not in r.stdout;(root/'expected.json').write_text(r.stdout);h=cli(*base,'--html');assert h.returncode==0,h.stderr;(root/'prefix.html').write_text(h.stdout)
r=cli(*base,'--jsonl');assert r.returncode==0,r.stderr;prefix=root/'prefix.jsonl';prefix.write_text(r.stdout);assert [json.loads(line)for line in r.stdout.splitlines()]==[json.loads(line)for line in before.splitlines()[:2]];r=cli('verify',prefix,'--public-key',public);assert r.returncode==0 and json.loads(r.stdout)['count']==2
anchor=root/'latest-checkpoint.json';r=cli('checkpoint',store,anchor);assert r.returncode==0,r.stderr;r=cli('verify',prefix,'--public-key',public,'--checkpoint',anchor);assert r.returncode==1 and not r.stdout
for count in ['-1','4','1001']:
 r=cli('history-prefix',ledger,'--public-key',public,'--count',count,'--jsonl');assert r.returncode==1 and not r.stdout
r=cli('history-prefix',ledger,'--public-key',public,'--count','0','--jsonl');assert r.returncode==0 and not r.stdout
ledger.write_bytes(before.replace(b'localhost',b'tampered'));r=cli(*base,'--jsonl');assert r.returncode==1 and not r.stdout;ledger.write_bytes(before)
code="from unittest.mock import patch;from wireledger.__main__ import main\nwith patch('socket.getaddrinfo',side_effect=RuntimeError('DNS forbidden')),patch('wireledger.__main__.load_private',side_effect=RuntimeError('key forbidden')):raise SystemExit(main("+repr(list(map(str,base)))+"))";assert subprocess.run([sys.executable,'-c',code],capture_output=True).returncode==0;assert ledger.read_bytes()==before
