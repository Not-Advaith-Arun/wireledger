from pathlib import Path
import sys,json,subprocess,runpy,copy
root=Path(sys.argv[1]);store=root/'w';ledger=store/'observations.jsonl';public=store/'witness.pub'
def cli(*args):return subprocess.run([sys.executable,'-m','wireledger',*map(str,args)],capture_output=True,text=True)
if len(sys.argv)==2:
 runpy.run_path(str(Path(__file__).with_name('certificate_pair_fixture.py')),run_name='__main__');h=cli('certificate-picker',ledger,'--public-key',public,'--limit','1');assert h.returncode==0,h.stderr;assert'BEGIN CERTIFICATE'not in h.stdout and'PRIVATE KEY'not in h.stdout;(root/'page1.html').write_text(h.stdout);(root/'before').write_bytes(ledger.read_bytes())
elif sys.argv[2]=='carry':
 r=cli('compare-certificates',ledger,'--public-key',public,'--selection',root/'carry.json');assert r.returncode==1 and not r.stdout;h=cli('certificate-picker',ledger,'--public-key',public,'--after-sequence','2','--limit','1','--selection',root/'carry.json');assert h.returncode==0,h.stderr;(root/'page2.html').write_text(h.stdout)
else:
 before=(root/'before').read_bytes();file=root/'out.json';good=file.read_bytes();value=json.loads(good);assert value['left_sequence']==1 and value['right_sequence']==3;args=['compare-certificates',ledger,'--public-key',public,'--selection',file];r=cli(*args);assert r.returncode==0,r.stderr;assert json.loads(r.stdout)['comparison']=='different_captured_key';h=cli(*args,'--html');assert h.returncode==0;(root/'comparison.html').write_text(h.stdout)
 for bad in[{**value,'witness':'wrong'},{**value,'count':value['count']+1},{**value,'head':'0'*64},{**value,'left_sequence':True},{**value,'right_sequence':999}]:
  file.write_text(json.dumps(bad));r=cli(*args);assert r.returncode==1 and not r.stdout;assert ledger.read_bytes()==before
 file.write_bytes(good);assert cli(*args,'--left-sequence','1').returncode==1
 from wireledger.ledger import append,load_private
 row=json.loads(before.splitlines()[0]);append(ledger,load_private(store/'witness.key'),row['body']['observation']);r=cli(*args);assert r.returncode==1 and not r.stdout;ledger.write_bytes(before)
 corrupted=before.replace(b'localhost',b'changed');ledger.write_bytes(corrupted);r=cli('certificate-picker',ledger,'--public-key',public);assert r.returncode==1 and not r.stdout;ledger.write_bytes(before);assert ledger.read_bytes()==before
