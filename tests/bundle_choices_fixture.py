from pathlib import Path
import sys,json,subprocess,runpy,copy
root=Path(sys.argv[1]);bundle=root/'bundle.json';key=root/'public.key'
def cli(*args):return subprocess.run([sys.executable,'-m','wireledger',*map(str,args)],capture_output=True,text=True)
if len(sys.argv)==2:runpy.run_path(str(Path(__file__).with_name('bundle_picker_fixture.py')),run_name='__main__')
elif sys.argv[2]=='resume':
 h=cli('bundle-picker',bundle,'--public-key',key,'--choices',root/'choices.json');assert h.returncode==2,h.stderr;(root/'resumed.html').write_text(h.stdout)
else:
 file=root/'choices.json';good=file.read_bytes();choices=json.loads(good);assert choices['counts']==[2];before=bundle.read_bytes();data=json.loads(before)
 for bad in[{**choices,'bundle_sha256':'0'*64},{**choices,'witness':'wrong'},{**choices,'counts':[True]},{**choices,'counts':[2,2]},{**choices,'counts':[999]}]:
  file.write_text(json.dumps(bad));r=cli('bundle-picker',bundle,'--public-key',key,'--choices',file);assert r.returncode==1 and not r.stdout
 file.write_bytes(good);changed=copy.deepcopy(data);changed['checkpoints'].reverse();bundle.write_text(json.dumps(changed));r=cli('bundle-picker',bundle,'--public-key',key,'--choices',file);assert r.returncode==1 and not r.stdout;changed=copy.deepcopy(data);changed['checkpoints'][0]['signature']='invalid';bundle.write_text(json.dumps(changed));r=cli('bundle-picker',bundle,'--public-key',key,'--choices',file);assert r.returncode==1 and not r.stdout;bundle.write_bytes(before)
 selected=json.loads((root/'selected.json').read_text());assert selected==json.loads((root/'expected.json').read_text());recipient=root/'recipient';r=cli('import-retained',root/'selected.json','--store',recipient,'--public-key',key,'--preview');assert r.returncode==2 and json.loads(r.stdout)['imported_claims']==2;assert not recipient.exists();assert bundle.read_bytes()==before
