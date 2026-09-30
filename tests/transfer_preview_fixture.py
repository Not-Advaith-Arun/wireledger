"""Real signed transfer previews refuse accidental publication and bad trust."""
from pathlib import Path
import sys,subprocess,json,re
from wireledger.ledger import initialize,load_private,load_public,append,make_checkpoint,verify
from wireledger.retention import retain_checkpoint,export_bundle
root=Path(sys.argv[1]);w=root/'witness';initialize(w);private=load_private(w/'witness.key');public=load_public(w/'witness.pub');ledger=w/'observations.jsonl';origin=root/'origin';dest=root/'absent-destination'
append(ledger,private,{'host':'fictional.test','status':'error','error':'PRIVATE_DIAGNOSTIC'});cp=make_checkpoint(verify(ledger,public),private);retain_checkpoint(origin,cp,public);bundle=root/'bundle.json';bundle.write_text(json.dumps(export_bundle(origin,public)));original=bundle.read_bytes()
for name in ['absent','existing']:
 if name=='existing':retain_checkpoint(dest,cp,public)
 before={p:p.read_bytes()for p in dest.iterdir()}if dest.exists()else None
 base=[sys.executable,'-m','wireledger','import-retained',str(bundle),'--store',str(dest),'--public-key',str(w/'witness.pub')];native=subprocess.run(base+['--preview'],capture_output=True,text=True);data=json.loads(native.stdout);html=subprocess.run(base+['--preview','--html'],capture_output=True,text=True);assert native.returncode==html.returncode==0;assert json.loads(re.search(r'<script id="report-data" type="application/json">(.*?)</script>',html.stdout,re.S).group(1))==data;assert data['added_claims']==(1 if name=='absent'else 0);assert 'PRIVATE_DIAGNOSTIC'not in html.stdout and 'PRIVATE KEY'not in html.stdout;(root/(name+'.html')).write_text(html.stdout);(root/(name+'.json')).write_text(json.dumps(data));assert (not dest.exists())if before is None else all(p.read_bytes()==v for p,v in before.items())
 refused=subprocess.run(base+['--html'],capture_output=True,text=True);assert refused.returncode==1 and not refused.stdout
assert bundle.read_bytes()==original
other=root/'other';initialize(other);bad=subprocess.run([*base[:-1],str(other/'witness.pub'),'--preview','--html'],capture_output=True,text=True);assert bad.returncode==1 and not bad.stdout
