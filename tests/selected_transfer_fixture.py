"""Actual selected signed-claim transfer keeps same-count conflicts and source bytes."""
from pathlib import Path
import sys,json,subprocess,re
from wireledger.ledger import initialize,load_private,load_public,append,verify,make_checkpoint
from wireledger.retention import retain_checkpoint
root=Path(sys.argv[1]);w=root/'w';initialize(w);private=load_private(w/'witness.key');public=load_public(w/'witness.pub');ledger=w/'observations.jsonl';store=root/'retained';retain_checkpoint(store,make_checkpoint([],private),public)
for n in range(1,3):append(ledger,private,{'host':'fictional.test','status':'error','n':n});retain_checkpoint(store,make_checkpoint(verify(ledger,public),private),public)
fork=root/'fork.jsonl';fork.touch()
for n in range(2):append(fork,private,{'host':'other.test','status':'error','n':n})
retain_checkpoint(store,make_checkpoint(verify(fork,public),private),public);before={p.name:p.read_bytes()for p in store.iterdir()if p.is_file()};base=[sys.executable,'-m','wireledger','export-retained','--store',str(store),'--public-key',str(w/'witness.pub')];all_claims=json.loads(subprocess.check_output(base,text=True));assert len(all_claims['checkpoints'])==4
for name,counts,expected_count,conflict in [('prefix',[0,1],2,False),('conflicts',[2],2,True)]:
 flags=[part for count in counts for part in ['--count',str(count)]];exported=subprocess.run(base+flags,capture_output=True,text=True);assert exported.returncode==0,exported.stderr;bundle=json.loads(exported.stdout);expected=[cp for cp in all_claims['checkpoints']if cp['body']['count']in counts];assert bundle['checkpoints']==expected and len(expected)==expected_count;source=root/(name+'-bundle.json');source.write_text(exported.stdout);destination=root/(name+'-absent');preview=[sys.executable,'-m','wireledger','import-retained',str(source),'--store',str(destination),'--public-key',str(w/'witness.pub'),'--preview'];native=subprocess.run(preview,capture_output=True,text=True);data=json.loads(native.stdout);assert data['conflicting_heads']==conflict and data['imported_claims']==expected_count;html=subprocess.run(preview+['--html'],capture_output=True,text=True);assert html.returncode==native.returncode==(2 if conflict else 0);assert json.loads(re.search(r'<script id="report-data" type="application/json">(.*?)</script>',html.stdout,re.S).group(1))==data;(root/(name+'.html')).write_text(html.stdout);(root/(name+'.json')).write_text(json.dumps(data));assert not destination.exists();assert before=={p.name:p.read_bytes()for p in store.iterdir()if p.is_file()}
for flags in [['--count','9'],['--count','-1'],['--count','1','--count','1']]:
 bad=subprocess.run(base+flags,capture_output=True,text=True);assert bad.returncode==1 and not bad.stdout
# A corrupt claim outside the selected count cannot be hidden by selection.
path=next(p for p in store.glob('anchor-*.json')if json.loads(p.read_text())['body']['count']==1);bad_claim=json.loads(path.read_text());bad_claim['signature']='invalid';path.write_text(json.dumps(bad_claim));bad=subprocess.run(base+['--count','2'],capture_output=True,text=True);assert bad.returncode==1 and not bad.stdout
