"""Real detached subset/conflict inspection authenticates every claim without stores."""
from pathlib import Path
import sys,json,subprocess,re,hashlib,shutil
from wireledger.ledger import initialize,load_private,load_public,append,verify,make_checkpoint,canonical
root=Path(sys.argv[1]);w=root/'w';initialize(w);private=load_private(w/'witness.key');public=load_public(w/'witness.pub');ledger=w/'observations.jsonl';claims=[]
for n in range(1,3):append(ledger,private,{'host':'fictional.test','status':'error','error':'PRIVATE_DIAGNOSTIC','n':n});claims.append(make_checkpoint(verify(ledger,public),private))
fork=root/'fork.jsonl';fork.touch()
for n in range(2):append(fork,private,{'host':'other.test','status':'error','n':n})
conflict=make_checkpoint(verify(fork,public),private);witness=claims[0]['body']['witness'];key=root/'public.key';shutil.copy(w/'witness.pub',key);shutil.rmtree(w);fork.unlink()
for name,selected,counts in [('subset',claims,[]),('conflict',[*claims,conflict],[2])]:
 source=root/(name+'-bundle.json');source.write_text(json.dumps({'format':'wireledger.checkpoint-bundle.v1','witness':witness,'checkpoints':selected}));before=source.read_bytes();files=set(root.iterdir());base=[sys.executable,'-m','wireledger','inspect-bundle',str(source),'--public-key',str(key)];native=subprocess.run(base,capture_output=True,text=True);data=json.loads(native.stdout);assert data['conflicting_counts']==counts and data['claim_count']==len(selected);assert data['claims']==[{'count':cp['body']['count'],'head':cp['body']['head'],'sha256':hashlib.sha256(canonical(cp)).hexdigest()}for cp in selected];html=subprocess.run(base+['--html'],capture_output=True,text=True);assert native.returncode==html.returncode==(2 if counts else 0);assert json.loads(re.search(r'<script id="report-data" type="application/json">(.*?)</script>',html.stdout,re.S).group(1))==data;assert 'PRIVATE_DIAGNOSTIC'not in html.stdout and 'PRIVATE KEY'not in html.stdout;assert source.read_bytes()==before and set(root.iterdir())==files;(root/(name+'.html')).write_text(html.stdout);(root/(name+'.json')).write_text(json.dumps(data))

left=root/'subset-bundle.json';right=root/'conflict-bundle.json';files=set(root.iterdir());before={p:p.read_bytes()for p in files if p.is_file()}
for name,other,code in [('same',left,0),('different',right,2)]:
 base=[sys.executable,'-m','wireledger','compare-bundles',str(left),str(other),'--public-key',str(key)]
 r=subprocess.run(base,capture_output=True,text=True);assert r.returncode==code,r.stderr;report=json.loads(r.stdout);assert report['shared_claim_count']==2;assert len(report['claims'])==(2 if name=='same'else 3)
 html=subprocess.run(base+['--html'],capture_output=True,text=True);assert html.returncode==code and 'PRIVATE_DIAGNOSTIC'not in html.stdout;assert json.loads(re.search(r'<script id="report-data" type="application/json">(.*?)</script>',html.stdout,re.S).group(1))==report
 (root/(name+'.html')).write_text(html.stdout);(root/(name+'.json')).write_text(json.dumps(report))
for p,raw in before.items():assert p.read_bytes()==raw
bad=root/'tampered.json';value=json.loads(right.read_text());value['checkpoints'][-1]['signature']='invalid';bad.write_text(json.dumps(value));r=subprocess.run([sys.executable,'-m','wireledger','compare-bundles',str(left),str(bad),'--public-key',str(key),'--html'],capture_output=True);assert r.returncode==1 and not r.stdout
