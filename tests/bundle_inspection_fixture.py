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
source=root/'bad.json';base=[sys.executable,'-m','wireledger','inspect-bundle',str(source),'--public-key',str(key),'--html'];valid={'format':'wireledger.checkpoint-bundle.v1','witness':witness,'checkpoints':claims}
for payload in [{**valid,'checkpoints':[]},{**valid,'checkpoints':[claims[0],claims[0]]},{**valid,'checkpoints':[claims[0],{**claims[1],'signature':'invalid'}]},{**valid,'witness':'wrong'}]:
 source.write_text(json.dumps(payload));before=source.read_bytes();bad=subprocess.run(base,capture_output=True,text=True);assert bad.returncode==1 and not bad.stdout and source.read_bytes()==before
