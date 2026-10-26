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

source=root/'conflict-bundle.json';before=source.read_bytes();recipient=root/'recipient'
def cli(*args):return subprocess.run([sys.executable,'-m','wireledger',*map(str,args)],capture_output=True,text=True)
base=['extract-checkpoint',source,'--public-key',key];r=cli(*base,'--count','1');assert r.returncode==0,r.stderr;assert json.loads(r.stdout)==claims[0];assert not recipient.exists()
for extra in [[],['--head',conflict['body']['head']]]:
 r=cli(*base,'--count','2',*extra)
 if not extra:assert r.returncode==1 and not r.stdout
 else:
  assert r.returncode==0 and json.loads(r.stdout)==conflict;output=root/'chosen.json';output.write_text(r.stdout);retained=cli('retain-checkpoint',output,'--store',recipient,'--public-key',key);assert retained.returncode==0,retained.stderr
listed=cli('list-retained','--store',recipient,'--public-key',key);assert listed.returncode==0 and conflict['body']['head']in listed.stdout
for extra in [['--count','9'],['--count','-1'],['--count','1','--head','missing']]:
 r=cli(*base,*extra);assert r.returncode==1 and not r.stdout
value=json.loads(source.read_text());value['checkpoints'][-1]['signature']='invalid';bad=root/'bad-bundle.json';bad.write_text(json.dumps(value));r=cli('extract-checkpoint',bad,'--public-key',key,'--count','1');assert r.returncode==1 and not r.stdout;assert source.read_bytes()==before
