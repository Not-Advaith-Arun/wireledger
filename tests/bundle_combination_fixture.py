"""Independent detached signed inputs combine without history or destination access."""
from pathlib import Path
import sys,json,subprocess,re,shutil
from wireledger.ledger import initialize,load_private,load_public,append,verify,make_checkpoint
root=Path(sys.argv[1]);w=root/'w';initialize(w);private=load_private(w/'witness.key');public=load_public(w/'witness.pub');ledger=w/'observations.jsonl';claims=[]
for n in range(1,3):append(ledger,private,{'host':'fictional.test','status':'error','n':n});claims.append(make_checkpoint(verify(ledger,public),private))
fork=root/'fork.jsonl';fork.touch()
for n in range(2):append(fork,private,{'host':'fork.test','status':'error','n':n})
conflict=make_checkpoint(verify(fork,public),private);key=root/'public.key';shutil.copy(w/'witness.pub',key);shutil.rmtree(w);fork.unlink();left={'format':'wireledger.checkpoint-bundle.v1','witness':claims[0]['body']['witness'],'checkpoints':claims};right={**left,'checkpoints':[claims[0],conflict]};a=root/'left.json';b=root/'right.json';a.write_text(json.dumps(left));b.write_text(json.dumps(right));before=[a.read_bytes(),b.read_bytes()];expected={**left,'checkpoints':[*claims,conflict]};base=[sys.executable,'-m','wireledger','combine-bundles',str(a),str(b),'--public-key',str(key)];r=subprocess.run(base,capture_output=True,text=True);assert r.returncode==2,r.stderr;assert json.loads(r.stdout)==expected;h=subprocess.run(base+['--html'],capture_output=True,text=True);assert h.returncode==2,h.stderr;assert json.loads(re.search(r'<script id="report-data" type="application/json">(.*?)</script>',h.stdout,re.S).group(1))==expected;(root/'combined.html').write_text(h.stdout);(root/'expected.json').write_text(json.dumps(expected));assert[a.read_bytes(),b.read_bytes()]==before
right['checkpoints'][0]={**claims[0],'signature':'invalid'};b.write_text(json.dumps(right));r=subprocess.run(base+['--html'],capture_output=True);assert r.returncode==1 and not r.stdout;b.write_bytes(before[1])
# Real signed native inputs exercise the union capacity independently of one valid side.
large=[]
for n in range(1024):
 body={'format':'wireledger.checkpoint.v1','witness':left['witness'],'count':n+1,'head':format(n,'064x')};from wireledger.ledger import canonical,CHECKPOINT_DOMAIN;import base64
 large.append({'body':body,'signature':base64.b64encode(private.sign(CHECKPOINT_DOMAIN+canonical(body))).decode('ascii')})
a.write_text(json.dumps({**left,'checkpoints':large}));r=subprocess.run(base,capture_output=True);assert r.returncode==1 and not r.stdout;a.write_bytes(before[0])
