"""Detached signed picker keeps all conflicts and authenticates omitted claims."""
from pathlib import Path
import sys,json,subprocess,shutil
from wireledger.ledger import initialize,load_private,load_public,append,verify,make_checkpoint
root=Path(sys.argv[1]);w=root/'w';initialize(w);private=load_private(w/'witness.key');public=load_public(w/'witness.pub');ledger=w/'observations.jsonl';claims=[]
for n in range(1,4):append(ledger,private,{'host':'fictional.test','status':'error','n':n});claims.append(make_checkpoint(verify(ledger,public),private))
fork=root/'fork.jsonl';fork.touch()
for n in range(2):append(fork,private,{'host':'fork.test','status':'error','n':n})
conflict=make_checkpoint(verify(fork,public),private);key=root/'public.key';shutil.copy(w/'witness.pub',key);shutil.rmtree(w);fork.unlink();bundle={'format':'wireledger.checkpoint-bundle.v1','witness':claims[0]['body']['witness'],'checkpoints':[claims[0],claims[1],conflict,claims[2]]};source=root/'bundle.json';source.write_text(json.dumps(bundle));before=source.read_bytes();base=[sys.executable,'-m','wireledger','bundle-picker',str(source),'--public-key',str(key)];r=subprocess.run(base,capture_output=True,text=True);assert r.returncode==2,r.stderr;(root/'picker.html').write_text(r.stdout);(root/'expected.json').write_text(json.dumps({**bundle,'checkpoints':[claims[1],conflict]}));assert source.read_bytes()==before
bad={**bundle,'checkpoints':[{**claims[0],'signature':'invalid'},*bundle['checkpoints'][1:]]};source.write_text(json.dumps(bad));r=subprocess.run(base,capture_output=True);assert r.returncode==1 and not r.stdout;source.write_bytes(before)
