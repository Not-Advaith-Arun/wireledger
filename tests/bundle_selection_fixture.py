"""Detached transfer roundtrip with no source store, retaining conflicting heads."""
from pathlib import Path
import sys,json,subprocess,re,shutil
from wireledger.ledger import initialize,load_private,load_public,append,verify,make_checkpoint
root=Path(sys.argv[1]);w=root/'w';initialize(w);private=load_private(w/'witness.key');public=load_public(w/'witness.pub');ledger=w/'observations.jsonl';claims=[]
for n in range(1,4):
 append(ledger,private,{'host':'fictional.test','status':'error','n':n});claims.append(make_checkpoint(verify(ledger,public),private))
fork=root/'fork.jsonl';fork.touch()
for n in range(2):append(fork,private,{'host':'fork.test','status':'error','n':n})
conflict=make_checkpoint(verify(fork,public),private);key=root/'public.key';shutil.copy(w/'witness.pub',key);shutil.rmtree(w);fork.unlink();bundle={'format':'wireledger.checkpoint-bundle.v1','witness':claims[0]['body']['witness'],'checkpoints':[claims[0],claims[1],conflict,claims[2]]};source=root/'bundle.json';source.write_text(json.dumps(bundle));before=source.read_bytes();base=[sys.executable,'-m','wireledger','select-bundle',str(source),'--public-key',str(key),'--count','3','--count','2'];expected={**bundle,'checkpoints':[claims[1],conflict,claims[2]]}
r=subprocess.run(base,capture_output=True,text=True);assert r.returncode==2,r.stderr;assert json.loads(r.stdout)==expected;h=subprocess.run(base+['--html'],capture_output=True,text=True);assert h.returncode==2,h.stderr;assert json.loads(re.search(r'<script id="report-data" type="application/json">(.*?)</script>',h.stdout,re.S).group(1))==expected;assert source.read_bytes()==before;(root/'selected.html').write_text(h.stdout);(root/'expected.json').write_text(json.dumps(expected));assert not(root/'recipient').exists()
for counts in [['--count','9'],['--count','2','--count','2'],['--count','-1']]:
 r=subprocess.run(base[:7]+counts,capture_output=True);assert r.returncode==1 and not r.stdout
bad={**bundle,'checkpoints':[{**claims[0],'signature':'invalid'},*bundle['checkpoints'][1:]]};source.write_text(json.dumps(bad));r=subprocess.run(base+['--html'],capture_output=True);assert r.returncode==1 and not r.stdout;source.write_bytes(before)
wrong=root/'wrong';initialize(wrong);r=subprocess.run([*base[:6],str(wrong/'witness.pub'),*base[7:]],capture_output=True);assert r.returncode==1 and not r.stdout;shutil.rmtree(wrong)
