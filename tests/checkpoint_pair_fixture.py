"""Actual detached signed pairs retain all four relation classes without history reads."""
from pathlib import Path
import sys,json,subprocess,re
from wireledger.ledger import initialize,load_private,load_public,append,verify,make_checkpoint
root=Path(sys.argv[1]);w=root/'w';initialize(w);private=load_private(w/'witness.key');public=load_public(w/'witness.pub');ledger=w/'observations.jsonl'
append(ledger,private,{'host':'fictional.test','status':'error','error':'PRIVATE_DIAGNOSTIC'});one=make_checkpoint(verify(ledger,public),private);append(ledger,private,{'host':'later.test','status':'error'});two=make_checkpoint(verify(ledger,public),private)
fork=root/'fork.jsonl';fork.touch()
for i in range(2):append(fork,private,{'host':'different.test','status':'error','n':i})
conflict=make_checkpoint(verify(fork,public),private);foreign=root/'foreign';initialize(foreign);foreign_key=load_private(foreign/'witness.key');other=make_checkpoint([],foreign_key)
for name,left,right,right_key,relation in [('same',one,one,w/'witness.pub','identical'),('different',one,two,w/'witness.pub','ancestry-unproven'),('conflict',two,conflict,w/'witness.pub','conflicting-heads'),('independent',one,other,foreign/'witness.pub','independent-witnesses')]:
 l=root/(name+'-left.json');r=root/(name+'-right.json');l.write_text(json.dumps(left));r.write_text(json.dumps(right));original=[l.read_bytes(),r.read_bytes()];base=[sys.executable,'-m','wireledger','compare-checkpoints',str(l),str(r),'--left-key',str(w/'witness.pub'),'--right-key',str(right_key)];native=subprocess.run(base,capture_output=True,text=True);data=json.loads(native.stdout);assert data['relation']==relation;html=subprocess.run(base+['--html'],capture_output=True,text=True);assert html.returncode==native.returncode==(2 if name=='conflict'else 0);assert json.loads(re.search(r'<script id="report-data" type="application/json">(.*?)</script>',html.stdout,re.S).group(1))==data;assert 'PRIVATE_DIAGNOSTIC'not in html.stdout and 'PRIVATE KEY'not in html.stdout;(root/(name+'.html')).write_text(html.stdout);(root/(name+'.json')).write_text(json.dumps(data));assert [l.read_bytes(),r.read_bytes()]==original
bad=subprocess.run([*base,'--right-key',str(w/'witness.pub'),'--html'],capture_output=True,text=True);assert bad.returncode==1 and not bad.stdout
