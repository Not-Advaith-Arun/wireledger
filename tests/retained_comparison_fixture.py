"""Two disposable authenticated claim sets, including divergence and invalid trust."""
from pathlib import Path
import sys,subprocess,json,re
from wireledger.ledger import initialize,load_private,load_public,append,make_checkpoint,verify
from wireledger.retention import retain_checkpoint
root=Path(sys.argv[1]);w=root/'witness';initialize(w);private=load_private(w/'witness.key');public=load_public(w/'witness.pub');ledger=w/'observations.jsonl';left=root/'left';right=root/'right'
append(ledger,private,{'host':'fictional.test','status':'error','error':'PRIVATE_DIAGNOSTIC'});cp=make_checkpoint(verify(ledger,public),private)
for store in [left,right]:retain_checkpoint(store,cp,public)
def report(name):
 before={p:p.read_bytes()for store in [left,right]for p in store.iterdir()};base=[sys.executable,'-m','wireledger','compare-retained',str(left),str(right),'--public-key',str(w/'witness.pub')];native=subprocess.run(base,text=True,capture_output=True);data=json.loads(native.stdout);html=subprocess.run(base+['--html'],text=True,capture_output=True);assert html.returncode==native.returncode==(2 if data['needs_attention']else 0);assert json.loads(re.search(r'<script id="report-data" type="application/json">(.*?)</script>',html.stdout,re.S).group(1))==data;assert 'PRIVATE_DIAGNOSTIC' not in html.stdout and 'PRIVATE KEY' not in html.stdout;assert all(p.read_bytes()==v for p,v in before.items());(root/(name+'.html')).write_text(html.stdout);(root/(name+'.json')).write_text(json.dumps(data))
report('same');append(ledger,private,{'host':'second.test','status':'error'});retain_checkpoint(left,make_checkpoint(verify(ledger,public),private),public);report('different')
fork=root/'fork.jsonl';fork.touch(mode=0o600)
for i in range(2):append(fork,private,{'host':'fork.test','status':'error','index':i})
retain_checkpoint(right,make_checkpoint(verify(fork,public),private),public);report('conflict')
other=root/'other';initialize(other);base=[sys.executable,'-m','wireledger','compare-retained',str(left),str(right),'--public-key',str(other/'witness.pub'),'--html'];bad=subprocess.run(base,text=True,capture_output=True);assert bad.returncode==1 and not bad.stdout
anchor=next(left.glob('anchor-*'));value=json.loads(anchor.read_text());value['signature']='bad';anchor.write_text(json.dumps(value));bad=subprocess.run([*base[:-2],str(w/'witness.pub'),'--html'],text=True,capture_output=True);assert bad.returncode==1 and not bad.stdout
