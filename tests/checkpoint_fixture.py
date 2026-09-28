"""Real signatures, retained checkpoints, rollback and incorrect trust in CLI HTML."""
from pathlib import Path
import sys,json,subprocess,re
from wireledger.ledger import initialize,load_private,append,make_checkpoint,verify,load_public
from wireledger.retention import retain_checkpoint
root=Path(sys.argv[1]);store=root/'checkpoint-witness';initialize(store);key=load_private(store/'witness.key');public=load_public(store/'witness.pub');ledger=store/'observations.jsonl';retained=root/'retained'
for i in range(2):
    append(ledger,key,{'host':'offline.test','port':443,'vantage':'demo','status':'error','error':'private detail'})
    cp=make_checkpoint(verify(ledger,public),key);retain_checkpoint(retained,cp,public)
cpfile=root/'checkpoint.json';cpfile.write_text(json.dumps(cp));original=ledger.read_bytes();claims={p.name:p.read_bytes() for p in retained.glob('anchor-*')}
cmds=[['inspect-checkpoint',str(cpfile)],['list-retained','--store',str(retained)],['check-retained',str(ledger),'--store',str(retained)]]
for i,args in enumerate(cmds):
    base=[sys.executable,'-m','wireledger',*args,'--public-key',str(store/'witness.pub')];expected=json.loads(subprocess.check_output(base));r=subprocess.run(base+['--html'],capture_output=True,text=True);assert r.returncode==0,r.stderr
    html=r.stdout;assert json.loads(re.search(r'<script id="report-data" type="application/json">(.*?)</script>',html,re.S).group(1))==expected;assert 'private detail' not in html and 'PRIVATE KEY' not in html;(root/f'checkpoint-{i}.html').write_text(html)
assert ledger.read_bytes()==original and {p.name:p.read_bytes() for p in retained.glob('anchor-*')}==claims
ledger.write_bytes(original.splitlines(keepends=True)[0]);r=subprocess.run(base+['--html'],capture_output=True,text=True);assert r.returncode==2 and 'shorter-than-retained' in r.stdout;(root/'checkpoint-rollback.html').write_text(r.stdout)
other=root/'other-key';initialize(other);r=subprocess.run([*base[:-1],str(other/'witness.pub'),'--html'],capture_output=True,text=True);assert r.returncode==1 and not r.stdout
