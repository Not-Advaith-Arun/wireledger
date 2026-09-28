"""Actual signed collection gaps retain attention exit status in HTML."""
from pathlib import Path
import sys,json,subprocess,re
from wireledger.ledger import initialize,load_private,append
root=Path(sys.argv[1]);store=root/'sampling-witness';initialize(store);key=load_private(store/'witness.key');ledger=store/'observations.jsonl'
for host,time in [('offline.test','2026-10-01T00:00:00+00:00'),('offline.test','2026-10-01T02:00:00+00:00'),('unexpected.test',None)]:
    append(ledger,key,{'host':host,'port':443,'vantage':'lab','status':'error','error':'private diagnostics',**({'observed_at':time} if time else {})})
policy=root/'expected-policy.json';policy.write_text(json.dumps([{'host':host,'port':443,'vantage':'lab'} for host in ['offline.test','missing.test']]))
before=ledger.read_bytes()
commands=[['coverage','--expected',str(policy),'--attention-only','--exact'],['continuity','--as-of','2026-10-01T03:00:00+00:00','--max-gap-seconds','3600']]
for i,args in enumerate(commands):
    base=[sys.executable,'-m','wireledger',args[0],str(ledger),'--public-key',str(store/'witness.pub'),*args[1:]]
    r=subprocess.run(base,capture_output=True,text=True);assert r.returncode==2,r.stderr;expected=json.loads(r.stdout);r=subprocess.run(base+['--html'],capture_output=True,text=True);assert r.returncode==2,r.stderr
    assert json.loads(re.search(r'<script id="report-data" type="application/json">(.*?)</script>',r.stdout,re.S).group(1))==expected;assert 'private diagnostics' not in r.stdout
    (root/f'sampling-{i}.html').write_text(r.stdout)
assert ledger.read_bytes()==before
ledger.write_bytes(before.replace(b'offline.test',b'changed.test'));r=subprocess.run(base+['--html'],capture_output=True,text=True);assert r.returncode==1 and not r.stdout
