"""Signed vantage labels are compared with bounded, content-minimized exports."""
from pathlib import Path
import sys,json,subprocess,re
from wireledger.ledger import initialize,load_private,append
root=Path(sys.argv[1]);store=root/'vantage-witness';initialize(store);key=load_private(store/'witness.key');ledger=store/'observations.jsonl'
for label in ['a','b','c']:append(ledger,key,{'host':'offline.test','port':443,'vantage':label,'status':'error','error':'private details '+label})
append(ledger,key,{'host':'single.test','port':443,'vantage':'only','status':'error','error':'private details only'})
before=ledger.read_bytes();base=[sys.executable,'-m','wireledger','vantages',str(ledger),'--public-key',str(store/'witness.pub')]
for i,extra in enumerate([[],['--max-pairs','1']]):
    r=subprocess.run(base+extra+['--html'],capture_output=True,text=True);assert r.returncode==(0 if i==0 else 2),r.stderr
    payload=json.loads(re.search(r'<script id="report-data" type="application/json">(.*?)</script>',r.stdout,re.S).group(1));assert payload['comparisons_complete']==(i==0);assert 'private details' not in r.stdout;assert all('observation' not in view for row in payload['results'] for view in row['views'].values());assert payload['results'][1]['coverage']=='one-view-only'
    (root/f'vantages-{i}.html').write_text(r.stdout)
assert ledger.read_bytes()==before
