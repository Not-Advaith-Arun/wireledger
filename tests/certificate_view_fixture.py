"""Real signed-history CLI reports with honest unavailable, empty and tamper paths."""
from pathlib import Path
import sys,json,subprocess,re
from wireledger.ledger import initialize,load_private,append
root=Path(sys.argv[1]);store=root/'cert-store';initialize(store);key=load_private(store/'witness.key');ledger=store/'observations.jsonl'
for host,sha,end in [('near-a.test','a','2024-01-02T00:00:00Z'),('near-b.test','a','2024-01-02T00:00:00Z'),('healthy.test','c','2025-01-01T00:00:00Z')]:
 append(ledger,key,{'host':host,'port':443,'vantage':'local','status':'verified','certificate_sha256':sha*64,'spki_sha256':sha*64,'observed_at':'2024-01-01T00:00:00Z','not_before':'2023-01-01T00:00:00Z','not_after':end})
append(ledger,key,{'host':'failed.test','port':443,'vantage':'local','status':'error','error':'PRIVATE_DIAGNOSTIC','observed_at':'2024-01-01T00:00:00Z'})
def report(name,command,extra,source=ledger):
 before=source.read_bytes();base=[sys.executable,'-m','wireledger',command,str(source),'--public-key',str(store/'witness.pub'),*extra];native=subprocess.run(base,text=True,capture_output=True);data=json.loads(native.stdout);html=subprocess.run(base+['--html'],text=True,capture_output=True);assert html.returncode==native.returncode;assert json.loads(re.search(r'<script id="report-data" type="application/json">(.*?)</script>',html.stdout,re.S).group(1))==data;assert 'PRIVATE_DIAGNOSTIC' not in html.stdout and 'PRIVATE KEY' not in html.stdout and 'BEGIN CERTIFICATE' not in html.stdout;assert source.read_bytes()==before;(root/(name+'.html')).write_text(html.stdout);(root/(name+'.json')).write_text(json.dumps(data))
report('expiry','expiry',['--as-of','2024-01-01T00:00:00Z']);report('attention','expiry',['--as-of','2024-01-01T00:00:00Z','--attention-only']);report('reuse','fingerprint-reuse',[])
append(ledger,key,{'host':'near-b.test','port':443,'vantage':'local','status':'error','error':'PRIVATE_DIAGNOSTIC'})
report('superseded','fingerprint-reuse',[]);assert not json.loads((root/'superseded.json').read_text())['shared']['certificate_sha256']
empty=root/'empty.jsonl';empty.write_bytes(b'');report('empty','expiry',['--as-of','2024-01-01T00:00:00Z'],empty)
ledger.write_bytes(ledger.read_bytes().replace(b'near-a.test',b'tampered.test'));bad=subprocess.run([sys.executable,'-m','wireledger','expiry',str(ledger),'--public-key',str(store/'witness.pub'),'--as-of','2024-01-01T00:00:00Z','--html'],text=True,capture_output=True);assert bad.returncode==1 and not bad.stdout
