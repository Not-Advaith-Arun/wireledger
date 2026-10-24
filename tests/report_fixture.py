"""CLI inventory authentication and output boundary, using disposable signing keys."""
from pathlib import Path
import sys,json,subprocess
from wireledger.ledger import initialize,load_private,append
root=Path(sys.argv[1]);store=root/'store';initialize(store);key=load_private(store/'witness.key');ledger=store/'observations.jsonl'
for host,vantage in [('offline.test','a'),('offline.test','a'),('other.test','b')]:append(ledger,key,{'host':host,'port':443,'vantage':vantage,'status':'error','error':'private diagnostic omitted'})
before=ledger.read_bytes();base=[sys.executable,'-m','wireledger','endpoints',str(ledger),'--public-key',str(store/'witness.pub')];expected=json.loads(subprocess.check_output(base));html=subprocess.check_output(base+['--html'],text=True);assert ledger.read_bytes()==before;assert 'private diagnostic omitted' not in html;assert 'PRIVATE KEY' not in html
(root/'report.html').write_text(html);(root/'expected.json').write_text(json.dumps({'title':'Wireledger endpoint inventory','rows':2,'group':'error','groupRows':2,'payload':expected}))
# Wrong output combination and modified signed bytes never become an HTML report.
r=subprocess.run(base+['--html','--policy'],capture_output=True,text=True);assert r.returncode==1 and not r.stdout
ledger.write_bytes(before.replace(b'offline.test',b'changed.test'));r=subprocess.run(base+['--html'],capture_output=True,text=True);assert r.returncode==1 and not r.stdout
