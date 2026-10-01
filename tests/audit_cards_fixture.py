"""Real local TLS evidence is independently audited after network/signing resources are gone."""
from pathlib import Path
import sys,json,subprocess,re
from wireledger.lab import certificates,tls_server
from wireledger.ledger import initialize,load_private,append
from wireledger.probe import observe
from wireledger.audit_view import audit_metadata
root=Path(sys.argv[1]);ca,pairs=certificates(root);wrong=root/'wrong';wrong.mkdir();other_ca,_=certificates(wrong);w=root/'w';initialize(w);key=load_private(w/'witness.key');ledger=w/'observations.jsonl'
with tls_server(*pairs[0])as port:observation=observe('localhost',port,connect_ip='127.0.0.1',cafile=str(ca),vantage='fictional-loopback')
assert observation['status']=='verified';append(ledger,key,observation)
for p in root.rglob('*.key'):p.unlink()
before=ledger.read_bytes();base=[sys.executable,'-m','wireledger','audit',str(ledger),'--public-key',str(w/'witness.pub')]
for name,trust,extra,code in [('current',ca,[],0),('observed',ca,['--at-observed-time'],0),('wrong-trust',other_ca,[],2)]:
 args=base+['--ca-file',str(trust),*extra];r=subprocess.run(args,capture_output=True,text=True);assert r.returncode==code,r.stderr;report=json.loads(r.stdout);assert report['ok']==(code==0);h=subprocess.run(args+['--html'],capture_output=True,text=True);assert h.returncode==code,h.stderr;expected=audit_metadata(report);actual=json.loads(re.search(r'<script id="report-data" type="application/json">(.*?)</script>',h.stdout,re.S).group(1));# Current verification time is independently sampled per invocation.
 for row in expected['results']:row.pop('verification_time',None)
 comparable=json.loads(json.dumps(actual))
 for row in comparable['results']:row.pop('verification_time',None)
 assert comparable==expected and 'BEGIN CERTIFICATE'not in h.stdout and 'PRIVATE KEY'not in h.stdout and 'detail'not in json.dumps(actual['results']);(root/(name+'.html')).write_text(h.stdout);(root/(name+'.json')).write_text(json.dumps(actual));assert ledger.read_bytes()==before
# Legacy and failed observations retain honest nonpassing states without diagnostics.
legacy=root/'legacy.jsonl';legacy.touch();append(legacy,key,{'host':'legacy.test','port':443,'status':'verified'});append(legacy,key,{'host':'failed.test','port':443,'status':'error','error':'PRIVATE_DIAGNOSTIC'});r=subprocess.run([sys.executable,'-m','wireledger','audit',str(legacy),'--public-key',str(w/'witness.pub'),'--ca-file',str(ca),'--html'],capture_output=True,text=True);assert r.returncode==2 and 'PRIVATE_DIAGNOSTIC'not in r.stdout;data=json.loads(re.search(r'<script id="report-data" type="application/json">(.*?)</script>',r.stdout,re.S).group(1));assert [row['status']for row in data['results']]==['evidence-missing','no-successful-handshake']
