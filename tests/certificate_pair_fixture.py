"""Real loopback renewal/key rotation and complete selected-chain refusal."""
from pathlib import Path
import sys,json,subprocess,copy
from wireledger.lab import certificates,tls_server
from wireledger.ledger import initialize,load_private,append
root=Path(sys.argv[1]);store=root/'w';initialize(store);ca,variants=certificates(root);port=0
def cli(*args):return subprocess.run([sys.executable,'-m','wireledger',*map(str,args)],text=True,capture_output=True)
for cert,key in variants:
 with tls_server(cert,key,port=port)as assigned:
  port=assigned;r=cli('observe',store,'localhost','--port',port,'--connect-ip','127.0.0.1','--ca-file',ca);assert r.returncode==0,r.stderr
ledger=store/'observations.jsonl';public=store/'witness.pub';before=ledger.read_bytes();base=['compare-certificates',ledger,'--public-key',public,'--left-sequence','1','--right-sequence','3'];r=cli(*base);assert r.returncode==0,r.stderr;data=json.loads(r.stdout);assert data['comparison']=='different_captured_key'and data['same_endpoint']and data['same_vantage'];h=cli(*base,'--html');assert h.returncode==0,h.stderr;assert'PRIVATE KEY'not in h.stdout and'BEGIN CERTIFICATE'not in h.stdout;(root/'pair.html').write_text(h.stdout);(root/'expected.json').write_text(json.dumps(data));r=cli('compare-certificates',ledger,'--public-key',public,'--left-sequence','1','--right-sequence','2');assert json.loads(r.stdout)['comparison']=='different_certificate_same_key';assert ledger.read_bytes()==before
assert cli(*base,'--left-sequence','0').returncode==1
observation=copy.deepcopy(json.loads(before.splitlines()[0])['body']['observation']);field=next(k for k,v in observation['evidence'].items()if isinstance(v,list));observation['evidence'][field].append('bm90LWRlcg==');append(ledger,load_private(store/'witness.key'),observation);r=cli(*base,'--right-sequence','4');assert r.returncode==1 and not r.stdout;ledger.write_bytes(before.replace(b'localhost',b'tampered'));r=cli(*base);assert r.returncode==1 and not r.stdout;ledger.write_bytes(before)
