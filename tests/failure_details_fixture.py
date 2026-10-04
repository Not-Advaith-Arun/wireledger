from pathlib import Path
import json,sys,subprocess
from wireledger.lab import certificates,tls_server
from wireledger.ledger import append,load_private
root=Path(sys.argv[1]);store=root/'w'
def cli(*args):return subprocess.run([sys.executable,'-m','wireledger',*map(str,args)],capture_output=True,text=True)
assert cli('init',store).returncode==0;ledger=store/'observations.jsonl';public=store/'witness.pub';private=load_private(store/'witness.key');ca,variants=certificates(root);cert,key=variants[0]
with tls_server(cert,key) as port:
 observe=['observe',store,'localhost','--port',port,'--vantage','local','--connect-ip','127.0.0.1','--ca-file',ca];assert cli(*observe).returncode==0
 for host,p,v,time in [('localhost',port,'local','2026-01-02T00:00:00+00:00'),('other.test',443,'other',None),('localhost',port,'local','2026-01-01T00:00:00+00:00')]:
  row={'host':host,'port':p,'vantage':v,'status':'error','error':'PRIVATE failure diagnostic'}
  if time is not None:row['observed_at']=time
  append(ledger,private,row)
 before=ledger.read_bytes();base=['failure-details',ledger,'--public-key',public,'--host','localhost','--port',port,'--vantage','local','--limit','1'];r=cli(*base);assert r.returncode==2,r.stderr;data=json.loads(r.stdout);assert data['current_streak_length']==2 and data['first_streak_sequence']==2 and data['last_verified_sequence']==1;assert data['omitted_older_streak_samples']==1 and data['samples']==[{'sequence':4,'status':'error','recorded_time':'2026-01-01T00:00:00+00:00'}];assert 'PRIVATE'not in r.stdout and 'BEGIN CERTIFICATE'not in r.stdout;(root/'expected.json').write_text(r.stdout);h=cli(*base,'--html');assert h.returncode==2,h.stderr;(root/'details.html').write_text(h.stdout)
 r=cli('failure-details',ledger,'--public-key',public,'--host','other.test','--port','443','--vantage','other');assert r.returncode==2 and json.loads(r.stdout)['no_verified_sample_in_group'];assert json.loads(r.stdout)['last_verified_sequence']is None
 for extra in [['--limit','0'],['--host','missing.test'],['--host','LOCALHOST']]:
  r=cli(*base,*extra);assert r.returncode==1 and not r.stdout
 ledger.write_bytes(before.replace(b'other.test',b'tamper.bad'));r=cli(*base);assert r.returncode==1 and not r.stdout;ledger.write_bytes(before)
 code="from unittest.mock import patch;from wireledger.__main__ import main\nwith patch('socket.getaddrinfo',side_effect=RuntimeError('DNS forbidden')),patch('wireledger.__main__.load_private',side_effect=RuntimeError('key forbidden')):raise SystemExit(main("+repr(list(map(str,base)))+"))";assert subprocess.run([sys.executable,'-c',code],capture_output=True).returncode==2;assert ledger.read_bytes()==before
 assert cli(*observe).returncode==0;recovered=ledger.read_bytes();r=cli(*base);assert r.returncode==0,r.stderr;data=json.loads(r.stdout);assert data['current_streak_length']==0 and data['last_verified_sequence']==5 and not data['samples'];assert ledger.read_bytes()==recovered
