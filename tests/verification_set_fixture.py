from pathlib import Path
from copy import deepcopy
from unittest.mock import patch
import json,subprocess,sys
from wireledger.lab import certificates,tls_server
from wireledger.verification_set import verify_set
root=Path(sys.argv[1]);manifest=root/'views.json'
def cli(*args):return subprocess.run([sys.executable,'-m','wireledger',*map(str,args)],capture_output=True,text=True)
ca,variants=certificates(root);cert,key=variants[0]
with tls_server(cert,key)as port:
 for name in ['w1','w2']:
  store=root/name;assert cli('init',store).returncode==0;assert cli('observe',store,'localhost','--port',port,'--vantage',name,'--connect-ip','127.0.0.1','--ca-file',ca).returncode==0;assert cli('checkpoint',store,root/(name+'.pin')).returncode==0
value={'format':'wireledger-history-view-set/v1','views':[{'id':n,'history':n+'/observations.jsonl','public_key':n+'/witness.pub','checkpoint':n+'.pin'}for n in ['w1','w2']]};manifest.write_text(json.dumps(value));r=cli('verify-set',manifest);assert r.returncode==0,r.stderr;good=json.loads(r.stdout);assert good['all_verified']and good['verified_views']==2 and good['distinct_verified_public_keys']==2 and all(v['records']==1 for v in good['views']);assert 'BEGIN CERTIFICATE'not in r.stdout and str(root)not in r.stdout
second=root/'w2/observations.jsonl';before=second.read_bytes();second.write_bytes(before.replace(b'localhost',b'tamper.bad'));r=cli('verify-set',manifest);assert r.returncode==2,r.stderr;bad=json.loads(r.stdout);assert bad['verified_views']==1 and bad['views'][0]['records']==1 and bad['views'][1]['records']is None and not bad['all_verified'];(root/'expected.json').write_text(r.stdout);h=cli('verify-set',manifest,'--html');assert h.returncode==2,h.stderr;(root/'verification.html').write_text(h.stdout);second.write_bytes(before)
missing=deepcopy(value);missing['views'][1]['public_key']='missing.pub';result=verify_set(missing,root);assert result['views'][1]['status']=='unverified_history_key_or_pin'and result['views'][1]['records']is None
invalid=deepcopy(value);invalid['views'][1]['unknown']='bad'
with patch('wireledger.verification_set.load_public',side_effect=AssertionError('must validate all manifest rows first')):
 try:verify_set(invalid,root);raise AssertionError('invalid late manifest accepted')
 except ValueError:pass
code="from unittest.mock import patch;from wireledger.__main__ import main\nwith patch('socket.getaddrinfo',side_effect=RuntimeError('DNS forbidden')),patch('wireledger.__main__.load_private',side_effect=RuntimeError('key forbidden')):raise SystemExit(main("+repr(['verify-set',str(manifest)])+"))";assert subprocess.run([sys.executable,'-c',code],capture_output=True).returncode==0;assert second.read_bytes()==before
