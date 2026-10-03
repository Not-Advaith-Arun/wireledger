from pathlib import Path
import sys,json,subprocess
root=Path(sys.argv[1]);file=root/'policy.json'
def cli(*args):return subprocess.run([sys.executable,'-m','wireledger',*map(str,args)],capture_output=True,text=True)
if len(sys.argv)==2:
 rows=[{'host':'BÜCHER.example.','port':443,'vantage':'local'},{'host':'other.example','port':8443,'vantage':'remote'}]+[{'host':'host'+str(i)+'.example','port':443,'vantage':'local'}for i in range(16)];file.write_text(json.dumps(rows));h=cli('policy-picker',file);assert h.returncode==0,h.stderr;(root/'picker.html').write_text(h.stdout);(root/'before').write_bytes(file.read_bytes());bad=rows+[{'host':'bad.example','port':True,'vantage':'local'}];file.write_text(json.dumps(bad));r=cli('policy-picker',file);assert r.returncode==1 and not r.stdout;file.write_bytes((root/'before').read_bytes());code="from unittest.mock import patch;from wireledger.__main__ import main\nwith patch('socket.getaddrinfo',side_effect=RuntimeError('DNS forbidden')),patch('wireledger.__main__.load_private',side_effect=RuntimeError('key forbidden')),patch('wireledger.__main__.verify',side_effect=RuntimeError('history forbidden')):raise SystemExit(main("+repr(['policy-picker',str(file)])+"))";assert subprocess.run([sys.executable,'-c',code],capture_output=True).returncode==0
else:
 selected=json.loads((root/'out.json').read_text());assert selected==[{'host':'other.example','port':8443,'vantage':'remote'},{'host':'xn--bcher-kva.example','port':443,'vantage':'local'}];from wireledger.ledger import initialize
 initialize(root/'witness');r=cli('observe-policy',root/'witness','--expected',root/'out.json','--preview');assert r.returncode==0,r.stderr;assert json.loads(r.stdout)['selected_endpoints']==2;assert file.read_bytes()==(root/'before').read_bytes()
