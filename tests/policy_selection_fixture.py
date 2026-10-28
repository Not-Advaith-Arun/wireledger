"""Explicit normalized subset to native collection preview; full input still validates."""
from pathlib import Path
import sys,json,subprocess
from wireledger.ledger import initialize
from wireledger.collection import preview_policy
root=Path(sys.argv[1]);file=root/'policy.json';rows=[{'host':'BÜCHER.example.','port':443,'vantage':'local'},{'host':'other.example','port':443,'vantage':'local'},{'host':'xn--bcher-kva.example','port':443,'vantage':'remote'}];file.write_text(json.dumps(rows));before=file.read_bytes();base=['select-policy',str(file),'--endpoint','xn--bcher-kva.example','443','local']
def cli(args):return subprocess.run([sys.executable,'-m','wireledger',*args],text=True,capture_output=True)
r=cli(base);assert r.returncode==0,r.stderr;selected=json.loads(r.stdout);assert selected==[{'host':'xn--bcher-kva.example','port':443,'vantage':'local'}];h=cli(base+['--html']);assert h.returncode==0;(root/'comparison.html').write_text(h.stdout);(root/'expected.json').write_text(json.dumps(selected));initialize(root/'witness');assert preview_policy(root/'witness',selected)['selected_endpoints']==1
for extra in [['--endpoint','BÜCHER.example.','443','local'],['--endpoint','unknown.example','443','local']]:
 r=cli(base+extra);assert r.returncode==1 and not r.stdout
bad=[*rows,{'host':'bad.example','port':True,'vantage':'local'}];file.write_text(json.dumps(bad));assert cli(base).returncode==1;file.write_bytes(before);assert file.read_bytes()==before
code="from unittest.mock import patch;from wireledger.__main__ import main\nwith patch('socket.getaddrinfo',side_effect=RuntimeError('DNS forbidden')),patch('wireledger.__main__.load_private',side_effect=RuntimeError('key forbidden')):raise SystemExit(main("+repr(base)+"))";assert subprocess.run([sys.executable,'-c',code],capture_output=True).returncode==0
