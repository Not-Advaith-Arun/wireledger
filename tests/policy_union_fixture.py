"""Native normalized unsigned policy diff has no witness/history/network dependency."""
from pathlib import Path
import sys,json,subprocess,re
root=Path(sys.argv[1]);a=root/'left.json';b=root/'right.json';left=[{'host':'BÜCHER.example.','port':443,'vantage':'local'},{'host':'removed.example','port':8443,'vantage':'remote'}];right=[{'host':'xn--bcher-kva.example','port':443,'vantage':'local'},{'host':'added.example','port':443,'vantage':'local'}];a.write_text(json.dumps(left));b.write_text(json.dumps(right));before=[a.read_bytes(),b.read_bytes()];base=[sys.executable,'-m','wireledger','combine-policies',str(a),str(b)];r=subprocess.run(base,capture_output=True,text=True);assert r.returncode==0,r.stderr;data=json.loads(r.stdout);assert len(data)==3;assert any(row['host']=='xn--bcher-kva.example'for row in data);h=subprocess.run(base+['--html'],capture_output=True,text=True);assert h.returncode==0,h.stderr;assert json.loads(re.search(r'<script id="report-data" type="application/json">(.*?)</script>',h.stdout,re.S).group(1))==data;(root/'comparison.html').write_text(h.stdout);(root/'expected.json').write_text(json.dumps(data));assert[a.read_bytes(),b.read_bytes()]==before
code="from unittest.mock import patch;from wireledger.__main__ import main\nwith patch('wireledger.__main__.load_private',side_effect=RuntimeError('private key forbidden')),patch('socket.getaddrinfo',side_effect=RuntimeError('DNS forbidden')),patch('wireledger.__main__.verify',side_effect=RuntimeError('history forbidden')):raise SystemExit(main("+repr(base[3:])+"))";r=subprocess.run([sys.executable,'-c',code],capture_output=True);assert r.returncode==0
for bad in [[right[0],{**right[0],'host':'BÜCHER.example.'}],[{**right[0],'port':True}],[{**right[0],'vantage':''}]]:
 b.write_text(json.dumps(bad));r=subprocess.run(base+['--html'],capture_output=True);assert r.returncode==1 and not r.stdout
b.write_bytes(before[1])

from wireledger.policy_comparison import combine_policies
many=[{'host':f'host-{i}.example','port':443,'vantage':'local'}for i in range(1000)]
try:combine_policies(many,[{'host':'extra.example','port':443,'vantage':'local'}]);raise AssertionError('union cap')
except ValueError:pass
from wireledger.ledger import initialize
from wireledger.collection import preview_policy
initialize(root/'witness');preview=preview_policy(root/'witness',data);assert preview['selected_endpoints']==3
