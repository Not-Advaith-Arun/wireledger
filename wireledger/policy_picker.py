"""Choose unsigned collection intent only; no witness/key/network dependencies."""
from pathlib import Path
from .inventory import expected_endpoints
from .report_cards import render_report


def policy_choices(value):
    policy=[{'host':host,'port':port,'vantage':vantage}for host,port,vantage in sorted(expected_endpoints(value))]
    return {'format':'wireledger-policy-picker/v1','policy':policy,
        'scope':'Complete supplied unsigned policy validated before normalized choices are shown, including all omitted groups. Choose1..16 endpoint/port/vantage groups explicitly; filters do not choose rows and reload clears choices. Download is an unsigned native policy for separate observe-policy --preview, not signed observations or evidence of availability, trust, freshness or coverage. No witness, key, CA, history, DNS/TCP/TLS or collection accessed here. Endpoint/vantage labels are private input; protect exported policies.'}


def render_policy_choices(report):
    rows=[{'group':'Available unsigned intent','cells':[r['host'],r['port'],r['vantage']]}for r in report['policy']]
    return render_report('Wireledger choose collection policy',report['scope'],['Normalized host','Port','Declared vantage'],rows,payload=report,summary=f"{len(rows)} normalized groups available; choose at most16 for separate native preview. No endpoints contacted.",extra_script=Path(__file__).with_name('ui').joinpath('policy_picker.js').read_text())
