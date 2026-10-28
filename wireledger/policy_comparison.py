"""Collection intent differences, independent of observed network evidence."""
from .inventory import expected_endpoints
from .report_cards import render_report


def compare_policies(left,right):
    a=expected_endpoints(left);b=expected_endpoints(right)
    return {'format':'wireledger-policy-comparison-v1','left_endpoints':len(a),'right_endpoints':len(b),
            'shared_endpoints':len(a&b),'added_endpoints':len(b-a),'removed_endpoints':len(a-b),
            'endpoints':[{'host':host,'port':port,'vantage':vantage,'membership':'both'if(host,port,vantage)in a and(host,port,vantage)in b else'left_only'if(host,port,vantage)in a else'right_only'}for host,port,vantage in sorted(a|b)],
            'scope':'Explicit unsigned endpoint/vantage intent only, normalized with the native collection policy validator (IDNA/lowercase/trailing-dot host normalization; exact port/vantage). Endpoint and vantage labels may be private. Membership is not network availability, trust, freshness, observation or coverage evidence. No history, witness, key, CA-file, DNS/TCP/TLS, import, append or collection occurred. Input order is not collection order; separately preview a reviewed policy before any explicit collection. The native16-endpoint collection cap remains independent of policy inventory/comparison.'}


def render_policy_comparison(report):
    rows=[{'group':row['membership'],'cells':[row['host'],row['port'],row['vantage']]}for row in report['endpoints']]
    return render_report('Wireledger collection policy comparison',report['scope'],['Normalized host','Port','Declared vantage'],rows,payload=report,
        summary=f"Unsigned intent comparison: {report['shared_endpoints']} shared, {report['added_endpoints']} added, {report['removed_endpoints']} removed normalized endpoint/vantage groups. No network contact, signing or coverage assertion.")


def combine_policies(left,right):
    groups=expected_endpoints(left)|expected_endpoints(right)
    if len(groups)>1000:raise ValueError('combined policy exceeds1000 distinct endpoint/vantage groups')
    return [{'host':host,'port':port,'vantage':vantage}for host,port,vantage in sorted(groups)]


def render_combined_policy(policy):
    rows=[{'group':'Unsigned intent','cells':[row['host'],row['port'],row['vantage']]}for row in policy]
    return render_report('Wireledger combined collection policy',
        'Both complete unsigned policies validated before normalization and union. Identical normalized endpoint/vantage rows coalesced across inputs only; duplicates within either input refuse. Native JSON download is an unsigned policy, not signed observations or evidence of coverage, availability, trust or freshness. No witness, keys, history or network accessed. At most1000 inventory groups; actual collection still requires at most16 endpoints and separate explicit observe-policy preview/collection. Host and vantage labels may be private.',
        ['Normalized host','Port','Declared vantage'],rows,payload=policy,
        summary=f"{len(rows)} distinct endpoint/vantage groups. Download the native policy for separate review; no collection or history changes occurred.")


def select_policy(policy,selections):
    available=expected_endpoints(policy);selected=expected_endpoints(selections)
    if len(selected)>16:raise ValueError('select at most16 explicit endpoint/vantage groups')
    if not selected<=available:raise ValueError('every selected normalized endpoint/vantage must exist in the supplied policy')
    return [{'host':host,'port':port,'vantage':vantage}for host,port,vantage in sorted(selected)]


def render_policy_selection(policy,input_count):
    rows=[{'group':'Chosen unsigned intent','cells':[row['host'],row['port'],row['vantage']]}for row in policy]
    return render_report('Wireledger chosen collection policy',
        'Entire unsigned input and explicit chosen host/port/vantage rows validated before selection. Native normalization applied to both; unknown or duplicate chosen groups refuse. Download is a native policy of at most16 groups for separate observe-policy preview. Omitted groups are not assessed, observed or deleted. No witness, keys, history, DNS/TCP/TLS, signing or collection occurred. Endpoint labels may be private; membership is not trust, availability, freshness or coverage evidence.',
        ['Normalized host','Port','Declared vantage'],rows,payload=policy,
        summary=f"{len(policy)} explicit groups chosen from {input_count}; {input_count-len(policy)} omitted. Download the unsigned policy for separate native preview; no network contact or collection.")
