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
