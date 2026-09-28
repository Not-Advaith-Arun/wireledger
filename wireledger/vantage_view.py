"""Content-minimized latest-label comparisons under one supplied witness key."""
from .report_cards import render_report


def render_vantages(report):
    rows=[];results=[]
    for endpoint in report['results']:
        name=endpoint['host']+':'+str(endpoint['port'])
        safe_views={label:{'sequence':view['sequence'],'status':view['observation']['status']} for label,view in endpoint['views'].items()}
        results.append({**{key:value for key,value in endpoint.items() if key!='views'},'views':safe_views})
        rows.append({'group':'Coverage','cells':[name,', '.join(safe_views),endpoint['coverage'],f"{len(endpoint['comparisons'])} compared; {endpoint['omitted_pairs']} omitted",'Not an independent-witness claim']})
        for pair in endpoint['comparisons']:
            rows.append({'group':'Different fields' if pair['differences'] else 'No compared difference','cells':[name,pair['left_vantage']+' / '+pair['right_vantage'],', '.join(pair['differences']) or 'None in compared fields',pair['observer_time_separation_seconds'] if pair['observer_time_separation_seconds'] is not None else 'Unknown observer time','Latest signed sequence per label']})
    scope=report['scope']+f" Pair budget: {report['maximum_pairs']}; comparisons complete: {report['comparisons_complete']}. Omitted pairs remain unknown. Observation bodies, error details and certificate bodies are excluded from this page and its JSON download."
    payload={**report,'results':results,'scope':scope}
    return render_report('Wireledger recorded vantage comparison',scope,['Endpoint','Recorded labels','Comparison / coverage','Timing / budget','Interpretation boundary'],rows,payload=payload)
