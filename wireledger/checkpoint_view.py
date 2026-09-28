"""Present authenticated retained claims without overstating their guarantees."""
from .report_cards import render_report


def render_checkpoints(report):
    rows=[]
    if 'claim' in report:
        claims=[{'group':'History not checked', **report['claim']}]
    elif 'stores' in report:
        claims=[{'group':'Store '+str(store['store_index'])+' / '+row['relation'],**row}
                for store in report['stores'] for row in store['checkpoints']]
    elif 'ok' in report:
        claims=[{'group':row['relation'],**row} for row in report['checkpoints']]
    else:
        conflicting={row['count'] for row in report['conflicting_heads']}
        claims=[{'group':'Conflicting signed heads' if row['count'] in conflicting else 'History not checked',**row}
                for row in report['checkpoints']]
    for row in claims:
        rows.append({'group':row['group'],'cells':[row['count'],row['head'],row['group']]})
    status=('All selected claims match this authenticated history.' if report.get('ok') is True else
            'Attention: selected claims do not all match this history.' if report.get('ok') is False else
            'Signatures checked; history consistency was not checked.')
    return render_report('Wireledger retained checkpoint review',report['scope']+' '+status+' Independently trust the supplied key. No live sampling, freshness or observer-truth guarantee.',
                         ['Signed record count','Claimed head','Checked relation'],rows,payload=report)
