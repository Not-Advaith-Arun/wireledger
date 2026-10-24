"""Authenticated collection inventory presentation; never an availability verdict."""
from .report_cards import render_report


def render_inventory(report):
    rows=[]
    for row in report['results']:
        latest=row['latest'];rows.append({'group':latest['status'],'cells':[
            row['host']+':'+str(row['port']),row['vantage'],latest['status'],row['records'],latest['sequence'],row['consecutive_failures'],row['last_verified_sequence']]})
    scope=report['scope']+' This is an exported inventory snapshot, not a live monitor. Omitted endpoint groups are not proven healthy or absent.'
    return render_report('Wireledger endpoint inventory',scope,['Endpoint','Vantage','Latest recorded status','Signed samples','Latest sequence','Consecutive failures','Last verified sequence'],rows,payload=report)
