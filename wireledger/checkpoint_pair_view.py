"""Detached claim pairs; authentication does not prove history ancestry or freshness."""
from .report_cards import render_report


def render_pair(report):
    rows=[{'group':side,'cells':[side,report[side]['witness'],report[side]['count'],report[side]['head']]}for side in ('left','right')]
    return render_report('Wireledger signed checkpoint pair',report['scope']+' Each signature was checked against its separately supplied key. Independently trust those identities. No histories, storage custody, rollback detection, live sampling or observer truth checked. Browser filtering never changes the checked relation.',
        ['Selected side','Signed witness identity','Signed record count','Claimed head'],rows,payload=report,
        summary=('Conflicting signed heads. 'if report['relation']=='conflicting-heads'else'Checked relation: '+report['relation']+'. ')+'Detached signed claims only. Different counts do not prove ancestry; matching claims do not establish freshness or observer truth.')
