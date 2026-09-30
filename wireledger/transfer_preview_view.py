"""Authenticated transfer proposal counts without claim publication."""
from .report_cards import render_report


def render_transfer(report):
    if not report['preview']or report['retained']:raise ValueError('transfer cards require an unapplied preview')
    rows=[{'group':'Checked incoming bundle','cells':[report['imported_claims'],report['added_claims'],report['already_retained_claims'],report['total_claims'],report['conflicting_heads']]}]
    return render_report('Wireledger checkpoint import preview',report['scope']+f" Supplied witness identity {report['witness']}. No private keys, observation text or destination paths included. The browser cannot import these claims.",
        ['Incoming claims','New claims proposed','Already retained','Proposed total claims','Conflicting signed heads'],rows,payload=report,
        summary=('Conflicting signed heads need attention. 'if report['conflicting_heads']else'Checked signatures and proposed counts only. ')+'Preview: no claims published or destination created; no ancestry, independent custody, freshness or observer-truth proof. A later explicit import revalidates everything.')
