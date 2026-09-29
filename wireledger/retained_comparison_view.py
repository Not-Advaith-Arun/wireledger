"""Authenticated retained-set differences, not a history or custody proof."""
from .report_cards import render_report


def render_retained_comparison(report):
    conflicts={row['count']for row in report['conflicting_heads']}
    rows=[{'group':label,'cells':[row['count'],row['head'],label,'Conflicting heads at this count'if row['count']in conflicts else'No same-count conflict recorded']}for label,key in [('Shared','shared'),('Only left','only_left'),('Only right','only_right')]for row in report[key]]
    critical=('Conflicting signed heads need attention.'if conflicts else'Claim sets differ or contain no evidence.'if report['needs_attention']else'Authenticated claim sets match.')
    return render_report('Wireledger retained store comparison',report['scope']+f" Supplied witness identity {report['witness']}; left {report['left_count']} claims, right {report['right_count']} claims. Independently trust this public key.",
        ['Signed record count','Claimed head','Claim-set membership','Same-count comparison'],rows,payload=report,
        summary=critical+' No history ancestry, freshness, independent custody or observer truth established. No claims copied or merged.')
