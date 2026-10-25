"""Captured maintenance claims, separate from independent TLS audit or freshness."""
from .report_cards import render_report


def render_certificate_review(report,kind):
    rows=[]
    if kind=='expiry':
        for row in report['results']:
            rows.append({'group':row['certificate_window']+' / '+row['sampling_state'],
                'cells':[f"{row['host']}:{row['port']}",row['vantage'],row['certificate_window'],
                         row['not_after'] or 'Unavailable',row['seconds_until_expiry'] if row['seconds_until_expiry'] is not None else 'Unknown',row['sampling_state'],row['sequence']]})
        scope=report['scope']+f" Explicit as-of {report['as_of']}, horizon {report['within_days']} days, maximum observer age {report['max_age_seconds']} seconds. Checked {report.get('checked_groups',len(rows))} groups; omitted healthy groups {report.get('omitted_healthy_groups',0)}."
        return render_report('Wireledger captured certificate expiry',scope,
            ['Endpoint','Vantage','Captured certificate window','Captured expiry claim','Seconds until claimed expiry','Observer sampling state','Latest signed sequence'],rows,payload=report,
            summary=('Attention required under supplied inputs. ' if report['needs_attention'] else 'No attention condition detected under supplied inputs. ')+'Captured observer claims, not a new TLS handshake, independent freshness or renewal guarantee. Unavailable latest samples never use older success.')
    for key,label in [('certificate_sha256','Shared certificate fingerprint'),('spki_sha256','Shared key fingerprint')]:
        for entry in report['shared'][key]:
            endpoints='; '.join(f"{r['host']}:{r['port']} / {r['vantage']} / sequence {r['sequence']}" for r in entry['samples'])
            rows.append({'group':label,'cells':[label,entry['fingerprint'],entry['distinct_endpoints'],endpoints]})
    for entry in report['unavailable_samples']:
        rows.append({'group':'Latest sample unavailable','cells':['Latest sample unavailable','Unknown',1,f"{entry['host']}:{entry['port']} / {entry['vantage']} / sequence {entry['sequence']}"]})
    scope=report['scope']+f" Latest endpoint/vantage samples {report['latest_samples']}; unavailable {len(report['unavailable_samples'])}. Opaque fingerprints and endpoint metadata only; no captured certificate bodies or private diagnostics."
    return render_report('Wireledger captured fingerprint sharing',scope,
        ['Captured relation','Fingerprint','Distinct endpoints','Latest signed samples'],rows,payload=report,
        summary='Shared captured fingerprints are observer claims, not attack, ownership or independent-audit verdicts. Failed latest samples remain unavailable; no TLS handshake is performed.')
