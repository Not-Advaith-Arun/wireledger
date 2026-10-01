"""Captured independent certificate audit metadata, never certificate bodies/diagnostics."""
from .report_cards import render_report


def audit_metadata(report):
    allowed={'sequence','host','port','status','verification_time','verified_chain_length','captured_ca_set_matches_audit_set','observer_policy_recorded'}
    return {'format':'wireledger-offline-audit-review/v1','ok':report['ok'],'audit_ca_set_sha256':report['audit_ca_set_sha256'],'time_policy':report['time_policy'],'verifier_policy':report['verifier_policy'],
            'results':[{key:value for key,value in row.items()if key in allowed}for row in report['results']],
            'details_omitted':True,'scope':report['scope']+' Captured independent certificate audit only, after native ledger signature verification. Private diagnostics, certificate bodies and input paths omitted. Hostnames, sequence IDs, timestamps and trust fingerprints can still be sensitive. Missing legacy evidence and unsuccessful handshakes never count as passing. Observer-asserted time is not independently trusted; audit trust can differ from recorded observer trust. This metadata is not a full diagnostic report or historical availability/observer-policy equivalence proof.'}


def render_audit(report):
    data=audit_metadata(report)
    rows=[{'group':row['status'],'cells':[row['sequence'],str(row['host'])+':'+str(row['port']),row['status'],row.get('verification_time','No certificate verification'),row.get('verified_chain_length','Not verified'),row.get('captured_ca_set_matches_audit_set','Not verified')]}for row in data['results']]
    return render_report('Wireledger independent offline certificate audit',data['scope'],['Signed sequence','Recorded endpoint','Independent audit result','Verification time','Verified chain length','Recorded CA set equals audit trust'],rows,payload=data,summary=f"Independent audit passed: {data['ok']}; {len(rows)} signed observations assessed using {data['time_policy']}. No live handshake, trusted timestamp or revocation proof; failure exits preserved.")
