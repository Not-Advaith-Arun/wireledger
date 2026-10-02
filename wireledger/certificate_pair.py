"""Compare two explicitly selected captured leaf certificates; no trust verdict."""
from .chain_export import certificate_info
from .report_cards import render_report


def compare_captured_certificates(records,left_sequence,right_sequence):
    one=certificate_info(records,left_sequence)['metadata'];two=certificate_info(records,right_sequence)['metadata']
    def sample(sequence,metadata):
        observation=records[sequence-1]['body']['observation']
        return {'sequence':sequence,'endpoint':{key:observation[key]for key in ('host','port','vantage')},'signed_status':observation['status'],**{key:metadata[key]for key in ('certificate_sha256','spki_sha256','not_before','not_after')}}
    left,right=sample(left_sequence,one),sample(right_sequence,two)
    same_leaf=one['certificate_sha256']==two['certificate_sha256'];same_key=one['spki_sha256']==two['spki_sha256']
    return {'format':'wireledger-captured-certificate-pair-v1','left':left,'right':right,'same_endpoint':(left['endpoint']['host'],left['endpoint']['port'])==(right['endpoint']['host'],right['endpoint']['port']),'same_vantage':left['endpoint']['vantage']==right['endpoint']['vantage'],'same_captured_leaf':same_leaf,'same_captured_key':same_key,'comparison':'same_captured_leaf'if same_leaf else'different_certificate_same_key'if same_key else'different_captured_key',
        'scope':'Full signed history authenticated before selecting these exact sequence numbers, including nonadjacent samples. Each selected complete captured chain validated against its signed metadata before leaf comparison. Unselected certificate evidence is not decoded. Endpoint/vantage labels, fingerprints and validity windows may be sensitive. No certificate bodies/private keys, DNS/TCP/TLS, writes or independent path/hostname/freshness audit. Equal keys or changed certificates do not establish ownership, renewal, attacks, current availability or observer truth; different endpoint/vantage flags remain explicit.'}


def render_certificate_pair(report):
    rows=[{'group':side,'cells':[value['sequence'],value['endpoint']['host'],value['endpoint']['port'],value['endpoint']['vantage'],value['certificate_sha256'],value['spki_sha256']]}for side,value in [('Left selected sample',report['left']),('Right selected sample',report['right'])]]
    return render_report('Wireledger captured certificate comparison',report['scope'],['Signed sequence','Captured host','Port','Vantage','Captured leaf fingerprint','Captured key fingerprint'],rows,payload=report,summary=f"{report['comparison']}. Same endpoint: {report['same_endpoint']}; same vantage: {report['same_vantage']}. Captured bytes compared, not a renewal, attack or trust verdict.")
