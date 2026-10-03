"""All-or-none metadata for explicitly chosen captured certificate sequences."""
from .chain_export import certificate_info
from .report_cards import render_report


def certificate_batch(records,sequences,*,index=1):
    if(not isinstance(sequences,list)or not 1<=len(sequences)<=16 or any(type(n)is not int or not 1<=n<=len(records)for n in sequences)or len(set(sequences))!=len(sequences)):
        raise ValueError('choose1..16 distinct existing signed sequences')
    if type(index)is not int or index<1:raise ValueError('certificate index must be positive and explicit')
    # Build the complete result only after every selected complete chain validates.
    samples=[certificate_info(records,number,index)for number in sequences]
    return {'format':'wireledger-certificate-metadata-batch/v1','selected_sequences':list(sequences),'certificate_index':index,'samples':samples,
        'scope':'Full signed history authenticated with independently supplied public key before decoding these1..16 explicit original sequences. Every complete selected captured chain and requested certificate index validates before any output; a late invalid sample refuses the whole export. Original choice order preserved. Decoded subject/issuer/SAN names, fingerprints and windows can be private; certificate bodies and private keys omitted. No DNS/TCP/TLS, writes, independent path/hostname/trust/freshness audit, ownership or attack verdict. Selection cap does not bound complete history verification cost. Missing capture remains an error, never invented certificate evidence.'}


def render_certificate_batch(report):
    rows=[{'group':'Explicit captured certificate','cells':[r['sequence'],r['certificate_index'],r['metadata']['subject'],r['metadata']['issuer'],r['metadata']['certificate_sha256'],r['metadata']['spki_sha256']]}for r in report['samples']]
    return render_report('Wireledger selected captured certificate metadata',report['scope'],['Signed sequence','Captured certificate index','Decoded subject','Decoded issuer','Captured certificate fingerprint','Captured key fingerprint'],rows,payload=report,summary=f"{len(rows)} explicitly selected captured certificates validated before this metadata export. No certificate bodies, live sampling or trust judgment.")
