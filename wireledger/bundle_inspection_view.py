"""Detached authenticated claim metadata without destination, ledger or custody inference."""
from .report_cards import render_report


def render_bundle(report):
    rows=[{'group':'Conflicting count'if claim['count']in report['conflicting_counts']else'Authenticated claim','cells':[i,claim['count'],claim['head'],claim['sha256']]}for i,claim in enumerate(report['claims'],1)]
    return render_report('Wireledger detached bundle inspection',report['scope']+' This captured page cannot import, sample a live endpoint or refresh trust. Preserve the original signed bundle separately; this metadata is not an importable bundle.',
        ['Supplied claim ordinal','Signed record count','Claimed head','Signed claim digest'],rows,payload=report,
        summary=f"Authenticated {report['claim_count']} detached claims. Same-count conflicts: {len(report['conflicting_counts'])}. No destination or history was required; unequal counts do not prove ancestry and subsets do not prove completeness.")


def render_comparison(report):
    rows=[{'group':c['membership'],'cells':[c['count'],c['head'],'Conflicting count'if c['count']in report['conflicting_counts']else'No supplied same-count conflict']}for c in report['claims']]
    return render_report('Wireledger detached bundle comparison',report['scope'],['Signed record count','Claimed head','Supplied conflict status'],rows,payload=report,summary=f"Left {report['left_claim_count']} claims; right {report['right_claim_count']}; shared {report['shared_claim_count']}. Same-count conflicts: {len(report['conflicting_counts'])}. No imports, store changes or ancestry proof.")


def render_selection(bundle,report,original_count):
    rows=[{'group':'Conflicting count'if c['count']in report['conflicting_counts']else'Selected signed claim','cells':[c['count'],c['head'],c['sha256']]}for c in report['claims']]
    return render_report('Wireledger selected detached claims',
        'Every original supplied signature was authenticated before selecting explicit record counts. Original selected claims and signatures are included in this page and native bundle download, including every conflicting head at each selected count. No destination, retained store, history or private key was read or changed. The container is unsigned: selection never proves original completeness, ancestry, freshness, independent custody or observer truth. Import or inspect separately with an independently supplied public key.',
        ['Signed record count','Claimed head','Signed claim digest'],rows,payload=bundle,
        summary=f"Selected {report['claim_count']} of {original_count} signed claims; {original_count-report['claim_count']} omitted. Same-count conflicts retained: {len(report['conflicting_counts'])}. Download report JSON is an importable signed-claim bundle; conflicts still require attention.")
