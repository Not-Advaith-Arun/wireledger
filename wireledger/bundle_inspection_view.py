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


def render_combined(bundle,report,input_claims):
    rows=[{'group':'Conflicting count'if c['count']in report['conflicting_counts']else'Authenticated claim','cells':[c['count'],c['head'],c['sha256']]}for c in report['claims']]
    return render_report('Wireledger combined detached claims',
        'Both complete input bundles authenticated against the same independently supplied public key. Identical signed bodies coalesced; distinct same-count heads are preserved with original signatures. Output order is first input then new claims from the second, not chronology or ancestry. Bundle containers are unsigned: no completeness, custody, freshness or history consistency is established. No store, history, private-key, import or network operation occurred. This page contains selected original signed claims for a separate explicit native import.',
        ['Signed record count','Claimed head','Signed claim digest'],rows,payload=bundle,
        summary=f"Combined {input_claims} supplied claims into {report['claim_count']} distinct signed bodies; {input_claims-report['claim_count']} repeated bodies coalesced. Same-count conflicts retained: {len(report['conflicting_counts'])}. Download report JSON is an importable bundle; conflicts still require attention.")


def render_bundle_picker(bundle,report,choices=None):
    from pathlib import Path
    import json
    from .bundle_choices import bundle_choices
    selected=bundle_choices(bundle,report,choices)
    captured='const capturedBundleChoices='+json.dumps(selected,ensure_ascii=True).replace('<','\\u003c').replace('&','\\u0026')+';\n'
    rows=[{'group':'Conflicting count'if row['count']in report['conflicting_counts']else'Authenticated claim','cells':[row['count'],row['head'],row['sha256']]}for row in report['claims']]
    return render_report('Wireledger detached claim picker',report['scope']+' Original signed claims are embedded by this explicit picker command. Saved count choices bind to this full canonical bundle and independently checked witness key; this hash is a consistency guard, not new authenticity or freshness evidence. Choose record counts; every supplied conflicting head at each chosen count is kept. Downloaded subsets require separate native verification/import with an independently supplied key. No history, private key, retained store or network accessed.',
        ['Signed record count','Claimed head','Signed claim digest'],rows,payload=bundle,
        summary=f"All {report['claim_count']} signatures authenticated; {len(report['conflicting_counts'])} conflicting counts need attention. Choose counts explicitly; neither a subset nor unequal counts prove completeness, ancestry or freshness.",extra_script=captured+Path(__file__).with_name('ui').joinpath('bundle_picker.js').read_text())
