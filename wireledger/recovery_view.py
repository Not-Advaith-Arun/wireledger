"""Path-free recovery review metadata, deliberately not a reusable apply plan."""
from .report_cards import render_report


def recovery_metadata(plan):
    fields=('witness','original_sha256','original_bytes','recovered_sha256','recovered_bytes','action','removed_bytes','added_bytes','verified_count','verified_head','scope')
    return {'format':'wireledger-recovery-review/v1',**{key:plan[key] for key in fields},'selected_stores':[{'ordinal':i,'claims':store['claims']} for i,store in enumerate(plan['selected_stores'],1)]}


def render_recovery(plan):
    data=recovery_metadata(plan)
    rows=[{'group':'Selected store '+str(store['ordinal']),'cells':[store['ordinal'],claim['count'],claim['head'],claim['sha256']]}for store in data['selected_stores']for claim in store['claims']]
    return render_report('Wireledger recovery preview',data['scope']+' Paths, original bytes and record contents are omitted. Downloaded review metadata is not a recovery-apply plan; obtain and independently review the native preview JSON for explicit recovery. This page never applies recovery.',
        ['Selected store ordinal','Retained record count','Retained head','Signed claim digest'],rows,payload=data,
        summary=f"Proposed {data['action']}: {data['original_bytes']} to {data['recovered_bytes']} bytes; remove {data['removed_bytes']}, add {data['added_bytes']}. Verified candidate prefix: {data['verified_count']} records. Candidate head and byte digests remain in the metadata download. No writes performed; selected claims do not prove freshness or observer truth.")
