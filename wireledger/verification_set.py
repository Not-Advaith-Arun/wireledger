"""Independent whole-history and optional trusted-pin checks for an explicit view set."""
from pathlib import Path
import re
from .ledger import load_public,public_id,read_checkpoint,verify,record_hash,ZERO
from .report_cards import render_report


def verify_set(manifest,base):
    if not isinstance(manifest,dict)or set(manifest)!={'format','views'}or manifest['format']!='wireledger-history-view-set/v1':raise ValueError('expected history view set manifest')
    views=manifest['views']
    if not isinstance(views,list)or not 1<=len(views)<=8:raise ValueError('choose1..8 explicit retained history views')
    seen=set()
    for row in views:
        if not isinstance(row,dict)or set(row)!={'id','history','public_key','checkpoint'}or not isinstance(row['id'],str)or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',row['id'])or row['id']in seen:raise ValueError('distinct bounded view IDs and exact history/public_key/checkpoint fields required')
        seen.add(row['id'])
        if any(not isinstance(row[k],str)or not row[k]or'\0'in row[k]for k in ('history','public_key'))or row['checkpoint']is not None and(not isinstance(row['checkpoint'],str)or not row['checkpoint']or'\0'in row['checkpoint']):raise ValueError('explicit paths required; checkpoint may be null')
    rows=[]
    for row in views:
        result={'id':row['id'],'status':'unverified','witness':None,'records':None,'head':None,'checkpoint_supplied':row['checkpoint']is not None,'checkpoint_ancestry':'not_checked'}
        try:
            key=load_public(Path(base)/row['public_key']);checkpoint=read_checkpoint(Path(base)/row['checkpoint'])if row['checkpoint']is not None else None
            records=verify(Path(base)/row['history'],key,checkpoint)
            result.update(status='verified',witness=public_id(key),records=len(records),head=record_hash(records[-1])if records else ZERO,checkpoint_ancestry='verified_prefix'if checkpoint is not None else'not_supplied')
        except (OSError,ValueError):result['status']='unverified_history_key_or_pin'
        rows.append(result)
    return {'format':'wireledger-history-view-set-report/v1','all_verified':all(r['status']=='verified'for r in rows),'views_checked':len(rows),'verified_views':sum(r['status']=='verified'for r in rows),
            'distinct_verified_public_keys':len({r['witness']for r in rows if r['status']=='verified'}),'views':rows,
            'scope':'Every explicit manifest row validates before opening inputs. Each complete supplied history independently verifies signatures, chain and any explicitly supplied trusted-key checkpoint; relative paths resolve beside the manifest. A failed or missing view keeps count/head unknown, never zero, while other verified views remain visible. Paths, observation bodies, certificates and raw private errors omitted. No cross-view fork/prefix relation, common origin, witness independence, trusted key provenance, freshest head, observer truth, network availability or real-time snapshot asserted. Multiple views may use the same public key. Trust keys/pins independently and compare related views separately. No private keys, network, history/retention writes or repair.'}


def render_verification_set(report):
    return render_report('Wireledger retained history view verification',report['scope'],['View ID','Independent verification','Captured records','Trusted checkpoint relation'],[{'group':r['status'],'cells':[r['id'],r['status'],r['records']if r['records']is not None else'Unknown',r['checkpoint_ancestry']]}for r in report['views']],payload=report,summary=f"{report['verified_views']} of {report['views_checked']} explicit views verified; {report['distinct_verified_public_keys']} distinct verified public keys. All verified: {report['all_verified']}. Unverified view counts remain unknown; no cross-view consistency or freshness claim.")
