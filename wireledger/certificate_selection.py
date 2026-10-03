"""Explicit sequence-pair handoff bound to a completely authenticated history."""
from pathlib import Path
from .report_cards import render_report


def selected_pair(records,identity,value,*,complete=False):
    fields={'format','witness','count','head','left_sequence','right_sequence'}
    if(not isinstance(value,dict)or set(value)!=fields or type(value.get('count'))is not int or value['format']!='wireledger-certificate-selection/v1'or any(value[key]!=identity[key]for key in('witness','count','head'))):
        raise ValueError('certificate selection belongs to a different or changed signed history')
    chosen=[]
    for field in('left_sequence','right_sequence'):
        number=value[field]
        if number is None and not complete:chosen.append(None);continue
        if type(number)is not int or not 1<=number<=len(records)or not isinstance(records[number-1]['body']['observation'].get('evidence'),dict):
            raise ValueError('choose an explicit signed sequence with captured certificate evidence for each side')
        chosen.append(number)
    return chosen


def certificate_choices(records,identity,*,after_sequence=0,limit=50,selection=None):
    if type(after_sequence)is not int or not 0<=after_sequence<=len(records)or type(limit)is not int or not 1<=limit<=1000:
        raise ValueError('certificate picker cursor must be0..count and limit1..1000')
    pair=selected_pair(records,identity,selection)if selection is not None else[None,None]
    eligible=[r for r in records if isinstance(r['body']['observation'].get('evidence'),dict)]
    remaining=[r for r in eligible if r['body']['sequence']>after_sequence];page=remaining[:limit];more=len(remaining)>len(page)
    rows=[]
    for row in page:
        observation=row['body']['observation'];rows.append({'sequence':row['body']['sequence'],**{key:observation[key]for key in('host','port','vantage','status')}})
    return {'format':'wireledger-certificate-picker/v1','selection':{'format':'wireledger-certificate-selection/v1',**{key:identity[key]for key in('witness','count','head')},'left_sequence':pair[0],'right_sequence':pair[1]},'samples':rows,'captured_samples':len(eligible),'has_more':more,'next_after_sequence':rows[-1]['sequence']if more else None,
        'scope':'Full signed history authenticated with the independently supplied public key before capturing this page. Rows only indicate stored certificate evidence exists; chains are not decoded here. Exact left/right sequences remain explicit across captured pages; changed witness/count/head refuses native carry/comparison. Private endpoint/vantage labels are included; no certificate bodies/private keys, network or writes. Native compare-certificates separately validates both complete selected chains. Captured identity is not freshness, observer truth, trust, renewal, attack or custody evidence.'}


def render_certificate_choices(report):
    rows=[{'group':'Captured evidence present','cells':[r['sequence'],r['host'],r['port'],r['vantage'],r['status']]}for r in report['samples']]
    return render_report('Wireledger choose captured certificates',report['scope'],['Signed sequence','Captured host','Port','Vantage','Signed status'],rows,payload=report,summary=f"{len(rows)} of {report['captured_samples']} captured-evidence samples. Next cursor: {report['next_after_sequence']}. Choose both sides deliberately; no certificate comparison or trust audit performed here.",extra_script=Path(__file__).with_name('ui').joinpath('certificate_picker.js').read_text())
