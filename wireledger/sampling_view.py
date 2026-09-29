"""Present collection gaps without translating observer claims into uptime."""
from .report_cards import render_report


def render_sampling(report):
    rows=[]
    if 'expected_groups' in report:
        for row in report['results']:
            rows.append({'group':row['collection_state'],'cells':[row['host']+':'+str(row['port']),row['vantage'],row['collection_state'],row['samples'],row['latest_sequence']]})
        for row in report['unexpected_groups']:
            rows.append({'group':'unexpected','cells':[row['host']+':'+str(row['port']),row['vantage'],'Outside selected policy','Not evaluated here','Not evaluated here']})
        scope=report['scope']+f" Expected groups: {report['expected_groups']}. Authenticated records: {report['total_records']}; selected records: {report['selected_records']}, after sequence {report['after_sequence']}. Omitted verified groups: {report.get('omitted_verified_groups',0)}."
        columns=['Endpoint','Vantage','Collection state','Selected samples','Latest selected sequence']
    else:
        for row in report['results']:
            rows.append({'group':row['sampling_state'],'cells':[row['host']+':'+str(row['port']),row['vantage'],row['sampling_state'],row['latest_status'],row['age_seconds'] if row['age_seconds'] is not None else 'Unknown',f"{len(row['gaps'])} gaps; {len(row['clock_reversals'])} reversals; {len(row['unavailable_times'])} unavailable times"]})
        scope=report['scope']+f" Explicit comparison time: {report['as_of']}; maximum gap: {report['max_gap_seconds']} seconds. Authenticated records: {report['total_records']}."
        columns=['Endpoint','Vantage','Observer-clock state','Latest signed status','Observer age seconds','Recorded timing gaps']
    scope+=' Attention required.' if report['needs_attention'] else ' No attention condition detected under these explicit inputs.'
    return render_report('Wireledger sampling coverage review',scope,columns,rows,payload=report,summary=("Attention required. " if report["needs_attention"] else "No attention condition detected under these inputs. ")+"Signed sampling evidence under explicit policy or observer-clock thresholds; no live availability or independent freshness claim.")
