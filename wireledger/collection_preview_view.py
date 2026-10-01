"""Offline collection-intent cards; no network or signing operation."""
from .report_cards import render_report


def render_collection(report):
    rows=[{'group':'Explicit endpoint intent','cells':[row['host'],row['port'],row['vantage']or'No vantage label']}for row in report['endpoints']]
    return render_report('Wireledger collection intent preview',report['scope']+' Endpoint labels and connection address may be private. This metadata is not an executable collection policy or an attestation. Native collection must be requested separately.', ['Normalized host','Port','Declared vantage label'],rows,payload=report,summary=f"Preview only: {report['selected_endpoints']} endpoints, {report['timeout_per_endpoint_seconds']} seconds network budget each, {report['history_records']} authenticated existing records. No network, CA-file read, private-key access or append; later collection can publish a partial prefix.")
