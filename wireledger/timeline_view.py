"""Static, bounded local timeline review after complete signed-history verification."""
from html import escape
import json


def render_html(report, *, max_rows=200):
    if type(max_rows) is not int or not 1 <= max_rows <= 1000:
        raise ValueError("max rows must be between 1 and 1000")
    selected = report["results"][-max_rows:]
    def text(value):
        return escape(str(value), quote=True)
    rows = []
    for row in selected:
        rows.append('<tr>' + ''.join('<td>' + text(row.get(key, 'unavailable')) + '</td>' for key in
                    ('sequence', 'observed_at', 'host', 'port', 'vantage', 'status', 'validity', 'peer_ip'))
                    + '<td>' + text(json.dumps(row['changes'], ensure_ascii=True)) + '</td></tr>')
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Wireledger observation timeline</title><style>
body{margin:0;background:#edf2f5;color:#233a47;font:16px/1.6 system-ui,sans-serif}main{max-width:1400px;margin:auto;padding:2rem}h1{font:2.3rem Georgia,serif}p{max-width:85ch}.scope{border-left:4px solid #526b7b;padding:.7rem 1rem;background:white}.table{overflow:auto;background:white}table{border-collapse:collapse;width:100%;font-size:.85rem}th,td{text-align:left;vertical-align:top;padding:.6rem;border-bottom:1px solid #b8c7cf;overflow-wrap:anywhere}caption{text-align:left;font-weight:600;padding:1rem}code{white-space:pre-wrap;overflow-wrap:anywhere}@media(max-width:650px){main{padding:1rem}th,td{min-width:7rem}}
</style></head><body><main><h1>Observation timeline</h1><p class="scope">''' + text(report['scope']) + ' ' + text(report['selection_scope']) + '</p><p>Validity time policy: ' + text(report['time_policy']) + '</p><p>' + text(report['pagination_scope']) + '</p><p>Page matches: ' + str(report['matching_records']) + '; remaining after cursor: ' + str(report['remaining_after_cursor']) + '; next after sequence: ' + text(report['next_after_sequence']) + '.</p><p>Showing ' + str(len(selected)) + ' of ' + str(report['selected_records']) + ' selected samples from ' + str(report['total_records']) + ' verified records. When capped, the latest signed-sequence samples are shown; omitted samples remain unshown.</p><details><summary>Selected filters</summary><code>' + text(json.dumps(report['filters'],ensure_ascii=True)) + '</code></details><div class="table"><table><caption>Verified signed observations · observer claims</caption><thead><tr>' + ''.join('<th scope="col">' + name + '</th>' for name in ['Sequence','Observer time','Host','Port','Vantage','Status','Certificate window','Peer','Changes']) + '</tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div><p>No private signing keys or certificate bodies are embedded. This page is a point-in-time display, not independent verification of observer truth or a live monitor.</p></main></body></html>'
