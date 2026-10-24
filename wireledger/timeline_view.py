"""Static, bounded local timeline review after complete signed-history verification."""
from html import escape
import json
from pathlib import Path


def render_html(report, *, max_rows=200):
    if type(max_rows) is not int or not 1 <= max_rows <= 1000:
        raise ValueError("max rows must be between 1 and 1000")
    selected = report["results"][-max_rows:]
    def text(value):
        return escape(str(value), quote=True)
    rows = []
    for row in selected:
        rows.append('<tr data-status="' + text(row['status']) + '" data-changes="' + str(bool(row['changes'])).lower() + '">' + ''.join('<td>' + text(row.get(key, 'unavailable')) + '</td>' for key in
                    ('sequence', 'observed_at', 'host', 'port', 'vantage', 'status', 'validity', 'peer_ip'))
                    + '<td>' + text(json.dumps(row['changes'], ensure_ascii=True)) + '</td></tr>')
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Wireledger observation timeline</title><style>
''' + Path(__file__).with_name('ui').joinpath('timeline.css').read_text(encoding='utf-8') + '''
</style></head><body><main><div class="topline"><span>Wireledger / Observation history</span><button id="theme" type="button" aria-pressed="false">Dark theme</button></div><h1>Observation timeline</h1><p class="scope">''' + text(report['scope']) + ' ' + text(report['selection_scope']) + '</p><p>Validity time policy: ' + text(report['time_policy']) + '</p><p>' + text(report['pagination_scope']) + '</p><p>Page matches: ' + str(report['matching_records']) + '; remaining after cursor: ' + str(report['remaining_after_cursor']) + '; next after sequence: ' + text(report['next_after_sequence']) + '.</p><p>Showing ' + str(len(selected)) + ' of ' + str(report['selected_records']) + ' selected samples from ' + str(report['total_records']) + ' verified records. When capped, the latest signed-sequence samples are shown; omitted samples remain unshown.</p><details><summary>Selected filters</summary><code>' + text(json.dumps(report['filters'],ensure_ascii=True)) + '</code></details><div class="filters"><label>Search displayed samples<input id="find" type="search" autocomplete="off"></label><label>Sample status<select id="status"><option value="">All statuses</option><option value="verified">Verified</option><option value="error">Error</option></select></label><label class="checkbox"><input id="changed" type="checkbox"> Changes only</label><button id="clear" type="button">Clear filters</button><output id="matches" aria-live="polite"></output></div><div class="table"><table><caption>Verified signed observations · observer claims</caption><thead><tr>' + ''.join('<th scope="col">' + name + '</th>' for name in ['Sequence','Observer time','Host','Port','Vantage','Status','Certificate window','Peer','Changes']) + '</tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div><p>No private signing keys or certificate bodies are embedded. This page is a point-in-time display, not independent verification of observer truth or a live monitor.</p></main><script>' + Path(__file__).with_name('ui').joinpath('timeline.js').read_text(encoding='utf-8') + '</script></body></html>'
