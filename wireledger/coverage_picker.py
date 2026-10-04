"""Explicit unsigned next-collection choices from authenticated coverage metadata."""
from pathlib import Path
from .report_cards import render_report


def coverage_choices(coverage, verification):
    return {'format': 'wireledger-coverage-policy-picker/v1', 'authenticated_history': verification,
            'coverage': coverage,
            'policy': [{key: row[key] for key in ('host', 'port', 'vantage')} for row in coverage['results']],
            'scope': 'Complete signed history and complete unsigned expected manifest validated natively before these explicit choices. Rows describe collection coverage, not current availability, independent freshness or trust. Choose at most16 intended endpoint/vantage groups deliberately; no failure or missing group is selected automatically. Attention-only mode offers only its reported groups and retains global attention/unexpected metadata. An empty choice set does not prove global coverage or freshness. Policy downloads are unsigned intent for separate observe-policy --preview; no private key, CA file, DNS/TCP/TLS, append or collection here. Host/vantage labels and hashes may be private. ' + coverage['scope']}


def render_coverage_choices(report):
    rows = [{'group': row['collection_state'], 'cells': [row['host'], row['port'], row['vantage'], row['collection_state'], row['latest_sequence'] if row['latest_sequence'] is not None else 'No selected sample']}
            for row in report['coverage']['results']]
    return render_report('Wireledger coverage collection choices', report['scope'],
                         ['Expected host', 'Port', 'Declared vantage', 'Recorded coverage', 'Latest selected signed sequence'], rows, payload=report,
                         summary=f"{len(rows)} expected groups offered for deliberate intent; needs attention: {report['coverage']['needs_attention']}. No endpoints contacted or selected automatically.",
                         extra_script=Path(__file__).with_name('ui').joinpath('policy_picker.js').read_text())
