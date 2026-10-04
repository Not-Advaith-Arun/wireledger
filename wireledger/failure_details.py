"""Bounded original signed-sequence samples within one current declared failure run."""
from .inventory import endpoint_inventory, expected_endpoints
from .report_cards import render_report


def failure_details(records, host, port, vantage, *, limit=50):
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError('failure detail display limit must be1..1000')
    # Validate native endpoint shape but keep the caller's exact signed labels.
    expected_endpoints([{'host': host, 'port': port, 'vantage': vantage}])
    for record in records:
        obs = record['body']['observation']
        if not isinstance(obs, dict): raise ValueError('unsupported signed observation metadata')
        expected_endpoints([{key: obs.get(key) for key in ('host', 'port', 'vantage')}])
        if (obs.get('status') not in ('verified', 'verification-failed', 'connection-failed', 'error')
                or obs.get('observed_at') is not None and (not isinstance(obs['observed_at'], str) or len(obs['observed_at']) > 120)):
            raise ValueError('unsupported signed observation group/status metadata')
    endpoint_inventory(records)  # Preserve complete evidence validation, including omitted groups.
    selected = [r for r in records if (r['body']['observation']['host'], r['body']['observation']['port'], r['body']['observation']['vantage']) == (host, port, vantage)]
    if not selected: raise ValueError('no captured signed samples for this exact group')
    last_success = next((i for i in range(len(selected) - 1, -1, -1) if selected[i]['body']['observation']['status'] == 'verified'), None)
    streak = selected[last_success + 1:] if last_success is not None else selected
    shown = streak[-limit:]
    return {'format': 'wireledger-failure-streak-details/v1', 'group': {'host': host, 'port': port, 'vantage': vantage},
            'full_history_records': len(records), 'group_samples': len(selected),
            'latest_sequence': selected[-1]['body']['sequence'], 'latest_status': selected[-1]['body']['observation']['status'],
            'last_verified_sequence': selected[last_success]['body']['sequence'] if last_success is not None else None,
            'no_verified_sample_in_group': last_success is None, 'current_streak_length': len(streak),
            'first_streak_sequence': streak[0]['body']['sequence'] if streak else None,
            'displayed_samples': len(shown), 'omitted_older_streak_samples': len(streak) - len(shown),
            'samples': [{'sequence': r['body']['sequence'], 'status': r['body']['observation']['status'], 'recorded_time': r['body']['observation'].get('observed_at')} for r in shown],
            'scope': 'Complete signed history authenticated before exact group inspection; all captured evidence metadata validates even outside this group. Current non-verified run starts after the last verified sample for this exact host/port/vantage in signed sequence order. Interleaved groups and reversed observer timestamps do not reorder or interrupt it. Newest bounded samples shown in original sequence order with explicit older omissions. Recorded time text and vantage labels are observer claims, not independent clocks, freshness, availability, outage duration, actual failure cause or network truth. Raw errors, certificates and private keys omitted; unsupported group/status metadata refuses. No history writes, DNS/TCP/TLS or private-key access; zero current streak only means the supplied history ends with a verified claim. A truncated or rolled-back supplied history can hide later samples without independent checkpoints.'}


def render_failure_details(report):
    rows = [{'group': row['status'], 'cells': [row['sequence'], row['status'], row['recorded_time'] if row['recorded_time'] is not None else 'Unknown recorded time']} for row in report['samples']]
    return render_report('Wireledger signed failure streak details', report['scope'], ['Original signed sequence', 'Recorded status', 'Observer time text'], rows, payload=report,
                         summary=f"{report['group']['host']}:{report['group']['port']} @ {report['group']['vantage']}: {report['current_streak_length']} current declared failures; {report['omitted_older_streak_samples']} older streak samples omitted. Last verified sequence: {report['last_verified_sequence']}. No new collection or freshness check.")
