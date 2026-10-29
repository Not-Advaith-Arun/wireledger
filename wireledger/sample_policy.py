"""Unsigned collection intent from explicit historical signed samples only."""
from .policy_picker import policy_choices
from .inventory import expected_endpoints


def policy_from_samples(records, sequences):
    if (not isinstance(sequences, list) or not 1 <= len(sequences) <= 16
            or any(type(n) is not int or not 1 <= n <= len(records) for n in sequences)
            or len(set(sequences)) != len(sequences)):
        raise ValueError('choose1..16 distinct existing signed sequences')
    rows = [{key: records[n - 1]['body']['observation'][key] for key in ('host', 'port', 'vantage')} for n in sequences]
    groups = set()
    for row in rows: groups.update(expected_endpoints([row]))
    report = policy_choices([{'host': host, 'port': port, 'vantage': vantage} for host, port, vantage in sorted(groups)])
    report['selected_sequences'] = list(sequences)
    report['scope'] = ('Complete history authenticated with an independently supplied witness public key before extracting these explicit signed sample identities. Only chosen samples contribute endpoint/port/vantage groups; duplicate normalized groups coalesce. Verified and failed samples both describe collection intent, not present availability or permission to contact an endpoint. No private key, DNS/TCP/TLS, source history mutation or new sample. Exported policy is unsigned and requires deliberate review before separate native collection preview. ' + report['scope'])
    return report
