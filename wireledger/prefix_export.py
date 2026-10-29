"""Explicit bounded prefix transport from a fully authenticated signed history."""
from .ledger import record_hash, ZERO
from .report_cards import render_report


def prefix_metadata(records, count, witness):
    if type(count) is not int or not 0 <= count <= min(len(records), 1000):
        raise ValueError('prefix count must be0..1000 and not exceed the fully verified input history')
    return {'format': 'wireledger-history-prefix/v1', 'witness': witness, 'source_records': len(records),
            'selected_records': count, 'omitted_suffix_records': len(records) - count,
            'prefix_head': record_hash(records[count - 1]) if count else ZERO,
            'scope': 'Complete original history authenticated under independently supplied public key before this explicit bounded prefix selection, including the omitted suffix. Default metadata omits observation bodies; --jsonl deliberately exports full original signed observations and captured certificates, which can be private. No signatures or observations created, keys loaded, history files changed or network accessed. Re-serialized JSON preserves original signed record values; output is a deliberately truncated transport, not a complete/fresh history, rollback approval or custody proof. A verifier with a newer retained checkpoint must reject the old prefix. Empty prefix is not evidence of no observations; source count and omissions here are unauthenticated metadata outside the original signatures. Prefix export cap does not bound full-history verification cost.'}


def render_prefix_metadata(report):
    return render_report('Wireledger explicit history prefix', report['scope'],
                         ['Verified source records', 'Explicit prefix count', 'Omitted suffix records', 'Chosen signed prefix head'],
                         [{'group': 'Deliberate partial transport', 'cells': [report['source_records'], report['selected_records'], report['omitted_suffix_records'], report['prefix_head']]}], payload=report,
                         summary='Explicit partial transport only. No completeness, freshness or rollback approval; raw private observations require separate --jsonl export.')
