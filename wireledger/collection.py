"""Explicit bounded collection policy; no scheduled or background observations."""
import ipaddress
import math
from pathlib import Path

from .inventory import expected_endpoints
from .ledger import append, load_private, load_public, verify, record_hash, ZERO
from .probe import observe


def _parameters(expected, *, connect_ip=None, timeout=5):
    rows = sorted(expected_endpoints(expected))
    if len(rows) > 16:
        raise ValueError('policy collection requires at most16 endpoint/vantage rows')
    if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError('timeout must be finite and between0 and60 seconds')
    if connect_ip is not None:
        connect_ip = str(ipaddress.ip_address(connect_ip))
        if '%' in connect_ip:
            raise ValueError('scoped connection addresses are not supported')
    return rows,connect_ip


def preview_policy(directory, expected, *, connect_ip=None, cafile=None, timeout=5):
    rows,connect_ip = _parameters(expected,connect_ip=connect_ip,timeout=timeout)
    directory=Path(directory)
    records=verify(directory/'observations.jsonl',load_public(directory/'witness.pub'))
    return {'preview':True,'selected_endpoints':len(rows),
            'endpoints':[{'host':host,'port':port,'vantage':vantage} for host,port,vantage in rows],
            'connect_ip':connect_ip,'timeout_per_endpoint_seconds':timeout,
            'trust_source':'explicit CA file' if cafile is not None else 'system default',
            'history_records':len(records),'history_head':record_hash(records[-1]) if records else ZERO,
            'scope':'Read-only normalized collection preview under the local witness public key. No private key,CA file,DNS,TCP,TLS or append attempted. Connectivity,private-key availability and trust-file validity remain untested; later collection independently revalidates and may append a partial prefix. No observations,freshness,network truth or cost guarantee implied.'}


def observe_policy(directory, expected, *, connect_ip=None, cafile=None, timeout=5):
    rows,connect_ip = _parameters(expected,connect_ip=connect_ip,timeout=timeout)
    directory = Path(directory)
    key = load_private(directory/'witness.key')
    ledger = directory/'observations.jsonl'
    verify(ledger, key.public_key())  # Refuse corrupt destination before network attempts.
    samples = []
    for host, port, vantage in rows:
        observation = observe(host, port, connect_ip=connect_ip, cafile=cafile, vantage=vantage, timeout=timeout)
        record = append(ledger, key, observation)
        samples.append({'host':host, 'port':port, 'vantage':vantage,
                        'sequence':record['body']['sequence'], 'status':observation['status']})
    return {'selected_endpoints':len(rows), 'recorded_samples':len(samples), 'samples':samples,
            'all_verified':all(row['status']=='verified' for row in samples),
            'scope':'Explicit one-pass collection in normalized endpoint order, each append authenticated and locked separately. Failed TLS/network observations are signed and collection continues. Not a transaction or snapshot: publication/I/O failure can leave a partial prefix; inspect history before retry, which creates new samples. Per-endpoint network budgets exclude file/lock work; no whole-command deadline, scheduling, freshness, independent vantage or observer-truth guarantee.'}
