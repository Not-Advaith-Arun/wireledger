"""Authenticate a retained/public checkpoint without retaining or sampling it."""
import hashlib
from .ledger import canonical, read_checkpoint, verify_checkpoint


def inspect_checkpoint(path, key):
    checkpoint = read_checkpoint(path)
    body = verify_checkpoint(checkpoint, key)
    return {"format": "wireledger-checkpoint-inspection-v1", "signature_verified": True,
            "checkpoint_sha256": hashlib.sha256(canonical(checkpoint)).hexdigest(),
            "claim": body, "history_relation": "not_checked", "freshness": "not_checked",
            "scope": "One checkpoint signature/shape checked against the explicitly supplied public key. No store, history, private key, network observation or retention write used. Caller must independently trust the key; this claim alone establishes no history ancestry, consistency, freshness, independent custody or observer truth."}
