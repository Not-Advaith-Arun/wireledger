"""Export selected captured public certificate bytes for independent offline tools."""
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from .evidence import validate_evidence


def certificate_chain(records, sequence):
    if type(sequence) is not int or not 1 <= sequence <= len(records):
        raise ValueError("sequence must select an existing signed observation")
    observation = records[sequence-1]["body"]["observation"]
    if "evidence" not in observation:
        raise ValueError("selected observation has no captured certificate evidence")
    chain = validate_evidence(observation)
    pem = "".join(x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM).decode("ascii") for der in chain)
    return {"sequence":sequence,"certificate_count":len(chain),"chain_capture":observation["evidence"]["chain_capture"],
            "sha256":[hashlib.sha256(der).hexdigest() for der in chain],"pem":pem,
            "scope":"Captured public certificate bytes only, validated against signed observation metadata after full history authentication. No private keys/session secrets, network, writes or independent trust decision. A leaf-only capture remains leaf-only; a captured verified-chain label is an observer claim, not a new path/hostname/freshness audit. Use independently supplied trust with external verification tools."}


def certificate_info(records, sequence, index=1):
    """Decode captured metadata after checking the complete selected evidence."""
    if type(sequence) is not int or not 1 <= sequence <= len(records):
        raise ValueError("sequence must select an existing signed observation")
    observation = records[sequence-1]["body"]["observation"]
    if "evidence" not in observation:
        raise ValueError("selected observation has no captured certificate evidence")
    chain = validate_evidence(observation)
    if type(index) is not int or not 1 <= index <= len(chain):
        raise ValueError("certificate index must select a captured certificate, starting at1")
    from .evidence import certificate_metadata
    return {"sequence":sequence,"certificate_index":index,"certificate_count":len(chain),
            "metadata":certificate_metadata(chain[index-1]),
            "scope":"Metadata decoded from public captured DER after complete selected evidence validation and full history authentication. No private keys, network, writes or certificate bodies emitted. A decoded name, issuer or validity window is not an independent trust/path/hostname/freshness decision; chain positions reflect captured order, not a new path build."}
