"""Domain-separated Ed25519 signatures over a strictly encoded hash chain."""

import base64
import fcntl
import hashlib
import json
import os
import stat
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ZERO = "0" * 64
DOMAIN = b"wireledger/v1/record\x00"
CHECKPOINT_DOMAIN = b"wireledger/v1/checkpoint\x00"
HASH_DOMAIN = b"wireledger/v1/hash\x00"
MAX_FILE = 32 * 1024 * 1024


class LedgerError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise LedgerError("duplicate JSON key")
        result[key] = value
    return result


def parse(raw):
    try:
        return json.loads(raw, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(LedgerError("nonfinite JSON")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LedgerError("invalid JSON") from exc


def public_id(public_key):
    return hashlib.sha256(public_key.public_bytes_raw()).hexdigest()


def record_hash(record):
    return hashlib.sha256(HASH_DOMAIN + canonical(record)).hexdigest()


def _read(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise LedgerError(f"expected a regular non-symlink file: {path}")
    with path.open("rb") as handle:
        data = handle.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise LedgerError("file exceeds prototype size limit (32 MiB)")
    return data


def load_public(path):
    key = serialization.load_pem_public_key(_read(path))
    if not isinstance(key, Ed25519PublicKey):
        raise LedgerError("expected an Ed25519 public key")
    return key


def load_private(path):
    if stat.S_IMODE(Path(path).stat().st_mode) & 0o077:
        raise LedgerError("private key must have permissions 0600 (or stricter)")
    key = serialization.load_pem_private_key(_read(path), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise LedgerError("expected an Ed25519 private key")
    return key


def exclusive_write(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def initialize(directory):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    key = Ed25519PrivateKey.generate()
    exclusive_write(directory / "witness.key", key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    exclusive_write(directory / "witness.pub", key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo), 0o644)
    exclusive_write(directory / "observations.jsonl", b"")
    return {"directory": str(directory), "witness_id": public_id(key.public_key())}


def _verify_signature(key, signature, payload):
    try:
        decoded = base64.b64decode(signature, validate=True)
        # Unused base64 padding bits must also be canonical: envelope hashes include
        # this representation, so accepting aliases would make chain heads malleable.
        if not isinstance(signature, str) or base64.b64encode(decoded).decode("ascii") != signature:
            raise LedgerError("noncanonical signature encoding")
        key.verify(decoded, payload)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise LedgerError("signature verification failed") from exc


def verify_records(raw, public_key, checkpoint=None):
    records, previous = [], ZERO
    if raw and not raw.endswith(b"\n"):
        raise LedgerError("incomplete final record; refusing possibly interrupted append")
    for sequence, line in enumerate(raw.splitlines(), 1):
        record = parse(line)
        if not isinstance(record, dict) or set(record) != {"body", "signature"}:
            raise LedgerError("unexpected record envelope")
        body = record["body"]
        if not isinstance(body, dict) or set(body) != {"format", "sequence", "previous", "witness", "observation"}:
            raise LedgerError("unexpected record body")
        if body["format"] != "wireledger.record.v1" or type(body["sequence"]) is not int or body["sequence"] != sequence:
            raise LedgerError("invalid format or sequence")
        if body["previous"] != previous or body["witness"] != public_id(public_key):
            raise LedgerError("broken chain or wrong witness identity")
        if not isinstance(body["observation"], dict):
            raise LedgerError("observation must be an object")
        _verify_signature(public_key, record["signature"], DOMAIN + canonical(body))
        previous = record_hash(record)
        records.append(record)
    if checkpoint is not None:
        if not isinstance(checkpoint, dict) or set(checkpoint) != {"body", "signature"}:
            raise LedgerError("invalid checkpoint envelope")
        body = checkpoint["body"]
        if not isinstance(body, dict) or set(body) != {"format", "count", "head", "witness"}:
            raise LedgerError("invalid checkpoint body")
        _verify_signature(public_key, checkpoint["signature"], CHECKPOINT_DOMAIN + canonical(body))
        count = body["count"]
        if body["format"] != "wireledger.checkpoint.v1" or body["witness"] != public_id(public_key):
            raise LedgerError("wrong checkpoint format or identity")
        if type(count) is not int or count < 0 or count > len(records):
            raise LedgerError("history shorter than checkpoint")
        head = record_hash(records[count - 1]) if count else ZERO
        if body["head"] != head:
            raise LedgerError("history diverges from checkpoint")
    return records


def verify(path, public_key, checkpoint=None):
    return verify_records(_read(path), public_key, checkpoint)


def append(path, key, observation):
    """Advisory locking serializes cooperating local writers on Unix."""
    if not isinstance(observation, dict):
        raise LedgerError("observation must be an object")
    # Fail before opening the ledger if the observation cannot be represented.
    canonical(observation)
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    with os.fdopen(fd, "r+b") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise LedgerError("ledger must be a regular file")
        fcntl.flock(handle, fcntl.LOCK_EX)
        raw = handle.read(MAX_FILE + 1)
        if len(raw) > MAX_FILE:
            raise LedgerError("ledger exceeds size limit")
        records = verify_records(raw, key.public_key())
        body = {"format": "wireledger.record.v1", "sequence": len(records) + 1,
                "previous": record_hash(records[-1]) if records else ZERO,
                "witness": public_id(key.public_key()), "observation": observation}
        record = {"body": body, "signature": base64.b64encode(key.sign(DOMAIN + canonical(body))).decode("ascii")}
        encoded = canonical(record) + b"\n"
        if len(raw) + len(encoded) > MAX_FILE:
            raise LedgerError("append would exceed size limit")
        handle.seek(0, os.SEEK_END)
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
        return record


def make_checkpoint(records, key):
    body = {"format": "wireledger.checkpoint.v1", "count": len(records),
            "head": record_hash(records[-1]) if records else ZERO,
            "witness": public_id(key.public_key())}
    return {"body": body, "signature": base64.b64encode(key.sign(CHECKPOINT_DOMAIN + canonical(body))).decode("ascii")}
