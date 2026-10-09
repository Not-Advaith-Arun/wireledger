"""Explicit, checkpoint-constrained recovery of an interrupted final append.

The saved original is evidence, not proof that interruption caused the damage.
Cooperating Unix writers share the ledger inode lock; recovery never replaces it.
"""

from contextlib import contextmanager, ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from .ledger import (LedgerError, MAX_FILE, ZERO, _pairs, canonical, public_id,
                     record_hash, verify_records)
from .retention import _locked, _read, _sync_directory

FORMAT = "wireledger.recovery-plan.v1"
_PENDING = re.compile(r"\.pending-recovery-[a-z0-9_]+\Z")
SCOPE = ("Explicit local recovery against selected retained claims only; incomplete syntax "
         "does not prove a crash, and consistency does not prove freshness or observer truth.")


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _existing_path(path):
    path = Path(path)
    if path.is_symlink():
        raise LedgerError("recovery paths must not be symlinks")
    return path.resolve(strict=True)


def _read_handle(handle):
    handle.seek(0)
    raw = handle.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        raise LedgerError("recovery input exceeds 32 MiB size limit")
    return raw


@contextmanager
def _inputs(ledger, stores, *, writable=False):
    ledger = _existing_path(ledger)
    stores = [_existing_path(store) for store in stores]
    if not 1 <= len(stores) <= 16:
        raise LedgerError("recovery requires 1 to 16 explicitly selected checkpoint stores")
    identities = [(path.stat().st_dev, path.stat().st_ino) for path in stores]
    if len(set(identities)) != len(stores):
        raise LedgerError("duplicate or aliased checkpoint stores are not allowed")
    stores.sort(key=str)
    fd = os.open(ledger, (os.O_RDWR if writable else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "r+b" if writable else "rb") as handle, ExitStack() as stack:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise LedgerError("ledger must be a regular file")
        fcntl.flock(handle, fcntl.LOCK_EX)
        if (ledger.stat().st_dev, ledger.stat().st_ino) != (os.fstat(fd).st_dev, os.fstat(fd).st_ino):
            raise LedgerError("ledger path changed while acquiring its writer lock")
        protected_inodes = {(os.fstat(fd).st_dev, os.fstat(fd).st_ino)}
        for store in stores:
            stack.enter_context(_locked(store, protected_inodes=protected_inodes))
        yield ledger, handle, stores


def _reject_duplicate_prefix_keys(text):
    """Inspect complete keys even when json's object hook never sees a closing }.

    Called only after the decoder has recognized a syntactically incomplete
    prefix. String decoding handles escaped-equivalent keys; separate nested
    objects have separate sets. An unfinished final string cannot establish a key.
    """
    decoder = json.JSONDecoder()
    stack, index = [], 0
    while index < len(text):
        character = text[index]
        if character == '{':
            stack.append({"keys": set(), "key_expected": True})
        elif character == '[':
            stack.append(None)
        elif character in '}]':
            stack.pop()
        elif character == ',' and stack and stack[-1] is not None:
            stack[-1]["key_expected"] = True
        elif character == '"':
            try:
                value, end = decoder.raw_decode(text, index)
            except json.JSONDecodeError:
                return  # The already-classified terminal unfinished string.
            if stack and stack[-1] is not None and stack[-1]["key_expected"]:
                current = stack[-1]
                if value in current["keys"]:
                    raise LedgerError("duplicate JSON key in incomplete final fragment")
                current["keys"].add(value)
                current["key_expected"] = False
            index = end
            continue
        index += 1


def _candidate(raw, key):
    if not raw or raw.endswith(b"\n"):
        raise LedgerError("no unterminated final record; ordinary verification is required")
    split = raw.rfind(b"\n") + 1
    prefix, tail = raw[:split], raw[split:]
    records = verify_records(prefix, key)  # Corruption in any complete record is never removed.
    if not tail.startswith(b"{"):
        raise LedgerError("final fragment is not an unambiguous JSON object prefix")
    try:
        text = tail.decode("ascii")
        json.loads(text, object_pairs_hook=_pairs,
                   parse_constant=lambda _: (_ for _ in ()).throw(LedgerError("nonfinite JSON")))
    except UnicodeError as exc:
        raise LedgerError("non-ASCII final fragment is not eligible for recovery") from exc
    except json.JSONDecodeError as exc:
        # Deliberately conservative. Incomplete literals/numeric exponents and
        # Unicode escape sequences are refused rather than guessed at.
        incomplete = (exc.msg.startswith("Unterminated string starting at") or
                      (exc.pos == len(text) and exc.msg in {
                          "Expecting value", "Expecting ',' delimiter",
                          "Expecting property name enclosed in double quotes", "Expecting ':' delimiter"}))
        if not incomplete:
            raise LedgerError("malformed or ambiguous final JSON; recovery refused") from exc
        _reject_duplicate_prefix_keys(text)
        repaired, action = prefix, "truncate-incomplete-tail"
    else:
        # Complete JSON is never discarded, even when its signature/shape fails.
        repaired, action = raw + b"\n", "append-missing-newline"
    if len(repaired) > MAX_FILE:
        raise LedgerError("recovered history would exceed the size limit")
    if action == "append-missing-newline":
        records = verify_records(repaired, key)
    return repaired, records, action


def _plan(ledger, raw, key, stores):
    repaired, records, action = _candidate(raw, key)
    selected = []
    for store in stores:
        checkpoints = _read(store, key)
        if not checkpoints:
            raise LedgerError("every selected checkpoint store must contain retained claims")
        claims = []
        for checkpoint in checkpoints:
            body = checkpoint["body"]
            count = body["count"]
            if count > len(records):
                raise LedgerError("recovery would be shorter than a retained checkpoint")
            head = record_hash(records[count - 1]) if count else ZERO
            if head != body["head"]:
                raise LedgerError("recovery conflicts with a retained checkpoint")
            claims.append({"count": count, "head": head, "sha256": _digest(canonical(checkpoint))})
        selected.append({"directory": str(store), "claims": claims})
    plan = {"format": FORMAT, "ledger": str(ledger), "witness": public_id(key),
            "original_sha256": _digest(raw), "original_bytes": len(raw),
            "recovered_sha256": _digest(repaired), "recovered_bytes": len(repaired),
            "action": action, "removed_bytes": max(0, len(raw) - len(repaired)),
            "added_bytes": max(0, len(repaired) - len(raw)),
            "verified_count": len(records), "verified_head": record_hash(records[-1]) if records else ZERO,
            "selected_stores": selected, "scope": SCOPE}
    return plan, repaired


def recovery_preview(ledger, key, stores):
    """Return a byte- and trust-bound plan without changing ledger/evidence bytes."""
    with _inputs(ledger, stores) as (ledger, handle, stores):
        plan, _ = _plan(ledger, _read_handle(handle), key, stores)
        return plan


def _evidence_path(evidence, ledger, stores, plan_path):
    evidence = Path(evidence)
    if evidence.is_symlink():
        raise LedgerError("recovery evidence directory must not be a symlink")
    evidence = evidence.resolve()
    if evidence == ledger or ledger.is_relative_to(evidence):
        raise LedgerError("recovery evidence must be separate from the ledger")
    if plan_path is not None:
        source_plan = _existing_path(plan_path)
        if source_plan == evidence or source_plan.is_relative_to(evidence):
            raise LedgerError("recovery evidence must be separate from the input plan")
    for store in stores:
        if evidence.is_relative_to(store) or store.is_relative_to(evidence):
            raise LedgerError("recovery evidence and checkpoint stores must be separate directories")
    return evidence


def _check_evidence(directory, ledger, plan_path):
    if directory.is_symlink() or not directory.is_dir():
        raise LedgerError("recovery evidence must be a non-symlink directory")
    protected = [ledger] + ([Path(plan_path)] if plan_path is not None else [])
    identities = {(p.stat().st_dev, p.stat().st_ino) for p in protected}
    with os.scandir(directory) as entries:
        pending = 0
        for entry in entries:
            if entry.name not in {"original.jsonl", "plan.json"} and not _PENDING.fullmatch(entry.name):
                raise LedgerError("unexpected entry in recovery evidence; refusing to overwrite")
            if not entry.is_file(follow_symlinks=False):
                raise LedgerError("recovery evidence contains a non-regular file")
            info = entry.stat(follow_symlinks=False)
            if (info.st_dev, info.st_ino) in identities:
                raise LedgerError("recovery evidence aliases the ledger or input plan")
            pending += bool(_PENDING.fullmatch(entry.name))
            if pending > 1024:
                raise LedgerError("too many incomplete recovery evidence files")


def _read_evidence(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise LedgerError("recovery evidence must be a regular file")
        return _read_handle(handle)


def _publish(directory, name, raw):
    destination = directory / name
    try:
        existing = _read_evidence(destination)
    except FileNotFoundError:
        fd, temporary = tempfile.mkstemp(prefix=".pending-recovery-", dir=directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, destination, follow_symlinks=False)
            except FileExistsError:
                if _read_evidence(destination) != raw:
                    raise LedgerError("existing recovery evidence disagrees; never overwritten")
        finally:
            Path(temporary).unlink(missing_ok=True)
    else:
        if existing != raw:
            raise LedgerError("existing recovery evidence disagrees; never overwritten")
    # Retry uncertain publication by syncing the actual published inode as well.
    fd = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def recovery_apply(ledger, key, stores, plan, evidence, *, plan_path=None):
    """Apply only a recomputed, exact plan; preserve original bytes before mutation.

If the final sync fails, the caller must treat durability as uncertain. The same
plan can be retried while the ledger and selected retained claims stay unchanged.
"""
    if not isinstance(plan, dict) or plan.get("format") != FORMAT:
        raise LedgerError("invalid recovery plan")
    with _inputs(ledger, stores, writable=True) as (ledger, handle, stores):
        evidence = _evidence_path(evidence, ledger, stores, plan_path)
        current = _read_handle(handle)
        already_recovered = _digest(current) == plan.get("recovered_sha256")
        if already_recovered:
            _check_evidence(evidence, ledger, plan_path)
            original = _read_evidence(evidence / "original.jsonl")
        elif _digest(current) == plan.get("original_sha256"):
            original = current
        else:
            raise LedgerError("ledger bytes differ from the reviewed recovery plan")
        expected, repaired = _plan(ledger, original, key, stores)
        if canonical(plan) != canonical(expected):
            raise LedgerError("reviewed recovery plan or selected checkpoint claims changed")
        if already_recovered and current != repaired:
            raise LedgerError("recovered bytes do not match the reviewed plan")
        evidence.mkdir(mode=0o700, exist_ok=True)
        _check_evidence(evidence, ledger, plan_path)
        _publish(evidence, "original.jsonl", original)  # A byte copy, never a link to the ledger.
        _publish(evidence, "plan.json", canonical(plan) + b"\n")
        _sync_directory(evidence)
        _sync_directory(evidence.parent)
        # All original/evidence directory barriers precede the first ledger write.
        try:
            if not already_recovered:
                if plan["action"] == "truncate-incomplete-tail":
                    os.ftruncate(handle.fileno(), len(repaired))
                else:
                    handle.seek(0, os.SEEK_END)
                    if handle.write(b"\n") != 1:
                        raise OSError("missing-newline recovery write was incomplete")
                    handle.flush()
            os.fsync(handle.fileno())
            _sync_directory(ledger.parent)
        except OSError as exc:
            raise LedgerError("recovery write/sync outcome is uncertain; preserve evidence and retry the exact plan") from exc
        if _read_handle(handle) != repaired:
            raise LedgerError("ledger changed during recovery; durability is uncertain")
        return {"recovered": True, "already_recovered": already_recovered,
                "action": plan["action"], "count": plan["verified_count"],
                "head": plan["verified_head"], "original_sha256": plan["original_sha256"],
                "recovered_sha256": plan["recovered_sha256"], "evidence": str(evidence), "scope": SCOPE}
