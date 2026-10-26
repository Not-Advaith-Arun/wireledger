"""Bounded, independently retained public checkpoints. No transport or freshness."""

from contextlib import contextmanager, nullcontext
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile

from .ledger import (LedgerError, ZERO, canonical, compare_checkpoints, public_id,
                     read_checkpoint, record_hash, verify, verify_checkpoint)

MAX_CHECKPOINTS = 1024
_NAME = re.compile(r"anchor-([0-9a-f]{64})\.json\Z")
_PENDING = re.compile(r"\.pending-anchor-[a-z0-9_]+\Z")
_LOCK = ".wireledger-checkpoints.lock"


def _sync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def _locked(directory, *, create=False, protected_inodes=None):
    directory = Path(directory)
    if create:
        directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink() or not directory.is_dir():
        raise LedgerError("checkpoint store must be a non-symlink directory")
    fd = os.open(directory / _LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a+b") as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise LedgerError("checkpoint lock must be a regular file")
        if protected_inodes is not None:
            identity = (info.st_dev, info.st_ino)
            if identity in protected_inodes or info.st_nlink != 1:
                raise LedgerError("checkpoint lock aliases another protected inode")
            protected_inodes.add(identity)
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield directory


def _read(directory, key):
    checkpoints = []
    # Iterate with an explicit bound rather than reading an unlimited directory.
    with os.scandir(directory) as entries:
        pending = 0
        for entry in entries:
            if entry.name == _LOCK:
                continue
            if _PENDING.fullmatch(entry.name):
                pending += 1
                if pending > MAX_CHECKPOINTS or not entry.is_file(follow_symlinks=False):
                    raise LedgerError("invalid or excessive incomplete checkpoint writes")
                continue
            match = _NAME.fullmatch(entry.name)
            if match is None or not entry.is_file(follow_symlinks=False):
                raise LedgerError("unexpected entry in checkpoint store")
            if len(checkpoints) >= MAX_CHECKPOINTS:
                raise LedgerError("checkpoint store exceeds 1024 claims")
            checkpoint = read_checkpoint(entry.path)
            verify_checkpoint(checkpoint, key)
            if hashlib.sha256(canonical(checkpoint["body"])).hexdigest() != match[1]:
                raise LedgerError("checkpoint filename disagrees with signed content")
            checkpoints.append(checkpoint)
    return sorted(checkpoints, key=lambda item: (item["body"]["count"], item["body"]["head"]))



def _publish_claim(directory, name, encoded, duplicate):
    destination = directory / name
    if not duplicate:
        fd, temporary = tempfile.mkstemp(prefix=".pending-anchor-", dir=directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary, destination, follow_symlinks=False)
        finally:
            Path(temporary).unlink(missing_ok=True)
    else:
        fd = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    _sync_directory(directory)
    _sync_directory(directory.parent)


def retain_checkpoint(directory, checkpoint, key):
    """Retain one authenticated claim, including a conflicting signed claim."""
    body = verify_checkpoint(checkpoint, key)  # fail before any filesystem mutation
    encoded = canonical(checkpoint)
    name = "anchor-" + hashlib.sha256(canonical(body)).hexdigest() + ".json"
    with _locked(directory, create=True) as directory:
        checkpoints = _read(directory, key)
        relations = [compare_checkpoints(existing, checkpoint, key, key)["relation"]
                     for existing in checkpoints]
        destination = directory / name
        duplicate = "identical" in relations
        if not duplicate and len(checkpoints) >= MAX_CHECKPOINTS:
            raise LedgerError("checkpoint store is full; existing claims are preserved")
        _publish_claim(directory, name, encoded, duplicate)
        return {"retained": True, "already_retained": duplicate,
                "witness": body["witness"], "count": len(checkpoints) + (not duplicate),
                "checkpoint_file": str(destination),
                "conflicting_heads": "conflicting-heads" in relations,
                "ancestry_unproven": "ancestry-unproven" in relations,
                "scope": "Locally retained signed claims. Store rollback, freshness and observer truth are not established."}


def check_retained_history(directory, ledger, key):
    """Authenticate a history, then compare every retained signed prefix claim."""
    return _check_retained_records(directory, verify(ledger, key), key)


def export_bundle(directory, key, *, counts=None):
    """Export all claims or explicit record counts, keeping every conflicting head.

    The unsigned bundle container never establishes completeness of its source store.
    Every retained signature is checked even when only some counts are exported.
    """
    if counts is not None and (not isinstance(counts,list) or not 1<=len(counts)<=MAX_CHECKPOINTS or
            any(type(count)is not int or count<0 for count in counts) or len(set(counts))!=len(counts)):
        raise LedgerError("select1..1024 distinct nonnegative retained record counts")
    with _locked(directory) as directory:
        checkpoints = _read(directory, key)
    if not checkpoints:
        raise LedgerError("no retained claims to export")
    if counts is not None:
        if set(counts)-{cp["body"]["count"]for cp in checkpoints}:
            raise LedgerError("selected record count has no retained claim; no partial bundle exported")
        checkpoints=[cp for cp in checkpoints if cp["body"]["count"]in counts]
    return {"format": "wireledger.checkpoint-bundle.v1", "witness": public_id(key), "checkpoints": checkpoints}


def _bundle_claims(bundle, key):
    if (not isinstance(bundle, dict) or set(bundle) != {"format", "witness", "checkpoints"}
            or bundle["format"] != "wireledger.checkpoint-bundle.v1" or bundle["witness"] != public_id(key)):
        raise LedgerError("bundle must match the independently supplied public key and supported format")
    incoming = bundle["checkpoints"]
    if not isinstance(incoming, list) or not 1 <= len(incoming) <= MAX_CHECKPOINTS:
        raise LedgerError("bundle requires 1..1024 signed checkpoints")
    prepared = {}
    for checkpoint in incoming:
        body = verify_checkpoint(checkpoint, key)
        name = "anchor-" + hashlib.sha256(canonical(body)).hexdigest() + ".json"
        if name in prepared:
            raise LedgerError("bundle contains a duplicate checkpoint claim")
        prepared[name] = checkpoint
    return prepared


def inspect_bundle(bundle, key):
    """Authenticate every detached claim without a destination or history read."""
    prepared=_bundle_claims(bundle,key)
    claims=[];heads={}
    for checkpoint in prepared.values():
        body=checkpoint["body"];heads.setdefault(body["count"],set()).add(body["head"])
        claims.append({"count":body["count"],"head":body["head"],"sha256":hashlib.sha256(canonical(checkpoint)).hexdigest()})
    return {"format":"wireledger.bundle-inspection.v1","witness":public_id(key),"claim_count":len(claims),"claims":claims,
        "conflicting_counts":sorted(count for count,values in heads.items()if len(values)>1),
        "scope":"Every detached claim signature checked against the independently supplied public key. No destination, retained store or ledger history read or changed. The bundle container is unsigned: no origin completeness/authenticity, custody, ancestry, freshness, rollback detection or observer truth established. Same-count conflicting heads need attention; unequal counts do not establish extension."}


def retain_bundle(directory, bundle, key, *, preview=False):
    prepared=_bundle_claims(bundle,key)
    incoming=list(prepared.values())
    directory = Path(directory)
    absent = preview and not directory.exists() and not directory.is_symlink()
    with (nullcontext(directory) if absent else _locked(directory, create=not preview)) as directory:
        existing = [] if absent else _read(directory, key)
        names = {"anchor-" + hashlib.sha256(canonical(cp["body"])).hexdigest() + ".json" for cp in existing}
        added = len(set(prepared) - names)
        if len(existing) + added > MAX_CHECKPOINTS:
            raise LedgerError("bundle exceeds remaining checkpoint store capacity; existing claims preserved")
        if not preview:
            for name, checkpoint in prepared.items():
                _publish_claim(directory, name, canonical(checkpoint), name in names)
        heads = {}
        for checkpoint in existing + incoming:
            body = checkpoint["body"]
            heads.setdefault(body["count"], set()).add(body["head"])
    return {"retained": not preview, "preview": preview, "witness": public_id(key), "imported_claims": len(incoming),
            "added_claims": added, "already_retained_claims": len(incoming) - added,
            "total_claims": len(existing) + added, "conflicting_heads": any(len(h) > 1 for h in heads.values()),
            "scope": (("Preview only: no claims published or destination created. Existing store locking may create its lock file. Counts/conflicts describe the checked snapshot, not a reservation or authorization; a later import revalidates everything and may differ. " if preview else "") + "Every incoming/existing signature and capacity checked before claim publication against your supplied key. Each claim publishes atomically; the bundle is not a transaction. I/O failure may leave a valid partial subset: preserve the store and retry the exact bundle. Signed conflicts retained, never overwritten. Selected bundles do not establish completeness of the origin store. No bundle authenticity, independent custody, ancestry, freshness or observer truth established.")}


def _check_retained_records(directory, records, key):
    with _locked(directory) as directory:
        checkpoints = _read(directory, key)
    if not checkpoints:
        raise LedgerError("checkpoint store contains no retained claims")
    results = []
    for checkpoint in checkpoints:
        body = checkpoint["body"]
        count = body["count"]
        if count > len(records):
            relation = "shorter-than-retained"
        else:
            head = record_hash(records[count - 1]) if count else ZERO
            relation = "consistent-prefix" if head == body["head"] else "divergent"
        results.append({"count": count, "head": body["head"], "relation": relation})
    return {"ok": all(row["relation"] == "consistent-prefix" for row in results),
            "witness": public_id(key), "history_count": len(records), "checkpoints": results,
            "scope": "Authenticated history against locally retained claims; consistency does not prove freshness or truthful observations."}


def list_retained(directory, key):
    """Inspect authenticated retained claims without needing an observer history."""
    with _locked(directory) as directory:
        checkpoints = _read(directory, key)
    heads = {}
    for checkpoint in checkpoints:
        body = checkpoint["body"]
        heads.setdefault(body["count"], set()).add(body["head"])
    conflicts = [{"count": count, "heads": sorted(values)} for count, values in sorted(heads.items())
                 if len(values) > 1]
    return {"witness": public_id(key), "count": len(checkpoints),
            "checkpoints": [checkpoint["body"] for checkpoint in checkpoints],
            "conflicting_heads": conflicts,
            "ancestry_unproven": len(heads) > 1,
            "scope": "Signatures checked against independently supplied public key. Different counts do not prove ancestry; no history, freshness or store rollback check is performed."}


def compare_retained(left, right, key):
    """Compare two authenticated claim sets; never infer history ancestry."""
    one, two = list_retained(left, key), list_retained(right, key)
    claims = [{(row["count"], row["head"]) for row in report["checkpoints"]} for report in (one, two)]
    a, b = claims
    combined = a | b
    counts = {}
    for count, head in combined:
        counts.setdefault(count, set()).add(head)
    conflicts = [{"count": count, "heads": sorted(heads)} for count, heads in sorted(counts.items()) if len(heads) > 1]
    def rows(values):
        return [{"count": count, "head": head} for count, head in sorted(values)]
    return {"witness": one["witness"], "left_count": len(a), "right_count": len(b),
            "identical_claim_sets": a == b, "shared": rows(a & b),
            "only_left": rows(a - b), "only_right": rows(b - a), "conflicting_heads": conflicts,
            "ancestry_unproven": len(counts) > 1,
            "needs_attention": not combined or a != b or bool(conflicts),
            "scope": "Each store authenticated under the same explicitly supplied public key, read separately under its lock. Claim-set equality/differences and same-count conflicts only. Different counts do not prove prefix ancestry. No history, freshness, store rollback, cross-store snapshot transaction, copying or merging established. Empty stores establish no retained evidence."}


def check_retained_stores(directories, ledger, key):
    """Check one authenticated history snapshot against every selected store."""
    if not isinstance(directories, (list, tuple)) or not 1 <= len(directories) <= 16:
        raise LedgerError("select 1..16 retained stores")
    resolved = [Path(directory).resolve() for directory in directories]
    if len(set(resolved)) != len(resolved):
        raise LedgerError("selected retained stores must be distinct directories")
    records = verify(ledger, key)
    reports = [{"store_index": index, **_check_retained_records(directory, records, key)}
               for index, directory in enumerate(directories, 1)]
    return {"ok": all(report["ok"] for report in reports), "witness": public_id(key),
            "history_count": len(records), "stores": reports,
            "scope": "One authenticated history snapshot checked against all selected locally retained claims. Stores read separately under their own locks; no cross-store snapshot transaction, independent custody, store rollback, freshness or observer-truth proof."}


def compare_bundles(left, right, key):
    """Compare authenticated detached claim sets; never infer prefix ancestry."""
    a=inspect_bundle(left,key);b=inspect_bundle(right,key)
    first={(c['count'],c['head']):c for c in a['claims']}
    second={(c['count'],c['head']):c for c in b['claims']}
    heads={}
    for count,head in first.keys()|second.keys():heads.setdefault(count,set()).add(head)
    return {'format':'wireledger.bundle-comparison.v1','witness':public_id(key),
            'left_claim_count':len(first),'right_claim_count':len(second),
            'shared_claim_count':len(first.keys()&second.keys()),
            'claims':[{'count':count,'head':head,'membership':'both'if(count,head)in first and(count,head)in second else'left_only'if(count,head)in first else'right_only'}for count,head in sorted(first.keys()|second.keys())],
            'conflicting_counts':sorted(count for count,values in heads.items()if len(values)>1),
            'scope':'All claims from both detached bundles authenticated with the independently supplied common public key. Membership describes count/head identity only, not ledger ancestry. Bundle containers are unsigned; omissions are not lost history or proof of withholding. No destination/store/history reads, imports, merge, completeness, custody, freshness or observer-truth guarantee.'}


def extract_checkpoint(bundle,key,*,count,head=None):
    """Export one explicit authenticated claim without rewriting its signature."""
    if type(count)is not int or count<0:
        raise LedgerError('select a nonnegative signed record count')
    if head is not None and not isinstance(head,str):
        raise LedgerError('checkpoint head must be text')
    # Authenticate the entire supplied bundle, even unselected claims.
    prepared=_bundle_claims(bundle,key)
    selected=[checkpoint for checkpoint in prepared.values()if checkpoint['body']['count']==count and(head is None or checkpoint['body']['head']==head)]
    if len(selected)!=1:
        raise LedgerError('selection must identify exactly one supplied claim; use an explicit --head to disambiguate conflicts')
    return selected[0]


def select_bundle(bundle, key, *, counts):
    """Narrow detached claims by count, preserving all same-count conflicts."""
    if (not isinstance(counts,list) or not 1<=len(counts)<=MAX_CHECKPOINTS
            or any(type(count)is not int or count<0 for count in counts)
            or len(set(counts))!=len(counts)):
        raise LedgerError('select1..1024 distinct nonnegative signed record counts')
    prepared=_bundle_claims(bundle,key)
    available={checkpoint['body']['count']for checkpoint in prepared.values()}
    if set(counts)-available:
        raise LedgerError('selected record count has no supplied signed claim; no partial bundle exported')
    return {'format':'wireledger.checkpoint-bundle.v1','witness':public_id(key),
            'checkpoints':[checkpoint for checkpoint in prepared.values()if checkpoint['body']['count']in counts]}
