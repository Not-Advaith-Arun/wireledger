import argparse
import json
import sys
from pathlib import Path

from .ledger import (append, canonical, compare_checkpoints, compare_verified_histories, exclusive_write, initialize,
                     load_private, load_public, make_checkpoint, public_id, read_checkpoint,
                     record_hash, verify, ZERO)
from .probe import changes, compare, observe
from .evidence import audit, load_trust
from .timeline import render_timeline, timeline


def main(argv=None):
    parser = argparse.ArgumentParser(description="Signed, locally verifiable TLS observation histories")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="create a new local witness, refusing existing directories")
    init.add_argument("directory", type=Path)
    probe = sub.add_parser("observe", help="perform one verified TLS handshake and append its observation")
    probe.add_argument("directory", type=Path)
    probe.add_argument("host")
    probe.add_argument("--port", type=int, default=443)
    probe.add_argument("--connect-ip")
    probe.add_argument("--ca-file")
    probe.add_argument("--vantage", default="local")
    probe.add_argument("--timeout", type=float, default=5,
                       help="total DNS/TCP/TLS network budget in seconds (0 < value <= 60)")
    for command in ("verify", "report", "timeline"):
        check = sub.add_parser(command)
        check.add_argument("ledger", type=Path)
        check.add_argument("--public-key", type=Path, required=True, help="independently trusted witness public key")
        check.add_argument("--checkpoint", type=Path)
        if command == "timeline":
            check.add_argument("--at-observed-time", action="store_true")
            output = check.add_mutually_exclusive_group()
            output.add_argument("--json", action="store_true", help="emit structured timeline data")
            output.add_argument("--html", action="store_true", help="emit a static local review, excluding signing keys/certificate bodies")
            check.add_argument("--max-rows", type=int, default=200, help="HTML display budget, latest 1..1000 selected samples")
            check.add_argument("--host", help="exact endpoint hostname")
            check.add_argument("--port", type=int)
            check.add_argument("--vantage", help="exact observer vantage label")
            check.add_argument("--since", help="inclusive observer timestamp with timezone")
            check.add_argument("--until", help="inclusive observer timestamp with timezone")
            check.add_argument("--changes-only", action="store_true", help="omit unchanged samples while retaining full-history change context")
            check.add_argument("--after-sequence", type=int, default=0, help="return matching samples strictly after this signed sequence")
            check.add_argument("--limit", type=int, help="return at most 1..1000 matching samples; full history is still verified")
    sampling = sub.add_parser("continuity", help="Report observer-clock sampling gaps, stale samples and clock reversals")
    sampling.add_argument("ledger", type=Path)
    sampling.add_argument("--public-key", type=Path, required=True)
    sampling.add_argument("--checkpoint", type=Path)
    sampling.add_argument("--as-of", required=True, help="Explicit timezone-aware comparison time")
    sampling.add_argument("--max-gap-seconds", type=float, default=86400)
    coverage = sub.add_parser("coverage", help="Compare signed observations with an explicit expected endpoint/vantage manifest")
    coverage.add_argument("ledger", type=Path)
    coverage.add_argument("--public-key", type=Path, required=True)
    coverage.add_argument("--checkpoint", type=Path)
    coverage.add_argument("--expected", type=Path, required=True, help="JSON array of host/port/vantage objects; no network calls")
    inventory = sub.add_parser("endpoints", help="Inventory signed endpoint/vantage collection and latest status")
    inventory.add_argument("ledger", type=Path)
    inventory.add_argument("--public-key", type=Path, required=True)
    inventory.add_argument("--checkpoint", type=Path)
    reuse = sub.add_parser("fingerprint-reuse", help="Inspect shared latest certificate/key fingerprints across distinct endpoints")
    reuse.add_argument("ledger", type=Path)
    reuse.add_argument("--public-key", type=Path, required=True)
    reuse.add_argument("--checkpoint", type=Path)
    expiration = sub.add_parser("expiry", help="Inspect latest signed-sequence certificate expiry horizons without network access")
    expiration.add_argument("ledger", type=Path)
    expiration.add_argument("--public-key", type=Path, required=True)
    expiration.add_argument("--checkpoint", type=Path)
    expiration.add_argument("--as-of", required=True)
    expiration.add_argument("--within-days", type=float, default=30)
    expiration.add_argument("--max-age-seconds", type=float, default=86400)
    views = sub.add_parser("vantages", help="Compare latest signed-sequence views across recorded vantage labels")
    views.add_argument("ledger", type=Path)
    views.add_argument("--public-key", type=Path, required=True)
    views.add_argument("--checkpoint", type=Path)
    views.add_argument("--max-pairs", type=int, default=1000, help="Global pair-comparison budget, 1..10000")
    evidence = sub.add_parser("audit", help="verify signatures and independently audit captured certificates offline")
    evidence.add_argument("ledger", type=Path)
    evidence.add_argument("--public-key", type=Path, required=True)
    evidence.add_argument("--checkpoint", type=Path)
    evidence.add_argument("--ca-file", type=Path, required=True, help="independently trusted PEM CA bundle, never taken from the ledger")
    evidence.add_argument("--at-observed-time", action="store_true", help="use the signed observer-asserted time instead of current time")
    checkpoint = sub.add_parser("checkpoint", help="sign current head; keep a copy outside the witness directory")
    checkpoint.add_argument("directory", type=Path)
    checkpoint.add_argument("output", type=Path)
    comparison = sub.add_parser("compare", help="compare two histories after verifying each witness signature")
    comparison.add_argument("left", type=Path)
    comparison.add_argument("right", type=Path)
    comparison.add_argument("--left-key", type=Path, required=True)
    comparison.add_argument("--right-key", type=Path, required=True)
    comparison.add_argument("--left-checkpoint", type=Path)
    comparison.add_argument("--right-checkpoint", type=Path)
    anchors = sub.add_parser("compare-checkpoints", help="verify and compare two signed checkpoint claims")
    anchors.add_argument("left", type=Path)
    anchors.add_argument("right", type=Path)
    anchors.add_argument("--left-key", type=Path, required=True)
    anchors.add_argument("--right-key", type=Path, required=True)
    retain = sub.add_parser("retain-checkpoint", help="keep an authenticated checkpoint in an independent local directory")
    retain.add_argument("checkpoint", type=Path)
    retain.add_argument("--store", type=Path, required=True)
    retain.add_argument("--public-key", type=Path, required=True)
    retained = sub.add_parser("check-retained", help="check a signed history against every independently retained checkpoint")
    retained.add_argument("ledger", type=Path)
    retained.add_argument("--store", type=Path, required=True)
    retained.add_argument("--public-key", type=Path, required=True)
    inventory = sub.add_parser("list-retained", help="Inspect pinned signed checkpoint claims without an observation history")
    inventory.add_argument("--store", type=Path, required=True)
    inventory.add_argument("--public-key", type=Path, required=True)
    for command in ("recovery-preview", "recovery-apply"):
        recovery = sub.add_parser(command, help="explicit checkpoint-constrained recovery of an interrupted final append")
        recovery.add_argument("ledger", type=Path)
        recovery.add_argument("--public-key", type=Path, required=True, help="independently trusted witness public key")
        recovery.add_argument("--store", type=Path, action="append", required=True,
                              help="selected retained checkpoint store; repeat to check all selected stores")
        if command == "recovery-apply":
            recovery.add_argument("--plan", type=Path, required=True, help="previously reviewed recovery-preview JSON")
            recovery.add_argument("--evidence", type=Path, required=True, help="separate directory for exclusive original-byte evidence")
    sub.add_parser("demo", help="loopback-only certificate rotation and tamper detection demonstration")
    args = parser.parse_args(argv)
    try:
        code = 0
        if args.command == "init":
            result = initialize(args.directory)
        elif args.command == "observe":
            key = load_private(args.directory / "witness.key")
            observation = observe(args.host, args.port, connect_ip=args.connect_ip,
                                  cafile=args.ca_file, vantage=args.vantage, timeout=args.timeout)
            record = append(args.directory / "observations.jsonl", key, observation)
            result = {"sequence": record["body"]["sequence"], "observation": observation}
            code = 0 if observation["status"] == "verified" else 2
        elif args.command == "checkpoint":
            key = load_private(args.directory / "witness.key")
            records = verify(args.directory / "observations.jsonl", key.public_key())
            result = make_checkpoint(records, key)
            exclusive_write(args.output, canonical(result) + b"\n", 0o644)
        elif args.command == "demo":
            from .lab import demo
            result = demo()
        elif args.command == "audit":
            key = load_public(args.public_key)
            checkpoint_data = read_checkpoint(args.checkpoint) if args.checkpoint else None
            records = verify(args.ledger, key, checkpoint_data)
            result = audit(records, load_trust(args.ca_file), at_observed_time=args.at_observed_time)
            code = 0 if result["ok"] else 2
        elif args.command == "compare-checkpoints":
            result = compare_checkpoints(read_checkpoint(args.left), read_checkpoint(args.right),
                                         load_public(args.left_key), load_public(args.right_key))
            code = 2 if result["relation"] == "conflicting-heads" else 0
        elif args.command == "retain-checkpoint":
            from .retention import retain_checkpoint
            result = retain_checkpoint(args.store, read_checkpoint(args.checkpoint), load_public(args.public_key))
            code = 2 if result["conflicting_heads"] else 0
        elif args.command == "check-retained":
            from .retention import check_retained_history
            result = check_retained_history(args.store, args.ledger, load_public(args.public_key))
            code = 0 if result["ok"] else 2
        elif args.command == "list-retained":
            from .retention import list_retained
            result = list_retained(args.store, load_public(args.public_key))
            code = 2 if result["conflicting_heads"] else 0
        elif args.command == "recovery-preview":
            from .recovery import recovery_preview
            result = recovery_preview(args.ledger, load_public(args.public_key), args.store)
        elif args.command == "recovery-apply":
            from .ledger import _read, parse
            from .recovery import recovery_apply
            result = recovery_apply(args.ledger, load_public(args.public_key), args.store,
                                    parse(_read(args.plan)), args.evidence, plan_path=args.plan)
        elif args.command == "compare":
            histories, keys = [], []
            for name in ("left", "right"):
                anchor = getattr(args, name + "_checkpoint")
                keys.append(load_public(getattr(args, name + "_key")))
                histories.append(verify(getattr(args, name), keys[-1],
                                        read_checkpoint(anchor) if anchor else None))
            result = {"comparisons": compare(*histories),
                      "history": compare_verified_histories(*histories, *keys),
                      "scope": "Latest samples per endpoint; sampling times and vantages can differ. Differences are not attack verdicts."}
            code = 2 if result["history"]["relation"] == "divergent" else 0
        else:
            key = load_public(args.public_key)
            checkpoint_data = read_checkpoint(args.checkpoint) if args.checkpoint else None
            records = verify(args.ledger, key, checkpoint_data)
            result = {"valid": True, "count": len(records), "witness": public_id(key),
                      "head": record_hash(records[-1]) if records else ZERO,
                      "checkpoint_checked": bool(args.checkpoint),
                      "scope": "authenticity and chain consistency; observer truth is not proven"}
            if args.command == "coverage":
                from .inventory import collection_coverage
                from .ledger import _read, parse
                result = collection_coverage(records, parse(_read(args.expected)))
                code = 2 if result["needs_attention"] else 0
            elif args.command == "endpoints":
                from .inventory import endpoint_inventory
                result = endpoint_inventory(records)
            elif args.command == "fingerprint-reuse":
                from .reuse import fingerprint_reuse
                result = fingerprint_reuse(records)
            elif args.command == "expiry":
                from .expiry import expiry
                result = expiry(records, as_of=args.as_of, within_days=args.within_days, max_age_seconds=args.max_age_seconds)
                code = 2 if result["needs_attention"] else 0
            elif args.command == "vantages":
                from .vantages import compare_vantages
                result = compare_vantages(records, max_pairs=args.max_pairs)
                code = 0 if result["comparisons_complete"] else 2
            elif args.command == "continuity":
                from .continuity import continuity
                result = continuity(records, as_of=args.as_of, max_gap_seconds=args.max_gap_seconds)
                code = 2 if result["needs_attention"] else 0
            elif args.command == "report":
                result["events"] = changes(records)
            elif args.command == "timeline":
                result = timeline(records, at_observed_time=args.at_observed_time, host=args.host,
                                  port=args.port, vantage=args.vantage, since=args.since,
                                  until=args.until, changes_only=args.changes_only,
                                  after_sequence=args.after_sequence, limit=args.limit)
                if args.html:
                    from .timeline_view import render_html
                    print(render_html(result, max_rows=args.max_rows))
                    return 0
                if not args.json:
                    print(render_timeline(result))
                    return 0
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return code
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
