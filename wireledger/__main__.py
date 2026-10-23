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
    from .showcase import arguments as showcase_arguments
    showcase_arguments(sub.add_parser("showcase", help="generate an interactive offline product sample"))
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
    collection = sub.add_parser("observe-policy", help="Collect each explicit endpoint/vantage once, sequentially, retaining signed failures; at most16 rows")
    collection.add_argument("directory", type=Path)
    collection.add_argument("--preview",action="store_true",help="Normalize/validate policy and current public-key history without private-key access,network or append")
    collection.add_argument("--expected", type=Path, required=True)
    collection.add_argument("--connect-ip", help="Optional explicit connection address applied to every selected endpoint")
    collection.add_argument("--ca-file")
    collection.add_argument("--timeout", type=float, default=5, help="Per-endpoint network budget in seconds,0<value<=60; no whole-command deadline")
    for command in ("verify", "report", "timeline", "certificate-chain", "certificate-info", "failures"):
        check = sub.add_parser(command)
        check.add_argument("ledger", type=Path)
        check.add_argument("--public-key", type=Path, required=True, help="independently trusted witness public key")
        check.add_argument("--checkpoint", type=Path)
        if command == "certificate-info":
            check.add_argument("--sequence", type=int, required=True)
            check.add_argument("--index", type=int, default=1, help="One-based captured certificate index, leaf first")
        if command == "certificate-chain":
            check.add_argument("--sequence", type=int, required=True)
            check.add_argument("--json", action="store_true", help="Include captured-chain metadata/scope; default emits public PEM certificates only")
        if command == "timeline":
            check.add_argument("--at-observed-time", action="store_true")
            output = check.add_mutually_exclusive_group()
            output.add_argument("--json", action="store_true", help="emit structured timeline data")
            output.add_argument("--html", action="store_true", help="emit a static local review, excluding signing keys/certificate bodies")
            output.add_argument("--csv", action="store_true", help="CSV page with literal-safe text and repeated page metadata; empty page has headers only, use JSON for full cursor/scope")
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
    coverage.add_argument("--after-sequence", type=int, default=0, help="Evaluate collection strictly after this signed sequence; full history still authenticated")
    coverage.add_argument("--attention-only", action="store_true", help="Omit expected groups whose latest sample is verified, keeping checked/omitted counts and unexpected groups")
    coverage.add_argument("--exact", action="store_true", help="Also require no endpoint/vantage groups outside the explicit expected manifest")
    inventory = sub.add_parser("endpoints", help="Inventory signed endpoint/vantage collection and latest status")
    inventory.add_argument("ledger", type=Path)
    inventory.add_argument("--public-key", type=Path, required=True)
    inventory.add_argument("--checkpoint", type=Path)
    inventory.add_argument("--host", help="Exact signed hostname, no normalization")
    inventory.add_argument("--vantage", help="Exact signed vantage label")
    inventory.add_argument("--failed-only", action="store_true", help="Only groups whose latest signed sequence reports failure")
    inventory.add_argument("--policy", action="store_true", help="Export unsigned endpoint/vantage policy candidate from observed groups; review intent before using with coverage/observe-policy")
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
    expiration.add_argument("--attention-only", action="store_true", help="Omit healthy expiry rows after full verification, retaining checked/omitted counts and overall attention status")
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
    inspect_checkpoint = sub.add_parser("inspect-checkpoint", help="Authenticate one checkpoint claim before choosing retention or history verification")
    inspect_checkpoint.add_argument("checkpoint", type=Path)
    inspect_checkpoint.add_argument("--public-key", type=Path, required=True)
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
    retained.add_argument("--store", type=Path, action="append", required=True, help="Retained checkpoint store; repeat to check all selected stores against one history snapshot")
    retained.add_argument("--public-key", type=Path, required=True)
    inventory = sub.add_parser("list-retained", help="Inspect pinned signed checkpoint claims without an observation history")
    inventory.add_argument("--store", type=Path, required=True)
    inventory.add_argument("--public-key", type=Path, required=True)
    stores = sub.add_parser("compare-retained", help="Compare two authenticated retained checkpoint stores without copying or merging")
    stores.add_argument("left", type=Path)
    stores.add_argument("right", type=Path)
    stores.add_argument("--public-key", type=Path, required=True)
    for name in ("export-retained", "import-retained"):
        bundle = sub.add_parser(name, help="Transfer signed retained claims; independently supplied key required, no custody/freshness guarantee")
        bundle.add_argument("--store", type=Path, required=True)
        bundle.add_argument("--public-key", type=Path, required=True)
        if name == "import-retained":
            bundle.add_argument("input", type=Path, help="Checkpoint bundle; all signatures checked before per-file publication")
            bundle.add_argument("--preview", action="store_true", help="Authenticate and report proposed claim counts/conflicts without publishing claims")
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
    if args.command == "showcase":
        from .showcase import generate
        return generate(args)
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
        elif args.command == "observe-policy":
            from .collection import observe_policy, preview_policy
            from .ledger import parse, _read
            operation = preview_policy if args.preview else observe_policy
            result = operation(args.directory, parse(_read(args.expected)), connect_ip=args.connect_ip,
                                    cafile=args.ca_file, timeout=args.timeout)
            code = 0 if args.preview or result["all_verified"] else 2
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
        elif args.command in ("export-retained", "import-retained"):
            from .retention import export_bundle, retain_bundle
            from .ledger import parse, _read
            key = load_public(args.public_key)
            result = (export_bundle(args.store, key) if args.command == "export-retained" else
                      retain_bundle(args.store, parse(_read(args.input)), key, preview=args.preview))
            code = 2 if result.get("conflicting_heads") else 0
        elif args.command == "compare-retained":
            from .retention import compare_retained
            result = compare_retained(args.left, args.right, load_public(args.public_key))
            code = 2 if result["needs_attention"] else 0
        elif args.command == "compare-checkpoints":
            result = compare_checkpoints(read_checkpoint(args.left), read_checkpoint(args.right),
                                         load_public(args.left_key), load_public(args.right_key))
            code = 2 if result["relation"] == "conflicting-heads" else 0
        elif args.command == "retain-checkpoint":
            from .retention import retain_checkpoint
            result = retain_checkpoint(args.store, read_checkpoint(args.checkpoint), load_public(args.public_key))
            code = 2 if result["conflicting_heads"] else 0
        elif args.command == "check-retained":
            from .retention import check_retained_history, check_retained_stores
            key = load_public(args.public_key)
            result = (check_retained_history(args.store[0], args.ledger, key) if len(args.store) == 1 else
                      check_retained_stores(args.store, args.ledger, key))
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
        elif args.command == "inspect-checkpoint":
            from .checkpoint_inspection import inspect_checkpoint
            result = inspect_checkpoint(args.checkpoint, load_public(args.public_key))
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
            if args.command == "failures":
                from .inventory import failure_streaks
                result = failure_streaks(records)
                code = 2 if result["needs_attention"] else 0
            elif args.command == "certificate-info":
                from .chain_export import certificate_info
                result = certificate_info(records,args.sequence,args.index)
            elif args.command == "certificate-chain":
                from .chain_export import certificate_chain
                result = certificate_chain(records, args.sequence)
                if not args.json:
                    print(result["pem"], end="")
                    return 0
            elif args.command == "coverage":
                from .inventory import collection_coverage
                from .ledger import _read, parse
                result = collection_coverage(records, parse(_read(args.expected)), exact=args.exact, after_sequence=args.after_sequence, attention_only=args.attention_only)
                code = 2 if result["needs_attention"] else 0
            elif args.command == "endpoints":
                from .inventory import endpoint_inventory, collection_policy
                if args.policy and (args.host is not None or args.vantage is not None or args.failed_only):
                    raise ValueError("policy export requires the complete inventory; selection flags are report-only")
                result = collection_policy(records) if args.policy else endpoint_inventory(records)
                if not args.policy and (args.host is not None or args.vantage is not None or args.failed_only):
                    all_rows = result["results"]
                    result["results"] = [row for row in all_rows
                        if (args.host is None or row["host"] == args.host)
                        and (args.vantage is None or row["vantage"] == args.vantage)
                        and (not args.failed_only or row["latest"]["status"] != "verified")]
                    result.update(selected_groups=len(result["results"]),omitted_groups=len(all_rows)-len(result["results"]),
                                  filters={"host":args.host,"vantage":args.vantage,"failed_only":args.failed_only})
                    result["scope"] += " Selection limits output only, all history authenticated. Omitted groups remain outside this view, not healthy or absent."
            elif args.command == "fingerprint-reuse":
                from .reuse import fingerprint_reuse
                result = fingerprint_reuse(records)
            elif args.command == "expiry":
                from .expiry import expiry
                result = expiry(records, as_of=args.as_of, within_days=args.within_days, max_age_seconds=args.max_age_seconds,
                                attention_only=args.attention_only)
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
                if args.csv:
                    from .timeline import render_csv
                    print(render_csv(result), end="")
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
