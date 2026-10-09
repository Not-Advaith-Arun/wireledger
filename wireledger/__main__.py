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
            check.add_argument("--json", action="store_true", help="emit structured timeline data")
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
            if args.command == "report":
                result["events"] = changes(records)
            elif args.command == "timeline":
                result = timeline(records, at_observed_time=args.at_observed_time)
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
