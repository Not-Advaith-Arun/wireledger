"""A signed observation collection inventory; no observer-clock freshness inference."""
from collections import Counter
from .evidence import validate_evidence


def expected_endpoints(expected):
    """Normalize and validate explicit endpoint policy before any collection."""
    if not isinstance(expected, list) or not 1 <= len(expected) <= 1000:
        raise ValueError("expected collection must contain 1..1000 endpoint rows")
    requested = set()
    for row in expected:
        if not isinstance(row, dict) or set(row) != {"host", "port", "vantage"}:
            raise ValueError("expected rows require exactly host, port and vantage")
        host, port, vantage = row["host"], row["port"], row["vantage"]
        if (not isinstance(host, str) or not host or len(host) > 253
                or any(c.isspace() or c in "/\\\x00" for c in host)):
            raise ValueError("invalid expected hostname")
        try:
            host = host.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError as error:
            raise ValueError("invalid expected hostname") from error
        if not host or len(host) > 253 or any(ord(c) < 33 or ord(c) > 126 for c in host):
            raise ValueError("invalid expected hostname")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("expected port must be 1..65535")
        if not isinstance(vantage, str) or not vantage or len(vantage) > 120 or not vantage.isprintable():
            raise ValueError("invalid expected vantage")
        key = host, port, vantage
        if key in requested:
            raise ValueError("duplicate expected endpoint/vantage")
        requested.add(key)
    return requested


def collection_coverage(records, expected, *, exact=False, after_sequence=0):
    """Compare verified collection with explicit intended endpoint/vantage rows."""
    requested = expected_endpoints(expected)
    if type(after_sequence) is not int or not 0 <= after_sequence <= 2**63-1:
        raise ValueError("after sequence must be0..2^63-1")
    total_records = len(records)
    records = [record for record in records if record["body"]["sequence"] > after_sequence]
    inventory = endpoint_inventory(records)
    observed = {(row["host"], row["port"], row["vantage"]): row for row in inventory["results"]}
    results = []
    for host, port, vantage in sorted(requested):
        row = observed.get((host, port, vantage))
        latest = row["latest"] if row else None
        results.append({"host": host, "port": port, "vantage": vantage,
                        "collection_state": "missing" if latest is None else
                            "observed-verified" if latest["status"] == "verified" else "latest-failed",
                        "samples": row["records"] if row else 0,
                        "latest_sequence": latest["sequence"] if latest else None})
    unexpected = sorted(set(observed) - requested)
    return {"expected_groups": len(requested), "total_records": total_records, "selected_records": len(records), "after_sequence": after_sequence, "results": results,
            "unexpected_groups": [{"host": h, "port": p, "vantage": v} for h, p, v in unexpected],
            "needs_attention": any(row["collection_state"] != "observed-verified" for row in results) or bool(exact and unexpected),
            **({"exact_collection_required": True} if exact else {}),
            "scope": "Expected manifest is an explicit local collection policy, not signed witness evidence. Full signed history is verified before selection. Latest means sequence order; an old verified sample does not establish freshness, availability, path validity or observer truth. Unexpected groups are listed; exact mode also requires that none exist. Selection uses signed sequences strictly after the explicit cursor; earlier observations are excluded from policy results but the CLI still authenticates the full history. A selected missing group may have older observations. Sequence selection is not clock freshness."}


def endpoint_inventory(records):
    groups = {}
    for record in records:
        obs = record["body"]["observation"]
        if "evidence" in obs:
            validate_evidence(obs)
        key = obs["host"], obs["port"], obs["vantage"]
        group = groups.setdefault(key, {"records": 0, "status_counts": Counter(),
                                       "first_sequence": record["body"]["sequence"],
                                       "first_observed_at": obs.get("observed_at")})
        group["records"] += 1
        group["status_counts"][obs["status"]] += 1
        group["latest"] = {"sequence": record["body"]["sequence"], "status": obs["status"],
                           "observed_at": obs.get("observed_at"),
                           "certificate_sha256": obs.get("certificate_sha256") if obs["status"] == "verified" else None,
                           "spki_sha256": obs.get("spki_sha256") if obs["status"] == "verified" else None}
    rows = [{"host": host, "port": port, "vantage": vantage, **group}
            for (host,port,vantage),group in sorted(groups.items())]
    return {"total_records": len(records), "endpoint_vantage_groups": len(rows), "results": rows,
            "scope": "Full verified signed sequence inventory. First/latest are sequence order, not a trusted wall clock; observer labels and timestamps are claims. No certificate bodies or error details exported. Counts do not establish collection completeness, network truth or independent witnesses."}
