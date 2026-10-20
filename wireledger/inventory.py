"""A signed observation collection inventory; no observer-clock freshness inference."""
from collections import Counter
from .evidence import validate_evidence


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
