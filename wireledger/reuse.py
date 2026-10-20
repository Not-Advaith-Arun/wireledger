"""Cross-endpoint fingerprint reuse in latest signed observer samples."""
from .evidence import validate_evidence


def fingerprint_reuse(records):
    latest = {}
    for record in records:
        obs = record["body"]["observation"]
        if "evidence" in obs:
            validate_evidence(obs)
        latest[(obs["host"], obs["port"], obs["vantage"])]=record
    groups = {"certificate_sha256": {}, "spki_sha256": {}}
    unavailable = []
    for endpoint, record in sorted(latest.items()):
        obs = record["body"]["observation"]
        row = dict(zip(("host", "port", "vantage"), endpoint))
        row["sequence"] = record["body"]["sequence"]
        if obs["status"] != "verified":
            unavailable.append(row)
            continue
        for field in groups:
            if obs.get(field):
                groups[field].setdefault(obs[field], []).append(row)
    result = {}
    for field, values in groups.items():
        result[field] = [{"fingerprint": key, "samples": samples,
                          "distinct_endpoints": len({(r["host"],r["port"]) for r in samples})}
                         for key, samples in sorted(values.items())
                         if len({(r["host"],r["port"]) for r in samples}) > 1]
    return {"shared": result, "latest_samples": len(latest), "unavailable_samples": unavailable,
            "scope": "Full history authenticated before latest signed-sequence selection. Shared captured certificate/key fingerprints across distinct endpoints are observer claims, not an attack, ownership, simultaneous deployment or independent TLS audit verdict. Failed latest samples never fall back to older successes. No certificate bodies exported."}
