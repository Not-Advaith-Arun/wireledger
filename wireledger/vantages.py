"""Latest observed views per vantage; a difference is not an attack verdict."""

from .evidence import parse_time, validate_evidence


def compare_vantages(records, *, max_pairs=1000):
    if type(max_pairs) is not int or not 1 <= max_pairs <= 10000:
        raise ValueError("max pairs must be an integer between 1 and 10000")
    remaining = max_pairs
    endpoints = {}
    for record in records:
        observation = record["body"]["observation"]
        if "evidence" in observation:
            validate_evidence(observation)
        endpoint = (observation["host"], observation["port"])
        # Latest signed sequence, deliberately not greatest observer clock time.
        endpoints.setdefault(endpoint, {})[observation["vantage"]] = {
            "sequence": record["body"]["sequence"], "observation": observation}
    results = []
    for (host, port), views in sorted(endpoints.items()):
        pairs = []
        names = sorted(views)
        total_pairs = len(names) * (len(names) - 1) // 2
        for index, left in enumerate(names):
            if remaining == 0:
                break
            for right in names[index + 1:]:
                if remaining == 0:
                    break
                remaining -= 1
                one, two = views[left]["observation"], views[right]["observation"]
                fields = ["status"]
                if one["status"] == two["status"] == "verified":
                    fields += ["certificate_sha256", "spki_sha256", "tls_version", "cipher", "alpn", "peer_ip", "trust"]
                differences = [field for field in fields if one.get(field) != two.get(field)]
                if one.get("evidence", {}).get("verifier_policy") != two.get("evidence", {}).get("verifier_policy"):
                    differences.append("verifier_policy")
                try:
                    separation = abs((parse_time(one.get("observed_at")) - parse_time(two.get("observed_at"))).total_seconds())
                except (ValueError, TypeError):
                    separation = None
                pairs.append({"left_vantage": left, "right_vantage": right,
                              "differences": differences, "observer_time_separation_seconds": separation})
        results.append({"host": host, "port": port, "views": views, "comparisons": pairs,
                        "coverage": "multiple-views" if len(views) > 1 else "one-view-only",
                        "comparisons_complete": len(pairs) == total_pairs, "omitted_pairs": total_pairs - len(pairs)})
    return {"results": results, "total_records": len(records), "maximum_pairs": max_pairs,
            "comparisons_complete": all(row["comparisons_complete"] for row in results),
            "scope": "One authenticated witness history, latest signed-sequence sample per endpoint/vantage. Vantage labels and times are observer assertions, not independent witnesses or simultaneous measurements. Differences are not attack verdicts; one view cannot establish agreement."}
