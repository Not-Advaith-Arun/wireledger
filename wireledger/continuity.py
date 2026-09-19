"""Observer-clock sampling gaps, explicitly separate from verified freshness."""

import math

from .evidence import parse_time, validate_evidence


def continuity(records, *, as_of, max_gap_seconds=86400):
    current = parse_time(as_of)
    if (isinstance(max_gap_seconds, bool) or not isinstance(max_gap_seconds, (int, float))
            or not math.isfinite(max_gap_seconds) or not 0 < max_gap_seconds <= 31536000):
        raise ValueError("max gap must be finite and between 0 and 31536000 seconds")
    groups = {}
    for record in records:
        observation = record["body"]["observation"]
        if "evidence" in observation:
            validate_evidence(observation)
        endpoint = (observation["host"], observation["port"], observation["vantage"])
        group = groups.setdefault(endpoint, {"samples": 0, "gaps": [], "clock_reversals": [], "unavailable_times": []})
        group["samples"] += 1
        sequence = record["body"]["sequence"]
        try:
            instant = parse_time(observation.get("observed_at"))
        except (ValueError, TypeError):
            group["unavailable_times"].append(sequence)
            group.pop("previous", None)
            group["latest"] = (sequence, None, observation["status"])
            continue
        previous = group.get("previous")
        if previous:
            gap = (instant - previous[1]).total_seconds()
            row = {"from_sequence": previous[0], "to_sequence": sequence, "seconds": gap}
            if gap < 0:
                group["clock_reversals"].append(row)
            elif gap > max_gap_seconds:
                group["gaps"].append(row)
        group["previous"] = (sequence, instant)
        group["latest"] = (sequence, instant, observation["status"])
    rows = []
    for (host, port, vantage), group in sorted(groups.items()):
        latest = group.pop("latest", None)
        group.pop("previous", None)
        age = (current - latest[1]).total_seconds() if latest and latest[1] is not None else None
        state = ("time-unavailable" if age is None else "future-sample" if age < 0 else
                 "stale-sample" if age > max_gap_seconds else "within-observer-threshold")
        rows.append({"host": host, "port": port, "vantage": vantage, **group,
                     "latest_sequence": latest[0] if latest else None,
                     "latest_status": latest[2] if latest else None,
                     "age_seconds": age, "sampling_state": state})
    attention = not rows or any(r["gaps"] or r["clock_reversals"] or r["unavailable_times"]
                    or r["sampling_state"] != "within-observer-threshold"
                    or r["latest_status"] != "verified" for r in rows)
    return {"as_of": current.isoformat(), "max_gap_seconds": max_gap_seconds,
            "needs_attention": attention, "results": rows, "total_records": len(records),
            "scope": "Full signed history checked before analysis. Sequence order is retained; gaps, ages and clock reversals use observer-asserted times. No independent freshness, uninterrupted availability, path audit or attack verdict is established. Empty histories establish no coverage."}
