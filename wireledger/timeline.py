"""Readable, terminal-safe signed observations with explicit validity-time policy."""

import json
from datetime import datetime, timezone

from .evidence import parse_time, validate_evidence
from .probe import changes


def timeline(records, *, at_observed_time=False, now=None, host=None, port=None,
             vantage=None, since=None, until=None, changes_only=False):
    current = now if now is not None else datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("timeline time must be timezone-aware")
    lower, upper = parse_time(since) if since else None, parse_time(until) if until else None
    if lower and upper and lower > upper:
        raise ValueError("timeline since must not be after until")
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        raise ValueError("timeline port must be between 1 and 65535")
    events = {event["sequence"]: event["changes"] for event in changes(records)}
    rows = []
    for record in records:
        observation = record["body"]["observation"]
        sequence = record["body"]["sequence"]
        row = {"sequence": sequence, "observed_at": observation.get("observed_at"),
               "host": observation["host"], "port": observation["port"],
               "vantage": observation["vantage"], "status": observation["status"],
               "changes": events.get(sequence, []), "validity": "unavailable"}
        if "evidence" in observation:
            validate_evidence(observation)
            instant = parse_time(observation["observed_at"]) if at_observed_time else current
            start, end = parse_time(observation["not_before"]), parse_time(observation["not_after"])
            row.update(verification_time=instant.isoformat(),
                       validity="not-yet-valid" if instant < start else "expired" if instant > end else "within-validity-window",
                       spki_sha256=observation["spki_sha256"],
                       certificate_sha256=observation["certificate_sha256"],
                       peer_ip=observation.get("peer_ip"),
                       provenance="recorded" if "verifier_policy" in observation["evidence"] else "legacy-unrecorded")
        elif observation["status"] == "verified":
            row["provenance"] = "legacy-fingerprint-only"
        rows.append(row)
    selected = []
    for row in rows:
        if ((host is not None and row["host"] != host)
                or (port is not None and row["port"] != port)
                or (vantage is not None and row["vantage"] != vantage)
                or (changes_only and not row["changes"])):
            continue
        if lower or upper:
            observed = parse_time(row["observed_at"])
            if (lower and observed < lower) or (upper and observed > upper):
                continue
        selected.append(row)
    return {"time_policy": "observer-asserted-time" if at_observed_time else "current-time",
            "results": selected, "total_records": len(rows), "selected_records": len(selected),
            "filters": {"host": host, "port": port, "vantage": vantage,
                        "since": since, "until": until, "changes_only": changes_only},
            "selection_scope": "Full history verified before filtering; changes computed against all prior samples. Time filters use signed observer-asserted timestamps, inclusively.",
            "scope": "Certificate validity windows, not an independent path audit. Times and vantages are observer assertions; differences are not attack verdicts."}


def render_timeline(report):
    def quoted(value):
        return json.dumps(value, ensure_ascii=True)

    lines = ["Validity time policy: " + report["time_policy"], report["scope"]]
    for row in report["results"]:
        lines.append(f"#{row['sequence']} {quoted(row['observed_at'])} "
                     f"{quoted(row['host'])}:{row['port']} vantage={quoted(row['vantage'])}")
        lines.append(f"  status={quoted(row['status'])} validity={row['validity']} "
                     f"peer={quoted(row.get('peer_ip'))}")
        if "spki_sha256" in row:
            lines.append("  spki=" + row["spki_sha256"] + " provenance=" + row["provenance"])
        lines.append("  changes=" + quoted(row["changes"]))
    return "\n".join(lines)
