"""Readable, terminal-safe signed observations with explicit validity-time policy."""

import json
import csv
import io
from datetime import datetime, timezone

from .evidence import parse_time, validate_evidence
from .probe import changes


def timeline(records, *, at_observed_time=False, now=None, host=None, port=None,
             vantage=None, since=None, until=None, changes_only=False,
             after_sequence=0, limit=None):
    if type(after_sequence) is not int or after_sequence < 0:
        raise ValueError("after sequence must be a nonnegative integer")
    if limit is not None and (type(limit) is not int or not 1 <= limit <= 1000):
        raise ValueError("timeline limit must be between 1 and 1000")
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
    remaining = [row for row in selected if row["sequence"] > after_sequence]
    page = remaining if limit is None else remaining[:limit]
    more = len(page) < len(remaining)
    return {"time_policy": "observer-asserted-time" if at_observed_time else "current-time",
            "results": page, "total_records": len(rows), "selected_records": len(page),
            "matching_records": len(selected), "remaining_after_cursor": len(remaining),
            "has_more": more, "next_after_sequence": page[-1]["sequence"] if more else None,
            "pagination_scope": "Pages use signed sequence order after filtering. Each request verifies the whole supplied history and computes full-history changes; the display limit does not bound verification cost. Separate requests are not a locked snapshot or a proof against history substitution; retain an independently trusted checkpoint when required.",
            "filters": {"host": host, "port": port, "vantage": vantage,
                        "since": since, "until": until, "changes_only": changes_only,
                        "after_sequence": after_sequence, "limit": limit},
            "selection_scope": "Full history verified before filtering; changes computed against all prior samples. Time filters use signed observer-asserted timestamps, inclusively.",
            "scope": "Certificate validity windows, not an independent path audit. Times and vantages are observer assertions; differences are not attack verdicts."}


def render_timeline(report):
    def quoted(value):
        return json.dumps(value, ensure_ascii=True)

    lines = ["Validity time policy: " + report["time_policy"], report["scope"],
             f"Page: {report['selected_records']} returned; {report['remaining_after_cursor']} after cursor; "
             f"{report['matching_records']} matching; next after sequence: {report['next_after_sequence']}",
             report["pagination_scope"]]
    for row in report["results"]:
        lines.append(f"#{row['sequence']} {quoted(row['observed_at'])} "
                     f"{quoted(row['host'])}:{row['port']} vantage={quoted(row['vantage'])}")
        lines.append(f"  status={quoted(row['status'])} validity={row['validity']} "
                     f"peer={quoted(row.get('peer_ip'))}")
        if "spki_sha256" in row:
            lines.append("  spki=" + row["spki_sha256"] + " provenance=" + row["provenance"])
        lines.append("  changes=" + quoted(row["changes"]))
    return "\n".join(lines)


def render_csv(report):
    columns = ["sequence", "observed_at", "host", "port", "vantage", "status", "validity", "changes",
               "spki_sha256", "certificate_sha256", "peer_ip", "provenance", "time_policy",
               "total_records", "matching_records", "has_more", "next_after_sequence", "scope"]
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(columns)
    def cell(value):
        if value is None:
            return ""
        if type(value) is bool:
            return "true" if value else "false"
        if isinstance(value, (list, dict)):
            value = json.dumps(value, ensure_ascii=True, sort_keys=True)
        return "'" + value if isinstance(value, str) and value else value
    for row in report["results"]:
        value = {**row, **{key: report[key] for key in ("time_policy", "total_records", "matching_records", "has_more", "next_after_sequence")},
                 "scope": "Observer-asserted samples; whole history verified. No independent path/freshness/attack verdict. See JSON for full filters and pagination scope."}
        writer.writerow([cell(value.get(key)) for key in columns])
    return output.getvalue()
