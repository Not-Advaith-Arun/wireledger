"""Latest signed-sequence certificate windows, separate from witness freshness."""
import math
from .evidence import parse_time, validate_evidence


def expiry(records, *, as_of, within_days=30, max_age_seconds=86400):
    now = parse_time(as_of)
    for value, maximum, label in ((within_days,365,"within days"),(max_age_seconds,31536000,"max age seconds")):
        if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or not 0 <= value <= maximum:
            raise ValueError(label + " must be finite, nonnegative and within the supported bound")
    latest = {}
    for record in records:
        obs=record["body"]["observation"]
        if "evidence" in obs:
            validate_evidence(obs)
        latest[(obs["host"],obs["port"],obs["vantage"])]=record
    rows=[]
    for (host,port,vantage),record in sorted(latest.items()):
        obs=record["body"]["observation"]
        try:
            age=(now-parse_time(obs.get("observed_at"))).total_seconds()
        except (ValueError,TypeError):
            age=None
        sampling="unknown-time" if age is None else "future-sample" if age < 0 else "stale-sample" if age > max_age_seconds else "within-observer-threshold"
        remaining=None;window="unavailable"
        if obs["status"]=="verified" and "not_before" in obs and "not_after" in obs:
            start,end=parse_time(obs["not_before"]),parse_time(obs["not_after"])
            remaining=(end-now).total_seconds()
            window="not-yet-valid" if now<start else "expired" if now>end else "expires-within-horizon" if remaining<=within_days*86400 else "beyond-horizon"
        rows.append({"host":host,"port":port,"vantage":vantage,"sequence":record["body"]["sequence"],
                     "observed_status":obs["status"],"certificate_window":window,"seconds_until_expiry":remaining,
                     "not_after":obs.get("not_after") if remaining is not None else None,
                     "sampling_state":sampling,"age_seconds":age})
    rows.sort(key=lambda r:(r["seconds_until_expiry"] is None,r["seconds_until_expiry"] or 0,r["host"],r["port"],r["vantage"]))
    return {"as_of":now.isoformat(),"within_days":within_days,"max_age_seconds":max_age_seconds,
            "results":rows,"needs_attention":not rows or any(r["certificate_window"]!="beyond-horizon" or r["sampling_state"]!="within-observer-threshold" for r in rows),
            "scope":"Full signed history verified before selecting the latest sequence per endpoint/vantage. Certificate windows use captured observer claims, not a new handshake, independent freshness, path audit or renewal guarantee. A later failed sample is unavailable; older success is not silently substituted."}
