"""One explicit TLS endpoint per invocation; no discovery, scans or application data."""

import ipaddress
import math
import platform
import ssl
import time
from datetime import datetime, timezone

import cryptography

from . import __version__
from .evidence import FORMAT, certificate_metadata, encode_chain, trust_fingerprint, validate_evidence
from .provenance import connect, resolution_request, verifier_policy
from .deadline import remaining


def client_context(cafile=None):
    # Construct explicitly: create_default_context consults SSLKEYLOGFILE and may
    # create/write an unrelated key log. Observers must never log session secrets.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    if hasattr(ssl, "VERIFY_X509_PARTIAL_CHAIN"):
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    if cafile:
        context.load_verify_locations(cafile=cafile)
    else:
        context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["h2", "http/1.1"])
    return context


def observe(host, port=443, *, connect_ip=None, cafile=None, vantage="local", timeout=5.0):
    if not isinstance(host, str) or not host or any(c.isspace() for c in host) or any(c in host for c in "/\\\x00"):
        raise ValueError("host must be a hostname or IP, without scheme/path/whitespace")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError("timeout must be finite and between 0 and 60 seconds")
    if not isinstance(vantage, str) or not vantage or len(vantage) > 120 or not vantage.isprintable():
        raise ValueError("vantage must be a short printable label")
    if connect_ip is not None:
        connect_ip = str(ipaddress.ip_address(connect_ip))
        if "%" in connect_ip:
            raise ValueError("scoped connection addresses are not supported")
    host = host.encode("idna").decode("ascii").lower().rstrip(".")
    if not host or len(host) > 253 or any(ord(c) < 33 or ord(c) > 126 for c in host):
        raise ValueError("invalid hostname")
    result = {"host": host, "port": port, "vantage": vantage,
              "observed_at": datetime.now(timezone.utc).isoformat(),
              "trust": "custom-ca" if cafile else "system-ca", "connect_ip": connect_ip}
    context = client_context(cafile)
    policy = verifier_policy(context, result["trust"], host)
    resolution = resolution_request(host, connect_ip)
    started = time.monotonic()
    deadline = started + timeout
    network = {"format": "wireledger.network-attempt.v1", "timeout_seconds": timeout,
               "phase": "resolve", "attempts": [], "deadline_exceeded": False}
    result["network_attempt"] = network
    completed = None
    try:
        with connect(host, port, connect_ip, deadline, resolution, network) as tcp:
            result["peer_ip"] = tcp.getpeername()[0]
            network["phase"] = "tls"
            tcp.settimeout(remaining(deadline))
            with context.wrap_socket(tcp, server_hostname=host) as tls:
                completed = time.monotonic()
                if completed >= deadline:
                    raise TimeoutError("observation TLS deadline exceeded")
                der = tls.getpeercert(binary_form=True)
                chain = tls.get_verified_chain() if hasattr(tls, "get_verified_chain") else [der]
                if not chain or chain[0] != der:
                    raise ValueError("captured chain does not start with the observed leaf certificate")
                result.update(certificate_metadata(der))
                result.update(status="verified", tls_version=tls.version(), cipher=tls.cipher()[0], alpn=tls.selected_alpn_protocol(),
                              evidence={"format": FORMAT, "chain_der": encode_chain(chain),
                                        "chain_capture": "verified-chain" if hasattr(tls, "get_verified_chain") else "leaf-only",
                                        "loaded_ca_set_sha256": trust_fingerprint(context.get_ca_certs(binary_form=True)),
                                        "verifier_policy": policy, "resolution": resolution,
                                        "runtime": {"python": platform.python_version(), "openssl": ssl.OPENSSL_VERSION,
                                                    "cryptography": cryptography.__version__, "wireledger": __version__}})
                network["attempts"][-1]["status"] = "verified"
                network["phase"] = "complete"
    except ssl.SSLCertVerificationError as exc:
        result.update(status="verification-failed", error_code=exc.verify_code, error=exc.verify_message,
                      connection_attempt={"verifier_policy": policy, "resolution": resolution})
        network["attempts"][-1].update(status="verification-failed", error=type(exc).__name__)
    except (OSError, ssl.SSLError) as exc:
        result.update(status="connection-failed", error=type(exc).__name__,
                      connection_attempt={"verifier_policy": policy, "resolution": resolution})
        if network["attempts"] and network["attempts"][-1]["status"] == "tcp-connected":
            network["attempts"][-1].update(status="tls-failed", error=type(exc).__name__)
    finally:
        finished = completed if completed is not None else time.monotonic()
        network["elapsed_seconds"] = max(0.0, finished - started)
        network["deadline_exceeded"] = finished >= deadline
    if result["status"] == "verified":
        validate_evidence(result)
    return result


def changes(records):
    """Compare per endpoint AND vantage. Changes are observations, not attack verdicts."""
    previous, events = {}, []
    for record in records:
        observation = record["body"]["observation"]
        if "evidence" in observation:
            validate_evidence(observation)
        try:
            endpoint = (observation["host"], observation["port"], observation["vantage"])
            status = observation["status"]
        except KeyError as exc:
            raise ValueError("signed entry is not a supported TLS observation") from exc
        old = previous.get(endpoint)
        reasons = []
        if old:
            if old["status"] != status:
                reasons.append("status-changed")
            if status == old["status"] == "verified":
                if observation["spki_sha256"] != old["spki_sha256"]:
                    reasons.append("public-key-changed")
                elif observation["certificate_sha256"] != old["certificate_sha256"]:
                    reasons.append("certificate-changed-same-key")
                for field in ("issuer", "tls_version", "cipher", "alpn", "peer_ip", "trust"):
                    if observation.get(field) != old.get(field):
                        reasons.append(field.replace("_", "-") + "-changed")
                for field in ("loaded_ca_set_sha256", "verifier_policy"):
                    if observation.get("evidence", {}).get(field) != old.get("evidence", {}).get(field):
                        reasons.append(field.replace("_", "-") + "-changed")
        else:
            reasons.append("first-observation")
        if reasons:
            events.append({"sequence": record["body"]["sequence"], "host": endpoint[0],
                           "port": endpoint[1], "vantage": endpoint[2], "changes": reasons})
        previous[endpoint] = observation
    return events


def compare(left, right):
    """Compare last observation per endpoint in two independently verified histories."""
    def latest(records):
        result = {}
        for record in records:
            observation = record["body"]["observation"]
            if "evidence" in observation:
                validate_evidence(observation)
            endpoint = (observation["host"], observation["port"])
            result.setdefault(endpoint, {})[observation.get("vantage")] = observation
        return result

    a, b = latest(left), latest(right)
    results = []
    for endpoint in sorted(set(a) | set(b)):
        left_views, right_views = a.get(endpoint, {}), b.get(endpoint, {})
        if len(left_views) > 1 or len(right_views) > 1:
            results.append({"host": endpoint[0], "port": endpoint[1],
                            "left_samples": list(left_views.values()), "right_samples": list(right_views.values()),
                            "comparison": "multiple-vantages",
                            "detail": "Multiple latest vantage samples retained; no single endpoint comparison selected."})
            continue
        one = next(iter(left_views.values()), None)
        two = next(iter(right_views.values()), None)
        item = {"host": endpoint[0], "port": endpoint[1], "left": one, "right": two}
        if one is None or two is None:
            item["comparison"] = "missing-observation"
        elif one["status"] != "verified" or two["status"] != "verified":
            item["comparison"] = "at-least-one-handshake-failed"
        else:
            fields = ("certificate_sha256", "spki_sha256", "issuer", "tls_version", "cipher", "alpn", "peer_ip", "trust")
            item["different_fields"] = [field for field in fields if one.get(field) != two.get(field)]
            item["different_fields"].extend("evidence." + field for field in ("loaded_ca_set_sha256", "verifier_policy")
                                           if one.get("evidence", {}).get(field) != two.get("evidence", {}).get(field))
            item["comparison"] = "different" if item["different_fields"] else "same-observed-properties"
        results.append(item)
    return results
