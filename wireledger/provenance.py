"""Bounded observer assertions about TLS policy and address selection.

An OS getaddrinfo result is not authenticated DNS evidence. OpenSSL's loaded CA
inventory can omit as-yet-unused capath certificates; it is not the full trust
configuration. Neither assertion proves that a handshake actually occurred.
"""

import ipaddress
import math
import socket

from .deadline import remaining, resolve

MAX_ADDRESSES = 64


def verifier_policy(context, trust_source, hostname):
    from .evidence import trust_fingerprint

    roots = context.get_ca_certs(binary_form=True)
    return {
        "hostname": hostname,
        "trust_source": trust_source,
        "verify_mode": int(context.verify_mode),
        "verify_flags": int(context.verify_flags),
        "check_hostname": context.check_hostname,
        "hostname_checks_common_name": context.hostname_checks_common_name,
        "minimum_tls_version": context.minimum_version.name,
        "maximum_tls_version": context.maximum_version.name,
        "security_level": context.security_level,
        "loaded_ca_set_before_sha256": trust_fingerprint(roots),
        "loaded_ca_count_before": len(roots),
        "ca_inventory_scope": "loaded-certificates-only",
    }


def address(family, sockaddr):
    return {"family": "IPv6" if family == socket.AF_INET6 else "IPv4",
            "ip": str(ipaddress.ip_address(sockaddr[0])), "port": sockaddr[1],
            "scope_id": sockaddr[3] if family == socket.AF_INET6 else 0}


def resolution_request(host, connect_ip):
    return {"method": "explicit-ip" if connect_ip else "system-getaddrinfo",
            "query": connect_ip or host, "dnssec": "not-assessed",
            "candidates": [], "attempted": [], "selected": None}


def connect(host, port, connect_ip, deadline, resolution, network):
    """Resolve once, then connect to exactly the recorded ordered candidates."""
    if connect_ip:
        ip = ipaddress.ip_address(connect_ip)
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        sockaddr = (str(ip), port, 0, 0) if ip.version == 6 else (str(ip), port)
        candidates = [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)]
    else:
        candidates = resolve(host, port, deadline)
    remaining(deadline)
    unique = []
    for candidate in candidates:
        family, kind, protocol, _, sockaddr = candidate
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        item = address(family, sockaddr)
        if item in resolution["candidates"]:
            continue
        if len(unique) >= MAX_ADDRESSES:
            raise OSError("address result exceeds 64 candidates")
        resolution["candidates"].append(item)
        unique.append((family, kind, protocol, sockaddr, item))
    last_error = OSError("resolver returned no usable addresses")
    network["phase"] = "tcp"
    for family, kind, protocol, sockaddr, item in unique:
        remaining(deadline)
        resolution["attempted"].append(item)
        attempt = {"address": item, "status": "tcp-started"}
        network["attempts"].append(attempt)
        tcp = None
        try:
            tcp = socket.socket(family, kind, protocol)
            tcp.settimeout(remaining(deadline))
            tcp.connect(sockaddr)
            remaining(deadline)
            resolution["selected"] = address(family, tcp.getpeername())
            attempt["status"] = "tcp-connected"
            return tcp
        except OSError as exc:
            if tcp is not None:
                tcp.close()
            last_error = exc
            attempt.update(status="tcp-failed", error=type(exc).__name__)
    raise last_error


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _address(item, port):
    if not isinstance(item, dict) or set(item) != {"family", "ip", "port", "scope_id"}:
        raise ValueError("invalid resolver address")
    if not isinstance(item["ip"], str) or "%" in item["ip"]:
        raise ValueError("invalid resolver IP")
    ip = ipaddress.ip_address(item["ip"])
    if str(ip) != item["ip"] or item["family"] != f"IPv{ip.version}":
        raise ValueError("resolver address family or canonical IP mismatch")
    if type(item["port"]) is not int or item["port"] != port:
        raise ValueError("resolver port mismatch")
    if not _integer(item["scope_id"], 0, 2**32 - 1) or (ip.version == 4 and item["scope_id"]):
        raise ValueError("invalid resolver scope ID")


def validate_provenance(observation):
    from .evidence import HEX

    evidence = observation["evidence"]
    policy = evidence["verifier_policy"]
    fields = {"hostname", "trust_source", "verify_mode", "verify_flags", "check_hostname",
              "hostname_checks_common_name", "minimum_tls_version", "maximum_tls_version",
              "security_level", "loaded_ca_set_before_sha256", "loaded_ca_count_before",
              "ca_inventory_scope"}
    if not isinstance(policy, dict) or set(policy) != fields:
        raise ValueError("invalid verifier policy fields")
    if policy["hostname"] != observation["host"] or policy["trust_source"] != observation.get("trust"):
        raise ValueError("verifier policy hostname or trust mismatch")
    if policy["trust_source"] not in ("custom-ca", "system-ca"):
        raise ValueError("invalid verifier trust source")
    if type(policy["verify_mode"]) is not int or policy["verify_mode"] != 2 or policy["check_hostname"] is not True:
        raise ValueError("verified evidence must require certificates and hostname checks")
    if not _integer(policy["verify_flags"], 0, 2**32 - 1):
        raise ValueError("invalid verification flags")
    if type(policy["hostname_checks_common_name"]) is not bool:
        raise ValueError("invalid common-name policy")
    versions = {"MINIMUM_SUPPORTED", "MAXIMUM_SUPPORTED", "SSLv3", "TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"}
    for field in ("minimum_tls_version", "maximum_tls_version"):
        if not isinstance(policy[field], str) or policy[field] not in versions:
            raise ValueError("invalid TLS version policy")
    minimum, maximum = policy["minimum_tls_version"], policy["maximum_tls_version"]
    if minimum == "MAXIMUM_SUPPORTED" or maximum == "MINIMUM_SUPPORTED":
        raise ValueError("invalid TLS version bound sentinel")
    order = {"MINIMUM_SUPPORTED": 0, "SSLv3": 1, "TLSv1": 2, "TLSv1_1": 3,
             "TLSv1_2": 4, "TLSv1_3": 5, "MAXIMUM_SUPPORTED": 6}
    negotiated = {"SSLv3": "SSLv3", "TLSv1": "TLSv1", "TLSv1.1": "TLSv1_1",
                  "TLSv1.2": "TLSv1_2", "TLSv1.3": "TLSv1_3"}
    version = observation.get("tls_version")
    if not isinstance(version, str) or version not in negotiated:
        raise ValueError("invalid negotiated TLS version")
    if not order[minimum] <= order[negotiated[version]] <= order[maximum]:
        raise ValueError("negotiated TLS version contradicts recorded policy bounds")
    if not _integer(policy["security_level"], 0, 5) or not _integer(policy["loaded_ca_count_before"], 0, 1_000_000):
        raise ValueError("invalid verifier policy counts")
    digest = policy["loaded_ca_set_before_sha256"]
    if not isinstance(digest, str) or not HEX.fullmatch(digest):
        raise ValueError("invalid pre-handshake CA inventory")
    if policy["ca_inventory_scope"] != "loaded-certificates-only":
        raise ValueError("unsupported CA inventory scope")
    resolution = evidence["resolution"]
    if not isinstance(resolution, dict) or set(resolution) != {"method", "query", "dnssec", "candidates", "attempted", "selected"}:
        raise ValueError("invalid resolution fields")
    explicit = observation.get("connect_ip")
    if explicit is not None:
        if not isinstance(explicit, str) or "%" in explicit:
            raise ValueError("invalid explicit connection IP")
        if str(ipaddress.ip_address(explicit)) != explicit:
            raise ValueError("explicit connection IP must be canonical")
    if resolution["method"] != ("explicit-ip" if explicit else "system-getaddrinfo"):
        raise ValueError("resolver method mismatch")
    if resolution["query"] != (explicit or observation["host"]) or resolution["dnssec"] != "not-assessed":
        raise ValueError("invalid resolver query or assurance")
    for field in ("candidates", "attempted"):
        items = resolution[field]
        if not isinstance(items, list) or not 1 <= len(items) <= MAX_ADDRESSES:
            raise ValueError("invalid resolver address count")
        for index, item in enumerate(items):
            _address(item, observation["port"])
            if item in items[:index]:
                raise ValueError("duplicate resolver address")
    attempted = resolution["attempted"]
    if attempted != resolution["candidates"][:len(attempted)]:
        raise ValueError("attempted addresses are not a candidate prefix")
    selected = resolution["selected"]
    _address(selected, observation["port"])
    if selected != attempted[-1] or selected["ip"] != observation.get("peer_ip"):
        raise ValueError("selected peer does not match the connected address")
    if explicit and (len(resolution["candidates"]) != 1 or selected["ip"] != explicit):
        raise ValueError("explicit connection address mismatch")


def validate_network_attempt(observation):
    """Check optional diagnostics on successful captures; old captures omit them.

    Consistency checks do not authenticate timing or prove the claimed attempts.
    """
    if "network_attempt" not in observation:
        return
    network = observation["network_attempt"]
    fields = {"format", "timeout_seconds", "elapsed_seconds", "phase", "attempts", "deadline_exceeded"}
    if not isinstance(network, dict) or set(network) != fields:
        raise ValueError("invalid network attempt fields")
    if network["format"] != "wireledger.network-attempt.v1":
        raise ValueError("unsupported network attempt format")
    timeout, elapsed = network["timeout_seconds"], network["elapsed_seconds"]
    if (type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60
            or type(elapsed) not in (int, float) or not math.isfinite(elapsed) or not 0 <= elapsed < timeout):
        raise ValueError("invalid successful network attempt timing")
    if network["phase"] != "complete" or network["deadline_exceeded"] is not False:
        raise ValueError("successful capture contradicts network deadline outcome")
    attempts = network["attempts"]
    if not isinstance(attempts, list) or not 1 <= len(attempts) <= MAX_ADDRESSES:
        raise ValueError("invalid network attempt count")
    for index, attempt in enumerate(attempts):
        last = index == len(attempts) - 1
        expected = {"address", "status"} if last else {"address", "status", "error"}
        if not isinstance(attempt, dict) or set(attempt) != expected:
            raise ValueError("invalid network attempt record")
        _address(attempt["address"], observation["port"])
        if attempt["status"] != ("verified" if last else "tcp-failed"):
            raise ValueError("network attempt status contradicts verified capture")
        if not last and (not isinstance(attempt["error"], str) or not attempt["error"].isidentifier()
                         or len(attempt["error"]) > 80):
            raise ValueError("invalid network attempt error")
    if attempts[-1]["address"]["ip"] != observation.get("peer_ip"):
        raise ValueError("network attempt peer mismatch")
    resolution = observation["evidence"].get("resolution")
    if resolution is not None and [attempt["address"] for attempt in attempts] != resolution["attempted"]:
        raise ValueError("network attempts contradict resolution provenance")
