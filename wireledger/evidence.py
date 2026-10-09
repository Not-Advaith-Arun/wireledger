"""Bounded public certificate evidence and offline verification against explicit trust."""

import base64
import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

LEGACY_FORMAT = "wireledger.tls-evidence.v1"
FORMAT = "wireledger.tls-evidence.v2"
MAX_CERT_BYTES = 64 * 1024
MAX_CHAIN = 16
MAX_CA_FILE = 4 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")


def certificate_metadata(der):
    try:
        return _certificate_metadata(der)
    except (UnsupportedAlgorithm, x509.DuplicateExtension,
            x509.UnsupportedGeneralNameType, OverflowError) as exc:
        # Lazy public-key/extension parsing raises exceptions outside ValueError.
        # Keep all malformed imported evidence on the ordinary validation path.
        raise ValueError("unsupported or malformed certificate evidence") from exc


def _certificate_metadata(der):
    if not isinstance(der, bytes) or not 1 <= len(der) <= MAX_CERT_BYTES:
        raise ValueError("certificate DER exceeds its bounded size")
    cert = x509.load_der_x509_certificate(der)
    if cert.public_bytes(serialization.Encoding.DER) != der:
        raise ValueError("certificate is not canonical DER")
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    try:
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = [str(name.value) for name in names]
    except x509.ExtensionNotFound:
        sans = []
    return {"certificate_sha256": hashlib.sha256(der).hexdigest(),
            "spki_sha256": hashlib.sha256(spki).hexdigest(),
            "issuer": cert.issuer.rfc4514_string(), "subject": cert.subject.rfc4514_string(),
            "sans": sans, "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat()}


def trust_fingerprint(roots):
    """Fingerprint a set of CA DER hashes, not private keys or local filesystem paths."""
    digests = sorted({hashlib.sha256(der).hexdigest() for der in roots})
    return hashlib.sha256(b"wireledger/trust-set/v1\x00" + "\n".join(digests).encode("ascii")).hexdigest()


def encode_chain(chain):
    if not isinstance(chain, list) or not 1 <= len(chain) <= MAX_CHAIN:
        raise ValueError("certificate evidence requires 1..16 certificates")
    result = []
    for der in chain:
        certificate_metadata(der)
        result.append(base64.b64encode(der).decode("ascii"))
    return result


def decode_chain(encoded):
    if not isinstance(encoded, list) or not 1 <= len(encoded) <= MAX_CHAIN:
        raise ValueError("certificate evidence requires 1..16 certificates")
    result = []
    for item in encoded:
        if not isinstance(item, str) or not item or len(item) > ((MAX_CERT_BYTES + 2) // 3) * 4:
            raise ValueError("invalid encoded certificate size")
        raw = base64.b64decode(item, validate=True)
        if base64.b64encode(raw).decode("ascii") != item:
            raise ValueError("noncanonical certificate Base64")
        certificate_metadata(raw)
        if raw in result:
            raise ValueError("duplicate certificate in captured chain")
        result.append(raw)
    return result


def parse_time(value):
    if not isinstance(value, str) or len(value) > 80:
        raise ValueError("invalid observation timestamp")
    instant = datetime.fromisoformat(value)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("observation timestamp must include its timezone")
    try:
        return instant.astimezone(timezone.utc)
    except OverflowError as exc:
        raise ValueError("observation timestamp falls outside the supported UTC range") from exc


def validate_evidence(observation):
    """Validate captured certificate metadata; signed text alone is not a certificate."""
    evidence = observation.get("evidence")
    fields = {"format", "chain_der", "chain_capture", "loaded_ca_set_sha256", "runtime"}
    if not isinstance(evidence, dict):
        raise ValueError("invalid certificate evidence fields")
    if evidence.get("format") == FORMAT:
        fields |= {"verifier_policy", "resolution"}
    elif evidence.get("format") != LEGACY_FORMAT:
        raise ValueError("unsupported certificate evidence format")
    if set(evidence) != fields:
        raise ValueError("invalid certificate evidence fields")
    if evidence["chain_capture"] not in ("verified-chain", "leaf-only"):
        raise ValueError("unsupported chain capture method")
    if not isinstance(evidence["loaded_ca_set_sha256"], str) or not HEX.fullmatch(evidence["loaded_ca_set_sha256"]):
        raise ValueError("invalid loaded-CA-set fingerprint")
    runtime = evidence["runtime"]
    if not isinstance(runtime, dict) or set(runtime) != {"python", "openssl", "cryptography", "wireledger"}:
        raise ValueError("invalid runtime evidence")
    if any(not isinstance(v, str) or not v or len(v) > 200 for v in runtime.values()):
        raise ValueError("invalid runtime version")
    if observation.get("status") != "verified":
        raise ValueError("certificate evidence attached to a non-verified observation")
    if not isinstance(observation.get("host"), str) or not observation["host"] or len(observation["host"]) > 253:
        raise ValueError("invalid observation hostname")
    if type(observation.get("port")) is not int or not 1 <= observation["port"] <= 65535:
        raise ValueError("invalid observation port")
    parse_time(observation.get("observed_at"))
    if evidence["format"] == FORMAT:
        from .provenance import validate_provenance
        validate_provenance(observation)
    from .provenance import validate_network_attempt
    validate_network_attempt(observation)
    chain = decode_chain(evidence["chain_der"])
    if evidence["chain_capture"] == "leaf-only" and len(chain) != 1:
        raise ValueError("leaf-only evidence has multiple certificates")
    expected = certificate_metadata(chain[0])
    for field, value in expected.items():
        if observation.get(field) != value:
            raise ValueError(f"certificate evidence does not match signed metadata: {field}")
    return chain


def load_trust(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_CA_FILE + 1)
    if len(raw) > MAX_CA_FILE:
        raise ValueError("CA file exceeds 4 MiB")
    certificates = x509.load_pem_x509_certificates(raw)
    if not certificates or len(certificates) > 4096:
        raise ValueError("CA file must contain 1..4096 certificates")
    return certificates


def audit(records, roots, *, at_observed_time=False, now=None):
    """Offline X.509 checks. Embedded chain certificates are never promoted to trust."""
    if not roots:
        raise ValueError("audit requires independently supplied trusted CA certificates")
    store = Store(roots)
    trusted_set = trust_fingerprint([cert.public_bytes(serialization.Encoding.DER) for cert in roots])
    current = now if now is not None else datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("audit time must be timezone-aware")
    rows = []
    for record in records:
        observation = record["body"]["observation"]
        row = {"sequence": record["body"]["sequence"], "host": observation.get("host"),
               "port": observation.get("port")}
        if observation.get("status") != "verified":
            row.update(status="no-successful-handshake", detail="No successful TLS observation to validate.")
        elif "evidence" not in observation:
            row.update(status="evidence-missing", detail="Legacy fingerprint-only observation; recapture to audit certificates.")
        else:
            try:
                chain = validate_evidence(observation)
                instant = parse_time(observation["observed_at"]) if at_observed_time else current
                row["verification_time"] = instant.isoformat()
                host = observation["host"]
                try:
                    subject = x509.IPAddress(ipaddress.ip_address(host))
                except ValueError:
                    subject = x509.DNSName(host)
                verifier = PolicyBuilder().store(store).time(instant).max_chain_depth(MAX_CHAIN - 2).build_server_verifier(subject)
                parsed = [x509.load_der_x509_certificate(der) for der in chain]
                verified = verifier.verify(parsed[0], parsed[1:])
                row.update(status="passed", verified_chain_length=len(verified),
                           captured_ca_set_matches_audit_set=observation["evidence"]["loaded_ca_set_sha256"] == trusted_set,
                           observer_policy_recorded=observation["evidence"]["format"] == FORMAT)
            except (ValueError, TypeError, VerificationError, x509.UnsupportedGeneralNameType) as exc:
                row.update(status="failed", detail=str(exc))
        rows.append(row)
    return {"ok": bool(rows) and all(row["status"] == "passed" for row in rows),
            "audit_ca_set_sha256": trusted_set,
            "time_policy": "observer-asserted-time" if at_observed_time else "current-time",
            "verifier_policy": "independent-pyca-server-verifier; not a replay of the observer's OpenSSL policy",
            "results": rows,
            "scope": "Offline certificate path, hostname, validity and metadata checks. No proof of handshake occurrence, trusted timestamp, revocation status, or absence of compromise."}
