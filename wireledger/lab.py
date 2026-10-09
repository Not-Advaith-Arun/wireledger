"""Loopback-only reproducible network lab, with disposable generated credentials."""

import socket
import ssl
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .ledger import (LedgerError, append, canonical, compare_checkpoints, compare_verified_histories,
                     initialize, load_private, make_checkpoint, verify, verify_records)
from .probe import changes, compare, observe
from .evidence import audit, load_trust
from .timeline import timeline


def certificates(directory):
    """Return trusted CA, two renewed leafs sharing a key, and one rotated leaf."""
    directory = Path(directory)
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Wireledger disposable lab CA")])
    ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=7))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    ca_path = directory / "lab-ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    first_key = ec.generate_private_key(ec.SECP256R1())
    pairs = []
    for index, key in enumerate((first_key, first_key, ec.generate_private_key(ec.SECP256R1()))):
        leaf = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
                .issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(hours=1)).not_valid_after(now + timedelta(days=1, hours=index))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                .sign(ca_key, hashes.SHA256()))
        cert_path, key_path = directory / f"leaf-{index}.pem", directory / f"leaf-{index}.key"
        cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        from .ledger import exclusive_write
        exclusive_write(key_path, key.private_bytes(serialization.Encoding.PEM,
                                                   serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        pairs.append((cert_path, key_path))
    return ca_path, pairs


@contextmanager
def tls_server(cert, key, *, port=0, host="127.0.0.1"):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    listener = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(4)
    listener.settimeout(0.1)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
                connection.settimeout(1)
                try:
                    with context.wrap_socket(connection, server_side=True):
                        pass
                except (ssl.SSLError, OSError):
                    connection.close()
            except socket.timeout:
                continue
            except OSError:
                break

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        stop.set()
        thread.join(timeout=2)
        listener.close()


def demo():
    with tempfile.TemporaryDirectory(prefix="wireledger-lab-") as temporary:
        root = Path(temporary)
        ca, pairs = certificates(root)
        state = root / "witness"
        initialize(state)
        key = load_private(state / "witness.key")
        ledger = state / "observations.jsonl"
        other = root / "second-witness"
        initialize(other)
        other_key = load_private(other / "witness.key")
        other_ledger = other / "observations.jsonl"
        port = 0
        for cert, private in pairs:
            with tls_server(cert, private, port=port) as bound:
                port = bound
                observation = observe("localhost", port, connect_ip="127.0.0.1", cafile=str(ca), vantage="loopback-lab")
                if observation["status"] != "verified":
                    raise LedgerError("local TLS lab verification failed: " + str(observation))
                append(ledger, key, observation)
                second = observe("localhost", port, connect_ip="127.0.0.1", cafile=str(ca), vantage="loopback-view-two")
                if second["status"] != "verified":
                    raise LedgerError("second loopback view failed")
                append(other_ledger, other_key, second)
        records = verify(ledger, key.public_key())
        offline_audit = audit(records, load_trust(ca))
        if not offline_audit["ok"]:
            raise LedgerError("offline lab certificate audit failed: " + str(offline_audit))
        checkpoint = make_checkpoint(records, key)
        other_records = verify(other_ledger, other_key.public_key())
        other_checkpoint = make_checkpoint(other_records, other_key)
        old_records = verify_records(canonical(records[0]) + b"\n", key.public_key())
        old_checkpoint = make_checkpoint(old_records, key)
        # Deliberately create a second, validly signed history using the SAME
        # disposable witness key. This is distinct from two independent observers.
        fork = root / "fork.jsonl"
        fork.write_bytes(canonical(records[0]) + b"\n")
        append(fork, key, {**records[1]["body"]["observation"], "vantage": "deliberate-fork"})
        append(fork, key, records[2]["body"]["observation"])
        fork_records = verify(fork, key.public_key())
        fork_checkpoint = make_checkpoint(fork_records, key)
        tampered = ledger.read_bytes().replace(b"loopback-lab", b"tampered-lab", 1)
        detected = {}
        for label, data, anchor in (
            ("content_tampering", tampered, None),
            ("tail_truncation_with_checkpoint", canonical(records[0]) + b"\n", checkpoint),
        ):
            try:
                verify_records(data, key.public_key(), anchor)
                detected[label] = False
            except LedgerError:
                detected[label] = True
        return {"network": "loopback only", "observations": len(records), "events": changes(records),
                "detected": detected, "temporary_keys_removed": True,
                "offline_certificate_audit": offline_audit,
                "witness_views": {"observations": [len(records), len(other_records)],
                                  "comparisons": compare(records, other_records),
                                  "checkpoints": compare_checkpoints(checkpoint, other_checkpoint, key.public_key(), other_key.public_key())},
                "old_prefix": {"checkpoints": compare_checkpoints(old_checkpoint, checkpoint, key.public_key(), key.public_key()),
                               "history": compare_verified_histories(old_records, records, key.public_key(), key.public_key())},
                "signed_fork": {"checkpoints": compare_checkpoints(checkpoint, fork_checkpoint, key.public_key(), key.public_key()),
                                "history": compare_verified_histories(records, fork_records, key.public_key(), key.public_key())},
                "timeline": timeline(records, at_observed_time=True),
                "note": "Certificate changes alone do not establish an attack."}
