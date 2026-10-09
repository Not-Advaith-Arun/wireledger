"""One monotonic budget, including a disposable process for blocking OS DNS."""

import json
from pathlib import Path
import socket
import subprocess
import sys
import time


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError("observation network deadline exceeded")
    return seconds


def resolve(host, port, deadline):
    """Resolve in a child that can be killed and reaped, without a stuck thread.

    Process startup and cleanup depend on the OS and are not hard realtime.
    The worker receives the same absolute deadline, so startup consumes budget.
    """
    remaining(deadline)
    process = subprocess.Popen(
        [sys.executable, "-I", str(Path(__file__).with_name("_resolver.py"))],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    try:
        request = json.dumps({"host": host, "port": port, "deadline": deadline}).encode()
        try:
            output, _ = process.communicate(request, timeout=remaining(deadline))
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("observation resolver deadline exceeded") from exc
        remaining(deadline)
        if process.returncode or len(output) > 65536:
            raise OSError("resolver worker failed")
        result = json.loads(output)
        if result.get("error") == "gaierror":
            raise socket.gaierror("resolver failed")
        if result.get("error") == "TimeoutError":
            raise TimeoutError("observation resolver deadline exceeded")
        if result.get("error"):
            raise OSError("resolver worker failed")
        return [(family, kind, protocol, name, tuple(sockaddr))
                for family, kind, protocol, name, sockaddr in result["addresses"]]
    finally:
        if process.poll() is None:
            process.kill()
        # Reap even if the caller is interrupted. No DNS worker is retained.
        process.communicate()
