"""Isolated stdlib-only DNS worker. Not a public command or trust boundary."""

import json
import signal
import socket
import sys
import time


def main():
    request = json.loads(sys.stdin.buffer.read(4097))
    seconds = request["deadline"] - time.monotonic()
    if seconds <= 0:
        print(json.dumps({"error": "TimeoutError"}))
        return
    # If the parent dies, a POSIX worker still expires rather than remaining in
    # libc getaddrinfo indefinitely. Parent-side kill/reap works on all platforms.
    if hasattr(signal, "setitimer"):
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        candidates = socket.getaddrinfo(request["host"], request["port"],
                                        type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        addresses = []
        seen = set()
        for family, kind, protocol, _, sockaddr in candidates:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            identity = (family, sockaddr)
            if identity in seen:
                continue
            seen.add(identity)
            addresses.append((family, kind, protocol, "", sockaddr))
            # Return one extra entry so the parent can report overflow while
            # retaining the bounded prefix; never emit an unbounded response.
            if len(addresses) == 65:
                break
        print(json.dumps({"addresses": addresses}))
    except OSError as exc:
        print(json.dumps({"error": type(exc).__name__}))


if __name__ == "__main__":
    main()
