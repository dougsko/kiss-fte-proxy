#!/usr/bin/env python3
"""End-to-end KISS round-trip test over two proxies + Dire Wolf.

The proxies use the cover protocol selected by COVER_PROTO (default: bbs) and
FTE_MODE (default: off).  This test exercises every cover protocol path by
sending KISS data frames through proxy-a -> direwolf -> bridge -> direwolf ->
proxy-b and verifying the payload round-trips byte-for-byte.

Cover-protocol coverage
-----------------------
* COVER_PROTO=bbs (default)  -> BBS 7PLUS narrator base64 path (FTE always on)

* COVER_PROTO=http|telnet|rotate -> those codecs

Boundary cases target each codec's per-message capacity so multi-chunk
reassembly and total_len truncation are exercised:
  * BBS base64 capacity  = MAX_COVER_MSG (default 200) bytes
  * BBS FTE capacity     = 4 bytes (bbs_vocab.json)
  * HTTP/Telnet FTE cap  = 2 / 1 bytes
"""
import hashlib
import os
import random
import socket
import time

HOST = os.getenv("TEST_HOST", "proxy-a")
RX_HOST = os.getenv("TEST_RX_HOST", "proxy-b")
PORT = int(os.getenv("TEST_PORT", "8001"))
RX_PORT = int(os.getenv("TEST_RX_PORT", "8001"))
COVER_PROTO = os.getenv("COVER_PROTO", "bbs").lower()
# FTE is always enabled in this test
FTE_MODE = True
MAX_COVER_MSG = int(os.getenv("MAX_COVER_MSG", "200"))
FEND, FESC, TFEND, TFESC = 0xC0, 0xDB, 0xDC, 0xDD


def escape(data):
    out = bytearray()
    for b in data:
        if b == FEND: out.extend((FESC, TFEND))
        elif b == FESC: out.extend((FESC, TFESC))
        else: out.append(b)
    return bytes(out)


def unescape(data):
    out = bytearray(); i = 0
    while i < len(data):
        if data[i] == FESC and i + 1 < len(data):
            if data[i + 1] == TFEND: out.append(FEND)
            elif data[i + 1] == TFESC: out.append(FESC)
            else: out.extend(data[i:i + 2])
            i += 2
        else:
            out.append(data[i]); i += 1
    return bytes(out)


class KissReader:
    def __init__(self, sock): self.sock, self.buf = sock, bytearray()
    def read_frame(self, timeout=20):
        self.sock.settimeout(timeout)
        while True:
            try:
                start = self.buf.index(FEND)
                if start: del self.buf[:start]
                end = self.buf.index(FEND, 1)
                raw = bytes(self.buf[1:end]); del self.buf[:end + 1]
                if len(raw) >= 1 and (raw[0] & 0x0F) == 0:
                    return unescape(raw[1:])
            except ValueError:
                chunk = self.sock.recv(8192)
                if not chunk: raise EOFError("proxy closed KISS connection")
                self.buf.extend(chunk)


def connect(host, port):
    deadline = time.time() + 45
    while time.time() < deadline:
        try: return socket.create_connection((host, port), timeout=2)
        except OSError: time.sleep(0.5)
    raise RuntimeError(f"timed out connecting to {host}:{port}")


def build_cases(rng):
    """Payload cases, with BBS/cover boundaries added alongside the basics."""
    cases = [
        ("small-16", bytes(range(16))),
        ("ack-boundary-32", bytes(range(32))),
        ("data-boundary-33", bytes(range(33))),
        ("single-chunk-110", bytes((i * 7) & 0xFF for i in range(110))),
        ("two-chunk-111", bytes((i * 11) & 0xFF for i in range(111))),
        ("one-kib", bytes(rng.randrange(256) for _ in range(1024))),
        ("all-byte-values", bytes(range(256))),
        ("ten-kib-random", bytes(rng.randrange(256) for _ in range(10 * 1024))),
        ("kiss-escape-heavy", bytes((FEND, FESC)) * 300),
    ]

    # BBS base64 capacity boundary (MAX_COVER_MSG): exact fit + one over.
    cases.append((f"bbs-cap-{MAX_COVER_MSG}", bytes(rng.randrange(256) for _ in range(MAX_COVER_MSG))))
    cases.append((f"bbs-cap-{MAX_COVER_MSG + 1}", bytes(rng.randrange(256) for _ in range(MAX_COVER_MSG + 1))))

    # BBS FTE capacity boundary (4 bytes) and just-over.
    if COVER_PROTO == "bbs" and FTE_MODE:
        cases.append(("bbs-fte-cap-4", bytes(range(4))))
        cases.append(("bbs-fte-cap-5", bytes(range(5))))
        cases.append(("bbs-fte-cap-12", bytes(range(12))))
    return cases


def main():
    tx = connect(HOST, PORT)
    rx = connect(RX_HOST, RX_PORT)
    reader = KissReader(rx)
    rng = random.Random(0xB55)
    cases = build_cases(rng)
    failures = 0
    print(f"KISS cover-protocol end-to-end test  (COVER_PROTO={COVER_PROTO}, FTE_MODE={FTE_MODE})")
    try:
        for name, payload in cases:
            tx.sendall(bytes((FEND, 0x00)) + escape(payload) + bytes((FEND,)))
            received = reader.read_frame(timeout=60)
            sent_hash = hashlib.sha256(payload).hexdigest()
            recv_hash = hashlib.sha256(received).hexdigest()
            ok = received == payload
            print(f"{'PASS' if ok else 'FAIL'} {name:24s} sent={len(payload):5d} recv={len(received):5d} sha256={recv_hash}")
            if not ok:
                failures += 1
                print(f"  expected sha256={sent_hash}")
    finally:
        tx.close(); rx.close()
    if failures:
        raise SystemExit(f"{failures} test(s) failed")
    print("ALL TESTS PASSED")


if __name__ == "__main__":
    main()