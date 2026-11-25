#!/usr/bin/env python3
"""Transparent KISS frame relay between two Dire Wolf KISSCOPY instances.

Also writes a standalone PCAP using LINKTYPE_AX25_KISS (16). No modem audio,
RF simulation, proxy decoding, or payload interpretation happens here.
"""
import os
import socket
import struct
import threading
import time

FEND, FESC, TFEND, TFESC = 0xC0, 0xDB, 0xDC, 0xDD
A_HOST, B_HOST = os.getenv("DW_A_HOST", "direwolf-a"), os.getenv("DW_B_HOST", "direwolf-b")
A_PORT = int(os.getenv("DW_A_PORT", "8001"))
B_PORT = int(os.getenv("DW_B_PORT", "8001"))
PCAP_PATH = os.getenv("PCAP_PATH", "/artifacts/transport.pcap")


def connect_retry(host, port):
    while True:
        try:
            sock = socket.create_connection((host, port), timeout=2)
            sock.settimeout(None)
            return sock
        except OSError:
            time.sleep(0.5)


def kiss_frames(sock):
    buf = bytearray()
    while True:
        chunk = sock.recv(8192)
        if not chunk:
            return
        buf.extend(chunk)
        while True:
            try:
                start = buf.index(FEND)
            except ValueError:
                buf.clear()
                break
            if start:
                del buf[:start]
            try:
                end = buf.index(FEND, 1)
            except ValueError:
                break
            raw = bytes(buf[1:end])
            del buf[:end + 1]
            if len(raw) < 2:
                continue
            command = raw[0]
            out = bytearray()
            i = 1
            while i < len(raw):
                if raw[i] == FESC and i + 1 < len(raw):
                    if raw[i + 1] == TFEND:
                        out.append(FEND)
                    elif raw[i + 1] == TFESC:
                        out.append(FESC)
                    else:
                        out.extend(raw[i:i + 2])
                    i += 2
                else:
                    out.append(raw[i])
                    i += 1
            yield command, bytes(out)


class PcapWriter:
    # LINKTYPE_AX25_KISS = 16; packet data is KISS command byte + AX.25 frame.
    def __init__(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.file = open(path, "wb", buffering=0)
        self.lock = threading.Lock()
        self.file.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 16))

    def write(self, command, payload):
        packet = bytes((command,)) + payload
        now = time.time()
        sec = int(now)
        usec = int((now - sec) * 1_000_000)
        with self.lock:
            self.file.write(struct.pack("<IIII", sec, usec, len(packet), len(packet)))
            self.file.write(packet)

    def close(self):
        self.file.close()


def relay(src, dst, pcap, label):
    for command, payload in kiss_frames(src):
        # This test transports KISS data frames only; pass their frame bytes
        # unchanged and leave KISS control commands local to each TNC.
        if (command & 0x0F) != 0:
            continue
        pcap.write(command, payload)
        escaped = bytearray()
        for byte in payload:
            if byte == FEND:
                escaped.extend((FESC, TFEND))
            elif byte == FESC:
                escaped.extend((FESC, TFESC))
            else:
                escaped.append(byte)
        dst.sendall(bytes((FEND, command)) + escaped + bytes((FEND,)))
        print(f"[{label}] relayed {len(payload)} AX.25 bytes", flush=True)


def main():
    a = connect_retry(A_HOST, A_PORT)
    b = connect_retry(B_HOST, B_PORT)
    pcap = PcapWriter(PCAP_PATH)
    print(f"[bridge] {A_HOST}:{A_PORT} <-> {B_HOST}:{B_PORT}", flush=True)
    print(f"[bridge] PCAP: {PCAP_PATH} (LINKTYPE_AX25_KISS)", flush=True)
    threads = [
        threading.Thread(target=relay, args=(a, b, pcap, "A>B"), daemon=True),
        threading.Thread(target=relay, args=(b, a, pcap, "B>A"), daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        for thread in threads:
            thread.join()
    finally:
        a.close(); b.close(); pcap.close()


if __name__ == "__main__":
    main()
